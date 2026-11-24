package main

// This file is the hardware boundary. PC/SC provides a connection to the card;
// the YubiKey performs the actual OATH calculations. We use Go's cryptography
// libraries only for the documented OATH password handshake and key normalization.
// FIDO and OpenPGP remain delegated to ykman.

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"golang.org/x/crypto/pbkdf2"
)

const (
	tagName = 0x71
	tagList = 0x72
	tagKey = 0x73
	tagChallenge = 0x74
	tagResponse = 0x75
	tagTruncated = 0x76
	tagHOTP = 0x77
	tagVersion = 0x79
	tagCounter = 0x7a
	tagAlgorithm = 0x7b
	tagTouch = 0x7c
	typeHOTP = 0x10
	typeTOTP = 0x20
)

var (
	managementAID = []byte{0xa0, 0, 0, 5, 0x27, 0x47, 0x11, 0x17}
	oathAID = []byte{0xa0, 0, 0, 5, 0x27, 0x21, 1}
	periodPrefix = regexp.MustCompile("^([0-9]+)/")
)

// An interface describes behavior, not a concrete implementation. This tiny
// interface allows tests to substitute a fake card without accessing hardware.
type transmitter interface {
	Transmit([]byte) ([]byte, error)
}

type tlv struct {
	tag byte
	value []byte
}

// TLV is the card's Tag-Length-Value encoding. Reject truncated/unknown
// length forms rather than interpreting an incomplete response as success.
func parseTLV(raw []byte) ([]tlv, error) {
	var result []tlv
	for len(raw) > 0 {
		if len(raw) < 2 { return nil, errors.New("truncated TLV header") }
		tag, n := raw[0], int(raw[1])
		raw = raw[2:]
		if n >= 128 {
			count := n & 127
			if count < 1 || count > 2 || len(raw) < count {
				return nil, errors.New("invalid TLV length")
			}
			n = 0
			for _, b := range raw[:count] { n = n*256 + int(b) }
			raw = raw[count:]
		}
		if n > len(raw) { return nil, errors.New("truncated TLV value") }
		result = append(result, tlv{tag, raw[:n]})
		raw = raw[n:]
	}
	return result, nil
}

func encodeTLV(tag byte, value []byte) []byte {
	result := []byte{tag}
	switch {
	case len(value) < 128:
		result = append(result, byte(len(value)))
	case len(value) <= 255:
		result = append(result, 0x81, byte(len(value)))
	default:
		result = append(result, 0x82, byte(len(value)>>8), byte(len(value)))
	}
	return append(result, value...)
}

func uniqueTLV(items []tlv, tag byte) ([]byte, error) {
	var found []byte
	count := 0
	for _, item := range items {
		if item.tag == tag { found = item.value; count++ }
	}
	if count > 1 { return nil, errors.New("duplicate card field") }
	return found, nil
}

type cardSession struct { card transmitter }

// exchange sends only the commands chosen by the typed methods below.
// Never log APDUs: enrollment requests contain the shared secret.
func (s cardSession) exchange(ins, p1, p2 byte, data []byte, continuation byte) ([]byte, error) {
	if len(data) > 255 { return nil, errors.New("card command too long") }
	cmd := []byte{0, ins, p1, p2}
	// Short APDUs require an explicit zero length even when data is empty.
	cmd = append(append(cmd, byte(len(data))), data...)
	var all []byte
	for i := 0; i < 256; i++ {
		raw, err := s.card.Transmit(cmd)
		if err != nil { return nil, errors.New("smart-card communication failed; check connection") }
		if len(raw) < 2 { return nil, errors.New("short smart-card response") }
		sw1, sw2 := raw[len(raw)-2], raw[len(raw)-1]
		all = append(all, raw[:len(raw)-2]...)
		if sw1 == 0x90 && sw2 == 0 { return all, nil }
		if sw1 == 0x61 {
			cmd = []byte{0, continuation, 0, 0, 0}
			continue
		}
		return nil, fmt.Errorf("card rejected command (status %02x%02x)", sw1, sw2)
	}
	return nil, errors.New("too many card response fragments")
}

func (s cardSession) selectApp(aid []byte, continuation byte) ([]byte, error) {
	return s.exchange(0xa4, 4, 0, aid, continuation)
}

// Read the serial on the SAME physical card connection that will be used for
// OATH. Reader order and USB product IDs are not device identity.
func (s cardSession) serial() (string, error) {
	if _, err := s.selectApp(managementAID, 0xc0); err != nil { return "", err }
	raw, err := s.exchange(0x1d, 0, 0, nil, 0xc0)
	if err != nil { return "", err }
	if len(raw) < 1 || int(raw[0]) != len(raw)-1 { return "", errors.New("invalid management response") }
	items, err := parseTLV(raw[1:])
	if err != nil { return "", err }
	value, err := uniqueTLV(items, 2)
	if err != nil || len(value) != 4 { return "", errors.New("card serial unavailable") }
	return strconv.FormatUint(uint64(binary.BigEndian.Uint32(value)), 10), nil
}

// openCard selects by verified serial, not by the first PC/SC reader.
// A transaction prevents another client from changing the selected app or
// credential inventory between a check and a write.
func openCard(serial string) (*scard.Context, *scard.Card, error) {
	ctx, err := scard.EstablishContext()
	if err != nil { return nil, nil, errors.New("PC/SC unavailable; check pcscd and CCID access") }
	readers, err := ctx.ListReaders()
	if err != nil { ctx.Release(); return nil, nil, errors.New("cannot enumerate PC/SC readers") }
	for _, reader := range readers {
		if !strings.Contains(strings.ToLower(reader), "yubikey") { continue }
		card, err := ctx.Connect(reader, scard.ShareShared, scard.ProtocolAny)
		if err != nil { continue }
		if err = card.BeginTransaction(); err != nil { card.Disconnect(scard.LeaveCard); continue }
		id, err := (cardSession{card}).serial()
		if err == nil && id == serial { return ctx, card, nil }
		card.EndTransaction(scard.LeaveCard)
		card.Disconnect(scard.LeaveCard)
	}
	ctx.Release()
	return nil, nil, errors.New("selected YubiKey not accessible over PC/SC or serial not verified")
}

type oathSession struct {
	cardSession
	version []byte
}

// Select and, if protected, authenticate once per command. Only the official
// protocol's challenge/response is sent; no password or PIN is in argv.
// No access-key or OTP is written to storage.
func openOATH(card transmitter) (oathSession, error) {
	s := oathSession{cardSession: cardSession{card}}
	raw, err := s.selectApp(oathAID, 0xa5)
	if err != nil { return s, err }
	items, err := parseTLV(raw)
	if err != nil { return s, err }
	s.version, err = uniqueTLV(items, tagVersion)
	if err != nil || len(s.version) != 3 { return s, errors.New("OATH version unavailable") }
	challenge, err := uniqueTLV(items, tagChallenge)
	if err != nil { return s, err }
	if len(challenge) == 0 { return s, nil }
	salt, err := uniqueTLV(items, tagName)
	if err != nil || len(salt) == 0 { return s, errors.New("OATH salt unavailable") }
	algo, err := uniqueTLV(items, tagAlgorithm)
	if err != nil || (len(algo) != 0 && !bytes.Equal(algo, []byte{1})) {
		return s, errors.New("unsupported OATH access-key algorithm")
	}
	if len(challenge) != 8 { return s, errors.New("invalid OATH challenge") }
	password, err := readSecret("OATH password: ")
	if err != nil { return s, err }
	defer clear(password)
	key := pbkdf2.Key(password, salt, 1000, 16, sha1.New)
	defer clear(key)
	mac := func(message []byte) []byte {
		h := hmac.New(sha1.New, key)
		h.Write(message)
		return h.Sum(nil)
	}
	hostChallenge := make([]byte, 8)
	if _, err = rand.Read(hostChallenge); err != nil { return s, errors.New("randomness unavailable") }
	data := append(encodeTLV(tagResponse, mac(challenge)), encodeTLV(tagChallenge, hostChallenge)...)
	raw, err = s.exchange(0xa3, 0, 0, data, 0xa5)
	if err != nil { return s, errors.New("OATH authentication failed; no retry attempted") }
	items, err = parseTLV(raw)
	if err != nil { return s, err }
	response, err := uniqueTLV(items, tagResponse)
	if err != nil || !hmac.Equal(response, mac(hostChallenge)) {
		return s, errors.New("card authentication failed")
	}
	return s, nil
}

type account struct {
	ID string
	Kind byte
	Period int64
	Issuer string
}

// The period is encoded in a Yubico account ID, e.g. 60/Issuer:Account.
// Standard TOTP IDs omit that prefix. HOTP has no time period.
func parseAccount(id string, kind byte) (account, error) {
	a := account{ID: id, Kind: kind}
	if !validName(id) { return a, errors.New("invalid card account identifier") }
	name := id
	switch kind {
	case typeTOTP:
		a.Period = 30
		if m := periodPrefix.FindStringSubmatch(id); m != nil {
			period, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil || period < 1 || period > 86400 { return a, errors.New("unsupported TOTP period") }
			a.Period = period
			name = id[len(m[0]):]
		}
	case typeHOTP:
	default:
		return a, errors.New("unknown OATH credential type")
	}
	if issuer, rest, ok := strings.Cut(name, ":"); ok && issuer != "" && rest != "" { a.Issuer = issuer }
	return a, nil
}

func (s oathSession) list() ([]account, error) {
	raw, err := s.exchange(0xa1, 0, 0, nil, 0xa5)
	if err != nil { return nil, err }
	items, err := parseTLV(raw)
	if err != nil { return nil, err }
	var result []account
	seen := map[string]bool{}
	for _, item := range items {
		if item.tag != tagList || len(item.value) < 2 { return nil, errors.New("unexpected OATH inventory field") }
		a, err := parseAccount(string(item.value[1:]), item.value[0]&0xf0)
		if err != nil { return nil, err }
		if seen[a.ID] { return nil, errors.New("duplicate credential identifier") }
		seen[a.ID] = true
		result = append(result, a)
	}
	return result, nil
}

type codeRow struct {
	ID, Code string
	Start, End int64 // zero End means no timed code (HOTP, touch, unsupported).
}

func challengeAt(now, period int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(now/period))
	return b
}

// YubiKey returns a truncated 31-bit value and digit count; formatting that
// value is not calculating an OTP on the host. Preserve leading zeroes.
func formatCode(raw []byte) (string, error) {
	if len(raw) != 5 || raw[0] < 6 || raw[0] > 8 { return "", errors.New("invalid OTP response") }
	mod := uint32(1)
	for i := byte(0); i < raw[0]; i++ { mod *= 10 }
	return fmt.Sprintf("%0*d", int(raw[0]), (binary.BigEndian.Uint32(raw[1:])&0x7fffffff)%mod), nil
}

func (s oathSession) calculateOne(a account, now int64) (string, error) {
	// This guard is essential: CALCULATE on HOTP advances its counter.
	if a.Kind != typeTOTP || a.Period <= 0 { return "", errors.New("refusing HOTP calculation") }
	data := append(encodeTLV(tagName, []byte(a.ID)), encodeTLV(tagChallenge, challengeAt(now, a.Period))...)
	raw, err := s.exchange(0xa2, 0, 1, data, 0xa5)
	if err != nil { return "", err }
	items, err := parseTLV(raw)
	if err != nil || len(items) != 1 || items[0].tag != tagTruncated {
		return "", errors.New("unexpected individual OTP response")
	}
	return formatCode(items[0].value)
}

func timedRow(a account, code string, now int64) codeRow {
	start := now/a.Period*a.Period
	return codeRow{ID:a.ID, Code:code, Start:start, End:start+a.Period}
}

// CALCULATE ALL does not advance HOTP and does not request touch. We never
// use ykman's CLI "accounts code" (which has an automatic repair path).
func (s oathSession) codes(accounts []account, selected string, now int64, touch bool) ([]codeRow, error) {
	raw, err := s.exchange(0xa4, 0, 1, encodeTLV(tagChallenge, challengeAt(now, 30)), 0xa5)
	if err != nil { return nil, err }
	items, err := parseTLV(raw)
	if err != nil || len(items)%2 != 0 { return nil, errors.New("invalid bulk OATH response") }
	byID := map[string]account{}
	for _, a := range accounts { byID[a.ID] = a }
	seen := map[string]bool{}
	var rows []codeRow
	for i:=0; i<len(items); i+=2 {
		name, value := items[i], items[i+1]
		id := string(name.value)
		a, ok := byID[id]
		if name.tag != tagName || !ok || seen[id] { return nil, errors.New("OATH inventory changed or response malformed") }
		seen[id] = true
		if a.Issuer == "_hidden" || (selected != "" && selected != id) { continue }
		row := codeRow{ID:id}
		switch {
		case a.Kind == typeHOTP:
			if value.tag != tagHOTP && value.tag != tagTouch { return nil, errors.New("unexpected HOTP response") }
			row.Code = "HOTP - on demand only"
		case a.Issuer == "Steam":
			row.Code = "Steam - use auth.py or Yubico Authenticator"
		case value.tag == tagTouch:
			row.Code = "Touch required"
			if touch && selected == id {
				fmt.Fprintln(stderr, "Touch your YubiKey (one code only).")
				code, e := s.calculateOne(a, now)
				if e != nil { return nil, e }
				row = timedRow(a, code, now)
			}
		case value.tag == tagTruncated:
			var code string
			if a.Period == 30 { code, err = formatCode(value.value) } else { code, err = s.calculateOne(a, now) }
			if err != nil { return nil, err }
			row = timedRow(a, code, now)
		default:
			return nil, errors.New("unknown OATH response type")
		}
		rows = append(rows, row)
	}
	if len(seen) != len(accounts) { return nil, errors.New("incomplete OATH response") }
	return rows, nil
}

type enrollment struct {
	ID string
	Kind, Algorithm, Digits byte
	Counter uint32
	Secret []byte
}

// Normalize HMAC keys exactly as the SDK does, using standard library hash
// implementations. The card still generates all authentication codes.
func normalizeKey(secret []byte, algorithm byte) ([]byte, error) {
	var newHash func() hash.Hash
	switch algorithm {
	case 1: newHash = sha1.New
	case 2: newHash = sha256.New
	case 3: newHash = sha512.New
	default: return nil, errors.New("unknown hash algorithm")
	}
	h := newHash()
	if len(secret) > h.BlockSize() { h.Write(secret); secret = h.Sum(nil); defer clear(secret) }
	result := make([]byte, max(14, len(secret)))
	copy(result, secret)
	return result, nil
}

func (s oathSession) add(e enrollment) error {
	key, err := normalizeKey(e.Secret, e.Algorithm)
	if err != nil { return err }
	defer clear(key)
	payload := append([]byte{e.Kind|e.Algorithm, e.Digits}, key...)
	defer clear(payload)
	data := append(encodeTLV(tagName, []byte(e.ID)), encodeTLV(tagKey, payload)...)
	if e.Counter != 0 {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, e.Counter)
		data = append(data, encodeTLV(tagCounter, b)...)
	}
	defer clear(data)
	// No touch property is included. Do not add a force or overwrite flag.
	_, err = s.exchange(1, 0, 0, data, 0xa5)
	return err
}

func (s oathSession) rename(old, new string) error {
	if bytes.Compare(s.version, []byte{5,3,1}) < 0 { return errors.New("rename requires firmware 5.3.1 or later") }
	data := append(encodeTLV(tagName, []byte(old)), encodeTLV(tagName, []byte(new))...)
	_, err := s.exchange(5, 0, 0, data, 0xa5)
	return err
}

func (s oathSession) remove(id string) error {
	_, err := s.exchange(2, 0, 0, encodeTLV(tagName, []byte(id)), 0xa5)
	return err
}

// Release the card between operations when possible; an OATH watch keeps its
// transaction until exit to avoid losing the selected/authenticated app.
func withOATH(serial string, fn func(oathSession) error) error {
	ctx, card, err := openCard(serial)
	if err != nil { return err }
	defer ctx.Release()
	defer card.Disconnect(scard.LeaveCard)
	defer card.EndTransaction(scard.LeaveCard)
	session, err := openOATH(card)
	if err != nil { return err }
	return fn(session)
}

func unixNow() int64 { return time.Now().Unix() }
