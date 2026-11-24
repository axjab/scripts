package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

type fakeCard struct {
	calls [][]byte
	replies [][]byte
}

func (f *fakeCard) Transmit(command []byte)([]byte,error) {
	f.calls=append(f.calls,append([]byte(nil),command...))
	reply:=f.replies[0]
	f.replies=f.replies[1:]
	return reply,nil
}
func reply(data []byte) []byte { return append(data,0x90,0) }

func TestBulkHOTPIsNeverCalculated(t *testing.T) {
	raw:=append(encodeTLV(tagName,[]byte("Counter")),encodeTLV(tagHOTP,[]byte{6})...)
	f:=&fakeCard{replies:[][]byte{reply(raw)}}
	s:=oathSession{cardSession:cardSession{f}}
	rows,err:=s.codes([]account{{ID:"Counter",Kind:typeHOTP}},"Counter",60,true)
	if err!=nil || len(rows)!=1 || !strings.Contains(rows[0].Code,"HOTP") { t.Fatalf("unexpected HOTP result: %v",err) }
	if len(f.calls)!=1 || f.calls[0][1]!=0xa4 { t.Fatal("unexpected card instruction") }
	if _,err=s.calculateOne(account{Kind:typeHOTP},60); err==nil { t.Fatal("HOTP guard failed") }
}
func TestBulkTouchIsNotTriggered(t *testing.T) {
	raw:=append(encodeTLV(tagName,[]byte("Example")),encodeTLV(tagTouch,[]byte{6})...)
	f:=&fakeCard{replies:[][]byte{reply(raw)}}
	s:=oathSession{cardSession:cardSession{f}}
	rows,err:=s.codes([]account{{ID:"Example",Kind:typeTOTP,Period:30}},"",60,false)
	if err!=nil || len(rows)!=1 || rows[0].Code!="Touch required" || len(f.calls)!=1 { t.Fatal("bulk touch safety failed") }
}
func TestTimer(t *testing.T) {
	rows:=[]codeRow{{"A","000001",30,60},{"B","123456",30,60}}
	if countdown(rows,59)!="Expires in 1s" { t.Fatal("wrong shared timer") }
	if strings.Contains(strings.Join(table(rows,60),"\n"),"000001") { t.Fatal("expired code displayed") }
	if end,ok:=nextExpiry(rows,29); !ok || end!=29 { t.Fatal("clock rollback not detected") }
	rows[1].Start=0
	if countdown(rows,59)!="Next expiry in 1s" { t.Fatal("mixed-period timer mislabeled") }
}
func TestFormatting(t *testing.T) {
	raw:=[]byte{6,0,0,0,1}
	code,err:=formatCode(raw)
	if err!=nil || code!="000001" { t.Fatal("leading zeroes lost") }
	if _,err=formatCode([]byte{6,0});err==nil { t.Fatal("malformed response accepted") }
	if got:=binary.BigEndian.Uint64(challengeAt(59,30));got!=1 { t.Fatal("wrong time step") }
}
func TestTLV(t *testing.T) {
	raw:=bytes.Repeat([]byte{7},130)
	items,err:=parseTLV(encodeTLV(0x71,raw))
	if err!=nil || len(items)!=1 || !bytes.Equal(items[0].value,raw) { t.Fatal("TLV round trip failed") }
	if _,err:=parseTLV([]byte{0x71,0x82,0x01});err==nil { t.Fatal("invalid length accepted") }
}
func TestNames(t *testing.T) {
	a,err:=parseAccount("60/Example:Account",typeTOTP)
	if err!=nil || a.Period!=60 || a.Issuer!="Example" { t.Fatal("period parsing failed") }
	id,err:=accountName("New",a.Issuer,a.Kind,a.Period)
	if err!=nil || id!="60/Example:New" { t.Fatal("rename did not preserve metadata") }
	if _,err:=resolve([]account{{ID:"Example"},{ID:"Example2"}},"Example");err==nil { t.Fatal("ambiguous query accepted") }
}
func TestPolicy(t *testing.T) {
	raw:="Enabled USB interfaces: FIDO, CCID\nNFC transport is enabled\nApplications USB NFC\n"
	for _,p:=range policy { raw+=p.Name+" "+p.Expected+" "+p.Expected+"\n" }
	checks:=compareInfo(raw)
	if len(checks)!=16 { t.Fatal("incomplete policy") }
	for _,c:=range checks { if c.Status!="OK" { t.Fatalf("unexpected check: %+v",c) } }
	checks=compareInfo(strings.Replace(raw,"FIDO2 Enabled Enabled","FIDO2 Disabled Not available",1))
	for _,c:=range checks {
		if c.Label=="FIDO2 / USB" && c.Status!="MISMATCH" { t.Fatal("USB mismatch hidden") }
		if c.Label=="FIDO2 / NFC" && c.Status!="UNSUPPORTED" { t.Fatal("unsupported NFC hidden") }
	}
	for _,c:=range compareInfo("") { if c.Status!="UNKNOWN" { t.Fatal("missing field was not unknown") } }
}
func TestDraw(t *testing.T) {
	var out bytes.Buffer
	draw(&out,[]string{"Expires in 1s"},1,80)
	if !strings.Contains(out.String(),"\x1b[1A") { t.Fatal("missing bounded cursor movement") }
	for _,bad:=range []string{"\x1b[2J","\x1b[3J","\x1b[?1049h"} {
		if strings.Contains(out.String(),bad) { t.Fatal("screen clear or alternate screen") }
	}
}
func TestAllowlist(t *testing.T) {
	for _,args:=range [][]string{{"oath","accounts","code"},{"config","usb"},{"fido","credentials","delete"},{"openpgp","keys","set-touch"}} {
		if allowed(args) { t.Fatal("unsafe backend command admitted") }
	}
}
