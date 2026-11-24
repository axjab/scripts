// auth is a local YubiKey authenticator. Start here when maintaining the CLI:
// main -> run -> command function -> hardware adapter in oath.go or ykman.
package main

import (
	"bufio"
	"context"
	"encoding/base32"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

const version = "0.2.0"

var stderr io.Writer = os.Stderr
var input = bufio.NewReader(os.Stdin)
var serialPattern = regexp.MustCompile("^[0-9]+$")

// A context carries cancellation to blocking subprocesses. The native
// smart-card transport may finish an in-flight command before exiting.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, err := run(ctx, os.Args[1:])
	if err != nil { fmt.Fprintln(stderr, "auth:", safe(err.Error())) }
	if ctx.Err() != nil { os.Exit(130) }
	os.Exit(code)
}

type options struct {
	device, algorithm, kind string
	digits, period int
	counter uint64
}

func usage() {
	fmt.Fprintln(os.Stdout, "auth [options] [QUERY | list | add [NAME] | rename QUERY NAME | rm QUERY | fido | pgp | doctor]\n"+
		"No arguments: watch TOTP with one global countdown. ls/remove are aliases.\n"+
		"Options before command: --device SERIAL, --version, --help;\n"+
		"add options: --algorithm SHA1|SHA256|SHA512, --digits 6|7|8,\n"+
		"--period SECONDS, --oath-type TOTP|HOTP, --counter N.")
}

func run(ctx context.Context, args []string) (int, error) {
	f := flag.NewFlagSet("auth", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.Usage = usage
	var o options
	f.StringVar(&o.device,"device","","YubiKey serial")
	f.StringVar(&o.algorithm,"algorithm","SHA1","enrollment hash")
	f.StringVar(&o.kind,"oath-type","TOTP","enrollment type")
	f.IntVar(&o.digits,"digits",6,"enrollment digits")
	f.IntVar(&o.period,"period",30,"enrollment period")
	f.Uint64Var(&o.counter,"counter",0,"initial HOTP counter")
	showVersion := f.Bool("version",false,"print version")
	if err:=f.Parse(args); err!=nil {
		if errors.Is(err,flag.ErrHelp) { return 0,nil }
		return 2,err
	}
	if *showVersion { fmt.Println(version); return 0,nil }
	args=f.Args()
	command:=""
	if len(args)>0 { command=args[0]; args=args[1:] }
	if command=="ls" { command="list" }
	if command=="remove" { command="rm" }
	if command=="help" && len(args)==0 { usage(); return 0,nil }
	if o.device!="" && !serialPattern.MatchString(o.device) { return 2,errors.New("device must be a numeric serial") }
	if o.period<1 || o.period>86400 || o.counter>0xffffffff || o.digits<6 || o.digits>8 ||
		(o.kind!="TOTP" && o.kind!="HOTP") || (o.algorithm!="SHA1" && o.algorithm!="SHA256" && o.algorithm!="SHA512") {
		return 2,errors.New("invalid enrollment options")
	}
	if command!="add" && (o.algorithm!="SHA1" || o.kind!="TOTP" || o.digits!=6 || o.period!=30 || o.counter!=0) {
		return 2,errors.New("enrollment options require add")
	}
	if command=="add" {
		if len(args)>1 { return 2,errors.New("add accepts one name") }
	} else if command=="rename" {
		if len(args)!=2 { return 2,errors.New("rename requires query and new name") }
	} else if command=="rm" {
		if len(args)!=1 { return 2,errors.New("rm requires a query") }
	} else if len(args)!=0 { return 2,errors.New("unexpected extra arguments") }
	if command=="doctor" { return doctor(ctx,o.device) }
	serial,err:=selectDevice(ctx,o.device)
	if err!=nil { return 2,err }
	switch command {
	case "fido":
		if !interactive() { return 2,errors.New("FIDO inventory requires a terminal for PIN entry") }
		fmt.Println("Discoverable credentials only; not all FIDO registrations. Incorrect PIN may reduce retries.")
		_,err=ykman(ctx,serial,true,"fido","credentials","list")
	case "pgp":
		err=pgp(ctx,serial)
	default:
		err=withOATH(serial,func(s oathSession) error {
			switch command {
			case "list":
				accounts,e:=s.list()
				if e!=nil { return e }
				for _,a:=range visible(accounts) {
					if a.Kind==typeHOTP { fmt.Printf("%s\tHOTP\n",safe(a.ID)) } else { fmt.Printf("%s\tTOTP\t%ds\n",safe(a.ID),a.Period) }
				}
				return nil
			case "add","rename","rm":
				return writeOATH(ctx,s,serial,command,args,o)
			default:
				return watch(ctx,s,command)
			}
		})
	}
	if err!=nil { return 2,err }
	return 0,nil
}

func safe(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf,r) { return '?' }
		return r
	},s)
}

func validName(s string) bool {
	return s!="" && utf8.ValidString(s) && safe(s)==s
}
func interactive() bool { return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())) }

func readSecret(prompt string) ([]byte,error) {
	if !interactive() { return nil,errors.New("secure input requires an interactive terminal") }
	fmt.Fprint(stderr,prompt)
	secret,err:=term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stderr)
	if err!=nil { return nil,errors.New("secure input failed") }
	return secret,nil
}
func ask(prompt string) (string,error) {
	if !interactive() { return "",errors.New("interactive terminal required") }
	fmt.Fprint(stderr,prompt)
	value,err:=input.ReadString('\n')
	if err!=nil { return "",errors.New("input cancelled") }
	return strings.TrimSpace(value),nil
}
func confirm(message string) error {
	fmt.Fprintln(stderr,safe(message))
	answer,err:=ask("Proceed? [y/N] ")
	if err!=nil { return err }
	if !strings.EqualFold(answer,"y") { return errors.New("cancelled; no write performed") }
	return nil
}

// The read-only command allowlist is intentionally explicit. No general
// ykman passthrough, config/reset, credential deletion or code command.
func allowed(args []string) bool {
	switch strings.Join(args," ") {
	case "--version","list --serials","info","fido credentials list","openpgp info",
		"openpgp keys info --help","openpgp keys info sig","openpgp keys info enc",
		"openpgp keys info dec","openpgp keys info aut":
		return true
	}
	return false
}
func ykman(ctx context.Context, serial string, direct bool, args ...string) (string,error) {
	if !allowed(args) { return "",errors.New("backend command not permitted") }
	if _,err:=exec.LookPath("ykman"); err!=nil { return "",errors.New("ykman is not installed") }
	if serial!="" { args=append([]string{"--device",serial},args...) }
	if direct {
		cmd:=exec.CommandContext(ctx,"ykman",args...)
		cmd.Stdin,cmd.Stdout,cmd.Stderr=os.Stdin,os.Stdout,os.Stderr
		if err:=cmd.Run(); err!=nil { return "",errors.New("ykman command failed; see backend output") }
		return "",nil
	}
	ctx,cancel:=context.WithTimeout(ctx,15*time.Second)
	defer cancel()
	cmd:=exec.CommandContext(ctx,"ykman",args...)
	raw,err:=cmd.Output()
	if err!=nil {
		if ctx.Err()!=nil { return "",errors.New("ykman timed out or cancelled") }
		var exit *exec.ExitError
		if errors.As(err,&exit) {
			detail:=strings.ToLower(string(exit.Stderr))
			switch {
			case strings.Contains(detail,"permission"): return "",errors.New("ykman permission denied")
			case strings.Contains(detail,"not found"): return "",errors.New("ykman device not found")
			case strings.Contains(detail,"not supported") || strings.Contains(detail,"no such command"): return "",errors.New("ykman command or application unsupported")
			}
		}
		return "",errors.New("ykman failed; check connection/application access")
	}
	return string(raw),nil
}
func devices(ctx context.Context) ([]string,error) {
	raw,err:=ykman(ctx,"",false,"list","--serials")
	if err!=nil { return nil,err }
	var result []string
	seen:=map[string]bool{}
	for _,line:=range strings.Split(strings.TrimSpace(raw),"\n") {
		line=strings.TrimSpace(line)
		if line=="" { continue }
		if !serialPattern.MatchString(line) || seen[line] { return nil,errors.New("unexpected device inventory") }
		seen[line]=true; result=append(result,line)
	}
	return result,nil
}
func selectDevice(ctx context.Context, requested string) (string,error) {
	all,err:=devices(ctx)
	if err!=nil { return "",err }
	if requested!="" {
		for _,id:=range all { if id==requested { return id,nil } }
		return "",errors.New("selected YubiKey not detected")
	}
	if len(all)==0 { return "",errors.New("no serial-numbered YubiKey detected") }
	if len(all)!=1 { return "",errors.New("multiple keys; select --device SERIAL") }
	return all[0],nil
}

func visible(accounts []account) []account {
	var result []account
	for _,a:=range accounts { if a.Issuer!="_hidden" { result=append(result,a) } }
	sort.Slice(result,func(i,j int)bool{return result[i].ID<result[j].ID})
	return result
}
func resolve(accounts []account, query string) (account,error) {
	var match account
	count:=0
	if query!="" {
		for _,a:=range accounts {
			if strings.Contains(strings.ToLower(a.ID),strings.ToLower(query)) { match=a; count++ }
		}
	}
	if count==0 { return match,errors.New("no matching OATH account") }
	if count!=1 { return match,errors.New("ambiguous OATH query; use a more specific fragment") }
	return match,nil
}
func hasID(accounts []account,id string) bool {
	for _,a:=range accounts { if a.ID==id { return true } }
	return false
}
func accountName(value,issuer string,kind byte,period int64) (string,error) {
	if i,n,ok:=strings.Cut(value,":"); ok { issuer,value=i,n }
	if !validName(value) || (issuer!="" && !validName(issuer)) || issuer=="_hidden" ||
		strings.Contains(value,":") || strings.Contains(issuer,":") || periodPrefix.MatchString(value) || periodPrefix.MatchString(issuer) {
		return "",errors.New("invalid name or issuer")
	}
	id:=value
	if issuer!="" { id=issuer+":"+id }
	if kind==typeTOTP && period!=30 { id=strconv.FormatInt(period,10)+"/"+id }
	if len(id)>64 { return "",errors.New("OATH identifier exceeds 64 bytes") }
	return id,nil
}

func writeOATH(ctx context.Context,s oathSession,serial,command string,args []string,o options) error {
	if !interactive() { return errors.New("hardware writes require interactive confirmation") }
	accounts,err:=s.list()
	if err!=nil { return err }
	if command=="add" {
		name:=""
		if len(args)==1 { name=args[0] } else if name,err=ask("Account name: "); err!=nil { return err }
		issuer:=""
		if !strings.Contains(name,":") { if issuer,err=ask("Issuer (optional): "); err!=nil { return err } }
		kind:=byte(typeTOTP)
		if o.kind=="HOTP" { kind=typeHOTP }
		if (kind==typeHOTP && o.period!=30) || (kind==typeTOTP && o.counter!=0) { return errors.New("counter is HOTP only; period is TOTP only") }
		id,err:=accountName(name,issuer,kind,int64(o.period))
		if err!=nil { return err }
		if hasID(accounts,id) { return errors.New("credential exists; refusing overwrite") }
		if err=confirm(fmt.Sprintf("Persistently enroll %s on key %s, without touch. Remove to undo.",id,serial)); err!=nil { return err }
		if ctx.Err()!=nil { return ctx.Err() }
		raw,err:=readSecret("Base32 secret: ")
		if err!=nil { return err }
		defer clear(raw)
		// Decode into memory only; never put the secret in a process argument.
		normalized:=make([]byte,0,len(raw))
		defer func(){clear(normalized)}()
		for _,b:=range raw {
			if b==' ' { continue }
			if b>='a' && b<='z' { b-=32 }
			normalized=append(normalized,b)
		}
		for len(normalized)>0 && normalized[len(normalized)-1]=='=' { normalized=normalized[:len(normalized)-1] }
		secret:=make([]byte,base32.StdEncoding.DecodedLen(len(normalized)))
		defer clear(secret)
		n,e:=base32.StdEncoding.WithPadding(base32.NoPadding).Decode(secret,normalized)
		if e!=nil || n<2 { return errors.New("invalid Base32 secret") }
		e=ctx.Err()
		if e!=nil { return e }
		alg:=map[string]byte{"SHA1":1,"SHA256":2,"SHA512":3}[o.algorithm]
		if err=s.add(enrollment{id,kind,alg,byte(o.digits),uint32(o.counter),secret[:n]}); err!=nil { return err }
		accounts,err=s.list()
		if err!=nil || !hasID(accounts,id) { return errors.New("enrollment result not verified; inspect list before retrying") }
		fmt.Println("Enrolled.")
		return nil
	}
	a,err:=resolve(accounts,args[0])
	if err!=nil { return err }
	if command=="rename" {
		id,e:=accountName(args[1],a.Issuer,a.Kind,a.Period)
		if e!=nil { return e }
		if hasID(accounts,id) { return errors.New("destination exists; refusing overwrite") }
		if e=confirm(fmt.Sprintf("Persistently rename %s to %s on key %s. Rename back to undo.",a.ID,id,serial)); e!=nil { return e }
		if ctx.Err()!=nil { return ctx.Err() }
		if e=s.rename(a.ID,id); e!=nil { return e }
		accounts,e=s.list()
		if e!=nil || !hasID(accounts,id) || hasID(accounts,a.ID) { return errors.New("rename result not verified; inspect list") }
		fmt.Println("Renamed.")
		return nil
	}
	if err=confirm(fmt.Sprintf("Permanently delete %s from key %s. Cannot recover without original secret.",a.ID,serial)); err!=nil { return err }
	if ctx.Err()!=nil { return ctx.Err() }
	if err=s.remove(a.ID); err!=nil { return err }
	accounts,err=s.list()
	if err!=nil || hasID(accounts,a.ID) { return errors.New("deletion result not verified; inspect list") }
	fmt.Println("Deleted.")
	return nil
}

// A single countdown shows the NEXT code expiry. For ordinary 30-second
// accounts this is the same expiry for every entry. Custom periods are
// supported, but labeled with their period instead of extra countdowns.
func nextExpiry(rows []codeRow,now int64) (int64,bool) {
	var end int64
	for _,r:=range rows {
		if r.End==0 { continue }
		if now<r.Start || now>=r.End { return now,true }
		if end==0 || r.End<end { end=r.End }
	}
	return end,end!=0
}
func table(rows []codeRow,now int64) []string {
	lines:=[]string{"ACCOUNT                          CODE"}
	sort.Slice(rows,func(i,j int)bool{return rows[i].ID<rows[j].ID})
	for _,r:=range rows {
		code:=r.Code
		if r.End!=0 && (now<r.Start || now>=r.End) { code="Expired - refreshing" }
		suffix:=""
		if r.End!=0 && r.End-r.Start!=30 { suffix=fmt.Sprintf(" (%ds period)",r.End-r.Start) }
		lines=append(lines,fmt.Sprintf("%-32s %s%s",safe(r.ID),safe(code),suffix))
	}
	if len(rows)==0 { lines=append(lines,"No visible OATH accounts") }
	return lines
}
func countdown(rows []codeRow,now int64) string {
	end,ok:=nextExpiry(rows,now)
	if !ok { return "No timed codes" }
	left:=max(int64(0),end-now)
	mixed:=false
	for _,r:=range rows { if r.End!=0 && r.End-r.Start!=30 { mixed=true } }
	label:="Expires in"
	if mixed { label="Next expiry in" }
	return fmt.Sprintf("%s %ds",label,left)
}
func fit(s string,width int) string {
	var out strings.Builder
	for _,r:=range safe(s) {
		size:=1
		if r>127 { size=2 } // conservative width: prevents wrapping wide Unicode
		if width<=size { break }
		width-=size
		out.WriteRune(r)
	}
	return out.String()
}

// Only our previously printed lines are replaced. No full-screen erases,
// alternate screen or cursor hiding. Stop on resize rather than risk reflow.
func draw(w io.Writer,lines []string,previous,width int) {
	if previous>0 { fmt.Fprintf(w,"\x1b[%dA",previous) }
	for _,line:=range lines { fmt.Fprintf(w,"\r\x1b[2K%s\n",fit(line,width)) }
}
func watch(ctx context.Context,s oathSession,query string) error {
	accounts,err:=s.list()
	if err!=nil { return err }
	selected:=""
	if query!="" {
		a,e:=resolve(visible(accounts),query)
		if e!=nil { return e }
		selected=a.ID
	}
	live:=interactive() && os.Getenv("TERM")!="" && os.Getenv("TERM")!="dumb"
	now:=unixNow()
	rows,err:=s.codes(accounts,selected,now,live && selected!="")
	if err!=nil { return err }
	// A touch-required account is an explicit one-shot, never auto-prompt.
	if selected!="" {
		// Check whether the selected account's bulk result requires touch
		// before starting a continuous watch. Conservatively make selected
		// account views one-shot when using the explicit query.
		live=false
	}
	if !live {
		for _,line:=range table(rows,unixNow()) { fmt.Println(line) }
		fmt.Println(countdown(rows,unixNow()))
		return nil
	}
	width,height,err:=term.GetSize(int(os.Stdout.Fd()))
	if err!=nil { return errors.New("cannot determine terminal size") }
	lines:=append(table(rows,unixNow()),countdown(rows,unixNow()))
	if len(lines)>=height { return errors.New("terminal too short; enlarge or pipe to a snapshot") }
	draw(os.Stdout,lines,0,width)
	ticker:=time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		end,timed:=nextExpiry(rows,unixNow())
		if !timed { return nil }
		select {
		case <-ctx.Done(): return ctx.Err()
		case <-ticker.C:
		}
		w,h,e:=term.GetSize(int(os.Stdout.Fd()))
		if e!=nil || w!=width || h!=height { return errors.New("terminal resized; restart watch") }
		now=unixNow()
		current,expired:=nextExpiry(rows,now)
		if expired && current<=now || now>=end {
			// Replace expired codes before the potentially slow hardware call.
			draw(os.Stdout,append(table(rows,now),"Refreshing..."),len(lines),width)
			rows,e=s.codes(accounts,selected,now,false)
			if e!=nil { return e }
			w,h,e=term.GetSize(int(os.Stdout.Fd()))
			if e!=nil || w!=width || h!=height { return errors.New("terminal resized; restart watch") }
			fresh:=append(table(rows,unixNow()),countdown(rows,unixNow()))
			if len(fresh)!=len(lines) { return errors.New("account count changed; restart watch") }
			draw(os.Stdout,fresh,len(lines),width)
			lines=fresh
		} else {
			// The common case replaces just the single countdown line.
			draw(os.Stdout,[]string{countdown(rows,now)},1,width)
		}
	}
}
