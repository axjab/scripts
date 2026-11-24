package main

// Device diagnostics are deliberately separate from OATH write operations.
// All ykman commands here are on the read-only allowlist in main.go.

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type policyEntry struct { Name, Expected string }
var policy=[]policyEntry{
	{"Yubico OTP","Disabled"},{"FIDO U2F","Disabled"},{"FIDO2","Enabled"},
	{"OATH","Enabled"},{"PIV","Disabled"},{"OpenPGP","Enabled"},{"YubiHSM Auth","Disabled"},
}
type check struct { Label, Status, Actual, Expected string }
var headerPattern=regexp.MustCompile("^Applications(?:\\s+(USB))?(?:\\s+(NFC))?$")
var statePattern=regexp.MustCompile("(?i)Not available|Not supported|Disabled|Enabled")

func comparison(label,actual,expected string) check {
	status:="MISMATCH"
	switch {
	case actual=="": status="UNKNOWN"; actual="not reported"
	case strings.EqualFold(actual,"Not available") || strings.EqualFold(actual,"Not supported"): status="UNSUPPORTED"
	case strings.EqualFold(actual,expected): status="OK"
	}
	return check{label,status,actual,expected}
}

func compareInfo(raw string) []check {
	fields:=map[string]string{}
	apps:=map[string]map[string]string{}
	var columns []string
	nfc:=""
	for _,line:=range strings.Split(raw,"\n") {
		line=strings.TrimSpace(line)
		if m:=headerPattern.FindStringSubmatch(line); m!=nil {
			columns=nil
			if m[1]!="" || m[2]=="" { columns=append(columns,"USB") }
			if m[2]!="" { columns=append(columns,"NFC") }
			continue
		}
		if key,value,ok:=strings.Cut(line,":"); ok { fields[key]=strings.TrimSpace(value) }
		if line=="NFC transport is enabled" { nfc="enabled" }
		if line=="NFC transport is disabled" { nfc="disabled" }
		for _,p:=range policy {
			if len(columns)==0 || !strings.HasPrefix(line,p.Name+" ") { continue }
			tail:=strings.TrimSpace(strings.TrimPrefix(line,p.Name))
			values:=statePattern.FindAllString(tail,-1)
			if len(values)==len(columns) && strings.EqualFold(strings.Join(strings.Fields(tail)," "),strings.Join(values," ")) {
				if apps[p.Name]!=nil { apps[p.Name]=map[string]string{}; continue }
				apps[p.Name]=map[string]string{}
				for i,c:=range columns { apps[p.Name][c]=values[i] }
			}
		}
	}
	interfaces:=fields["Enabled USB interfaces"]
	if interfaces!="" {
		parts:=strings.Split(interfaces,",")
		for i:=range parts { parts[i]=strings.TrimSpace(parts[i]) }
		sort.Strings(parts)
		interfaces=strings.Join(parts,", ")
	}
	result:=[]check{comparison("USB interfaces",interfaces,"CCID, FIDO"),comparison("NFC transport",nfc,"enabled")}
	for _,p:=range policy {
		for _,transport:=range []string{"USB","NFC"} {
			result=append(result,comparison(p.Name+" / "+transport,apps[p.Name][transport],p.Expected))
		}
	}
	return result
}
func doctor(ctx context.Context,requested string)(int,error) {
	fmt.Println("ENVIRONMENT")
	version,err:=ykman(ctx,"",false,"--version")
	if err!=nil { return 2,err }
	fmt.Println("  ykman          OK       "+safe(strings.TrimSpace(version)))
	clockCtx,cancel:=context.WithTimeout(ctx,5*time.Second)
	defer cancel()
	raw,clockErr:=exec.CommandContext(clockCtx,"timedatectl","show","-p","NTPSynchronized","--value").Output()
	clock:=strings.TrimSpace(string(raw))
	result:=0
	switch {
	case clockErr==nil && clock=="yes": fmt.Println("  Clock sync     OK       synchronized (not proof of exact accuracy)")
	case clockErr==nil && clock=="no": fmt.Println("  Clock sync     MISMATCH expected yes; observed no"); result=1
	default: fmt.Println("  Clock sync     UNKNOWN  unavailable")
	}
	all,err:=devices(ctx)
	if err!=nil { return 2,err }
	if requested!="" {
		found:=false
		for _,id:=range all { if id==requested { found=true } }
		if !found { return 2,errors.New("selected YubiKey not detected") }
		all=[]string{requested}
	}
	if len(all)==0 { return 2,errors.New("no serial-numbered YubiKey detected") }
	for _,id:=range all {
		fmt.Println("\nDEVICE "+id)
		info,e:=ykman(ctx,id,false,"info")
		if e!=nil { fmt.Println("  Device access ERROR "+safe(e.Error())); result=2; continue }
		for _,line:=range strings.Split(info,"\n") {
			if strings.HasPrefix(line,"Device type:") || strings.HasPrefix(line,"Firmware version:") || strings.HasPrefix(line,"Form factor:") { fmt.Println("  "+safe(line)) }
		}
		for _,c:=range compareInfo(info) {
			fmt.Printf("  %-24s %-12s actual: %s; expected: %s\n",c.Label,c.Status,safe(c.Actual),c.Expected)
			if c.Status=="MISMATCH" { result=max(result,1) } else if c.Status!="OK" { result=2 }
		}
	}
	if result==0 { fmt.Println("\nApplication policy verified.") } else { fmt.Println("\nReview differences with ykman info; no changes made.") }
	return result,nil
}
func pgp(ctx context.Context,serial string) error {
	info,err:=ykman(ctx,serial,false,"openpgp","info")
	if err!=nil { return err }
	printSafeLines(info)
	help,err:=ykman(ctx,serial,false,"openpgp","keys","info","--help")
	if err!=nil { return err }
	slot:="enc"
	if regexp.MustCompile("\\bdec\\b").MatchString(help) && !regexp.MustCompile("\\benc\\b").MatchString(help) { slot="dec" }
	var failed bool
	for _,key:=range []string{"sig",slot,"aut"} {
		fmt.Println("\n"+strings.ToUpper(key))
		raw,e:=ykman(ctx,serial,false,"openpgp","keys","info",key)
		if e!=nil || strings.TrimSpace(raw)=="" { fmt.Println("Unknown/inaccessible"); failed=true; continue }
		printSafeLines(raw)
	}
	if failed { return errors.New("one or more slot metadata checks failed") }
	return nil
}
func printSafeLines(raw string) {
	for _,line:=range strings.Split(strings.TrimRight(raw,"\n"),"\n") { fmt.Println(safe(line)) }
}
