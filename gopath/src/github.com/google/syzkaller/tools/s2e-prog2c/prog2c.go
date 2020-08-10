// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagBuild      = flag.Bool("build", false, "also build the generated program")
	flagThreaded   = flag.Bool("threaded", false, "create threaded program")
	flagCollide    = flag.Bool("collide", false, "create collide program")
	flagRepeat     = flag.Int("repeat", 1, "repeat program that many times (<=0 - infinitely)")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace)")
	flagProg       = flag.String("prog", "", "file with program to convert (required)")
	flagFaultCall  = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth   = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagHandleSegv = flag.Bool("segv", false, "catch and ignore SIGSEGV")
	flagUseTmpDir  = flag.Bool("tmpdir", false, "create a temporary dir and execute inside it")
	flagTrace      = flag.Bool("trace", false, "trace syscall results")
	flagStrict     = flag.Bool("strict", false, "parse input program in strict mode")
	flagEnable     = flag.String("enable", "none", "enable only listed additional features")
	flagDisable    = flag.String("disable", "none", "enable all additional features except listed")
	flagS2E        = flag.Bool("s2e", false, "make syscalls arguments concolic")
	flagJson       = flag.String("json", "", "json file with advance operations")
	flagExp        = flag.Bool("exp", false, "autogenerate exploit")
)

type Flags struct {
	Sandbox  string `json:"sandbox"`
	Threaded bool   `json:"Threaded"`
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	features, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, false)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}

	// Parse config from comments
	var flags Flags
	allComments := append([]string{}, p.Comments...)
	for _, call := range p.Calls {
		allComments = append(allComments, call.Comment)
	}
	for _, comment := range allComments {
		if err := json.Unmarshal([]byte(comment), &flags); err == nil {
			if flags.Sandbox != "" {
				*flagSandbox = flags.Sandbox
				if flags.Sandbox == "namespace" {
					*flagUseTmpDir = true
				}
			}
			if flags.Threaded {
				*flagThreaded = true
			}
			break
		}
	}

	opts := csource.Options{
		Threaded:         *flagThreaded,
		Collide:          *flagCollide,
		Repeat:           *flagRepeat != 1,
		RepeatTimes:      *flagRepeat,
		Procs:            *flagProcs,
		Sandbox:          *flagSandbox,
		Fault:            *flagFaultCall >= 0,
		FaultCall:        *flagFaultCall,
		FaultNth:         *flagFaultNth,
		EnableTun:        features["tun"].Enabled,
		EnableNetDev:     features["net_dev"].Enabled,
		EnableNetReset:   features["net_reset"].Enabled,
		EnableCgroups:    features["cgroups"].Enabled,
		EnableBinfmtMisc: features["binfmt_misc"].Enabled,
		EnableCloseFds:   features["close_fds"].Enabled,
		UseTmpDir:        *flagUseTmpDir,
		HandleSegv:       *flagHandleSegv,
		Repro:            false,
		Trace:            *flagTrace,
		S2E:              *flagS2E,
		Exp:              *flagExp,
	}

	if opts.Exp && opts.Threaded {
		panic("No support for exploit if it involves multiple threads (e.g., race condition)")
	}

	if *flagJson != "" {
		data, err := ioutil.ReadFile(*flagJson)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		json.Unmarshal(data, &opts.Exploit)
	}

	src, err := csource.Write(p, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate C source: %v\n", err)
		os.Exit(1)
	}
	if formatted, err := csource.Format(src); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	} else {
		src = formatted
	}
	os.Stdout.Write(src)
	if !*flagBuild {
		return
	}
	bin, err := csource.Build(target, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build C source: %v\n", err)
		os.Exit(1)
	}
	os.Remove(bin)
	fmt.Fprintf(os.Stderr, "binary build OK\n")
}
