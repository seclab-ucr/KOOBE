package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"os"
	"runtime"
	"strings"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagEnable = flag.String("enable", "", "comma-separated list of enabled syscalls")
)

func matchSyscall(name, pattern string) bool {
	if pattern == name || strings.HasPrefix(name, pattern+"$") {
		return true
	}
	if len(pattern) > 1 && pattern[len(pattern)-1] == '*' &&
		strings.HasPrefix(name, pattern[:len(pattern)-1]) {
		return true
	}
	return false
}

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	if *flagEnable != "" {
		enabled := strings.Split(*flagEnable, ",")
		for _, c := range enabled {
			n := 0
			for _, call := range target.Syscalls {
				if matchSyscall(call.Name, c) {
					n++
					break
				}
			}
			if n != 0 {
				fmt.Printf("%s\n", c)
			}
		}
	}
}
