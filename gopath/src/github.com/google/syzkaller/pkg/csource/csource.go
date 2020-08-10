// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package csource generates [almost] equivalent C programs from syzkaller programs.
package csource

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type Variable struct {
	Name string
	Def  string
	Size string
}

var SymbolArg_whitelist = map[string]bool{
	"nl_pid":            true,
	"pid":               true,
	"xfrm_selector":     true,
	"in":                true,
	"in6":               true,
	"xfrm_lifetime_cfg": true,
	"bmp":               true,
	"port":              true,
	"addr":              true,
}

var SymbolCall_whitelist = map[string]bool{
	"socket": true,
	"bind":   true,
}

func adjustDataOffset(name string, old, new uint64) string {
	pointer_str := strings.Replace(name, "ptr_0x", "", -1)
	if pointer, err := strconv.ParseUint(pointer_str, 16, 64); err == nil {
		new_pointer := pointer - old + new
		return fmt.Sprintf("ptr_0x%x", new_pointer)
	} else {
		panic("failed to parse pointer")
	}
}

func Write(p *prog.Prog, opts Options) ([]byte, error) {
	if err := opts.Check(p.Target.OS); err != nil {
		return nil, fmt.Errorf("csource: invalid opts: %v", err)
	}

	if opts.Exp {
		initialize(opts.Exploit.Version)

		pointer_str := strings.Replace(opts.Exploit.Pointer, "0x", "", -1)
		if pointer, err := strconv.ParseUint(pointer_str, 16, 64); err == nil {
			if pointer == p.Target.DataOffset {
				p.Target.DataOffset = pointer << 1
				new_solution := make(map[string]interface{}, len(opts.Exploit.Solution))
				for k, v := range opts.Exploit.Solution {
					if strings.HasPrefix(k, "ptr_0x") {
						k = adjustDataOffset(k, pointer, p.Target.DataOffset)
					}
					new_solution[k] = v
				}
				opts.Exploit.Solution = new_solution
			}
		} else if pointer_str != "" {
			panic(fmt.Sprintf("err: %v", err))
		}
	}

	ctx := &context{
		p:         p,
		opts:      opts,
		target:    p.Target,
		sysTarget: targets.Get(p.Target.OS, p.Target.Arch),
		calls:     make(map[string]uint64),
		num_vars:  0,
	}

	calls, vars, local_vars, err := ctx.generateProgCalls(ctx.p, opts.Trace)
	if err != nil {
		return nil, err
	}

	if ctx.opts.S2E && !ctx.opts.Threaded {
		calls = append([]string{"\ts2e_invoke_plugin(\"ProgramMonitor\", \"s\", 1);\n"}, calls...)
		calls = append(calls, "\ts2e_invoke_plugin(\"ProgramMonitor\", \"e\", 1);\n")
	}

	if ctx.opts.Exp {
		var tmpCalls []string
		ctx.adjustIndex()
		index := getIndexOfCall(ctx.opts.Exploit.AllocIndex, calls)
		tmpCalls = append(tmpCalls, calls[0:index]...)
		tmpCalls = append(tmpCalls, "do_fengshui();\n")
		if ctx.opts.Exploit.AllocIndex == ctx.opts.Exploit.DefIndex {
			tmpCalls = append(tmpCalls, "do_fengshui_tgt();\n")
			tmpCalls = append(tmpCalls, "do_alloc_target();\n")
			tmpCalls = append(tmpCalls, "do_fengshui_vuln();\n")
			tmpCalls = append(tmpCalls, calls[index])
		} else {
			tmpCalls = append(tmpCalls, "do_fengshui_vuln();\n")
			tmpCalls = append(tmpCalls, calls[index])
			tmpCalls = append(tmpCalls, "do_fengshui_tgt();\n")
			tmpCalls = append(tmpCalls, "do_alloc_target();\n")
		}
		tmpCalls = append(tmpCalls, calls[index+1:]...)
		calls = append(tmpCalls, "do_fengshui_trigger();\n")
		calls = append(calls, "do_trigger();\n")
	}

	// insert local variable definition
	calls = append(local_vars, calls...)

	mmapProg := p.Target.GenerateUberMmapProg()
	mmapCalls, _, _, err := ctx.generateProgCalls(mmapProg, false)
	if err != nil {
		return nil, err
	}

	for _, c := range append(mmapProg.Calls, p.Calls...) {
		ctx.calls[c.Meta.CallName] = c.Meta.NR
	}

	varsBuf := new(bytes.Buffer)
	if len(vars) != 0 {
		fmt.Fprintf(varsBuf, "uint64 r[%v] = {", len(vars))
		for i, v := range vars {
			if i != 0 {
				fmt.Fprintf(varsBuf, ", ")
			}
			fmt.Fprintf(varsBuf, "0x%x", v)
		}
		fmt.Fprintf(varsBuf, "};\n")
	}

	fengshuiBuf, allocBuf, triggerBuf := new(bytes.Buffer), new(bytes.Buffer), new(bytes.Buffer)
	if opts.Exp {
		target, err := getTarget(opts.Exploit.Version, opts.Exploit.Target)
		if err != nil {
			panic(fmt.Sprintf("failed to get the target %s [No implementation]", opts.Exploit.Target))
		}
		ctx.generateFengshui(fengshuiBuf, target)
		num_target := ctx.generateTarget(allocBuf, target)
		ctx.generateTrigger(triggerBuf, target, num_target)
		// FIXME: 32
		fmt.Fprintf(varsBuf, "uint64 s[%v] = {", 32)
		for i := 0; i < 32; i++ {
			if i != 0 {
				fmt.Fprintf(varsBuf, ", ")
			}
			fmt.Fprintf(varsBuf, "0")
		}
		fmt.Fprintf(varsBuf, "};\n")
	}

	sandboxFunc := "loop();"
	if opts.Sandbox != "" {
		sandboxFunc = "do_sandbox_" + opts.Sandbox + "();"
	}
	replacements := map[string]string{
		"PROCS":           fmt.Sprint(opts.Procs),
		"REPEAT_TIMES":    fmt.Sprint(opts.RepeatTimes),
		"NUM_CALLS":       fmt.Sprint(len(p.Calls)),
		"MMAP_DATA":       strings.Join(mmapCalls, ""),
		"SYSCALL_DEFINES": ctx.generateSyscallDefines(),
		"SANDBOX_FUNC":    sandboxFunc,
		"RESULTS":         varsBuf.String(),
		"SYSCALLS":        ctx.generateSyscalls(calls, len(vars) != 0, len(local_vars)),
		"FENGSHUI":        fengshuiBuf.String(),
		"ALLOCATETARGET":  allocBuf.String(),
		"TRIGGERTARGET":   triggerBuf.String(),
	}
	if !opts.Threaded && !opts.Repeat && opts.Sandbox == "" {
		// This inlines syscalls right into main for the simplest case.
		replacements["SANDBOX_FUNC"] = replacements["SYSCALLS"]
		replacements["SYSCALLS"] = "unused"
	}
	result, err := createCommonHeader(p, mmapProg, replacements, opts)
	if err != nil {
		return nil, err
	}
	header := "// autogenerated by KOOBE (https://github.com/google/syzkaller)\n\n"
	result = append([]byte(header), result...)
	result = ctx.postProcess(result)
	return result, nil
}

type context struct {
	p         *prog.Prog
	opts      Options
	target    *prog.Target
	sysTarget *targets.Target
	calls     map[string]uint64 // CallName -> NR
	num_vars  uint32
}

func getIndexOfCall(index int, calls []string) int {
	num := 0
	for i, v := range calls {
		if strings.Contains(v, "syscall") {
			if num == index {
				return i
			}
			num += 1
		}
	}
	return len(calls)
}

func (ctx *context) adjustIndex() {
	index := 0
	size := len(ctx.p.Calls)
	for i, syscall := range ctx.opts.Exploit.Syscalls {
		if index >= size {
			break
		}
		if ctx.p.Calls[index].Meta.NR == syscall {
			index += 1
		}
		if ctx.opts.Exploit.AllocIndex == i {
			ctx.opts.Exploit.AllocIndex = index - 1
		}
		if ctx.opts.Exploit.DefIndex == i {
			ctx.opts.Exploit.DefIndex = index - 1
		}
	}
}

func (ctx *context) getNumofOjbect() (int, int) {
	before, after := 0, 0
	start := false
	for _, v := range ctx.opts.Exploit.Layout {
		if v == 0 {
			start = true
		}
		if v == 1 || v == ctx.opts.Exploit.Size {
			if start {
				after += 1
			} else {
				before += 1
			}
		}
	}
	return before, after
}

func (ctx *context) generateFengshui(out *bytes.Buffer, target TargetObject) {
	version := ctx.opts.Exploit.Version
	result, fengshui := "", ""
	// fmt.Println(target.Alloc, ctx.opts.Exploit.VulAlloc)
	// cache exhaustion
	if target.Alloc == ctx.opts.Exploit.VulAlloc {
		pad, err := getPadding(version, target.Alloc, target.Size)
		if err != nil {
			panic(fmt.Sprintf("failed to get padding obj for %v", target.Alloc))
		}
		result = getPaddingFunc(pad, target.Size, 512)
		fengshui += fmt.Sprintf("%s();\n", pad.Name)
		fmt.Fprintf(out, result)

		vuln_bef, vuln_aft := ctx.getNumofOjbect()
		switch {
		case strings.HasPrefix(target.Name, "kmalloc_"):
			fengshui += getFengshui_sameCache_metadata(
				out, ctx.opts.Exploit.AllocIndex == ctx.opts.Exploit.DefIndex,
				vuln_bef, vuln_aft, target)
		default:
			fengshui += getFengshui_sameCache_oneTgt(
				out, ctx.opts.Exploit.AllocIndex == ctx.opts.Exploit.DefIndex,
				vuln_bef, vuln_aft, target)
		}
	} else {
		tgtPad, err1 := getPadding(version, target.Alloc, target.Size)
		if err1 != nil {
			panic(fmt.Sprintf("failed to get padding object for target %v", target.Alloc))
		}
		vulPad, err2 := getPadding(version, ctx.opts.Exploit.VulAlloc, ctx.opts.Exploit.Size)
		if err2 != nil {
			panic(fmt.Sprintf("failed to get padding object for vuln %v", ctx.opts.Exploit.VulAlloc))
		}
		result = getPaddingFunc(tgtPad, target.Size, 512)
		result += getPaddingFunc(vulPad, ctx.opts.Exploit.Size, 512)
		fengshui += fmt.Sprintf("%s();\n", tgtPad.Name)
		fengshui += fmt.Sprintf("%s();\n", vulPad.Name)
		fmt.Fprintf(out, result)

		vuln_bef, vuln_aft := ctx.getNumofOjbect()
		switch {
		case strings.HasPrefix(target.Name, "kmalloc_"):
			panic("Not implemented yet")
		default:
			fengshui += getFengshui_diffCache_oneTgt(
				out, ctx.opts.Exploit.AllocIndex == ctx.opts.Exploit.DefIndex,
				vuln_bef, vuln_aft, target)
		}
	}

	fmt.Fprintf(out, "void do_fengshui() {\n%s\n}", fengshui)
}

func (ctx *context) generateTarget(out *bytes.Buffer, target TargetObject) int {
	for _, dep := range target.Deps {
		fmt.Fprintf(out, getDependency(dep, ctx.opts.Exploit.Pointer))
	}

	var num_target int
	fmt.Fprintf(out, "void do_alloc_target() {\n")
	if target.Num == 0 {
		num_target = 16
		fmt.Fprintf(out, target.Define, num_target)
	} else {
		fmt.Fprintf(out, target.Define)
	}
	fmt.Fprintf(out, "\n}\n")
	return num_target
}

func (ctx *context) generateTrigger(out *bytes.Buffer, target TargetObject, num_target int) {
	fmt.Fprintf(out, "void do_trigger() {\n")
	if target.Num == 0 {
		fmt.Fprintf(out, target.Deref, num_target)
	} else {
		fmt.Fprintf(out, target.Deref)
	}
	fmt.Fprintf(out, "\n}\n")
}

func (ctx *context) generateSyscalls(calls []string, hasVars bool, localVars int) string {
	opts := ctx.opts
	buf := new(bytes.Buffer)
	if !opts.Threaded && !opts.Collide {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tlong res = 0;\n")
		}
		if opts.Repro {
			fmt.Fprintf(buf, "\tif (write(1, \"executing program\\n\", sizeof(\"executing program\\n\") - 1)) {}\n")
		}
		if opts.Trace {
			fmt.Fprintf(buf, "\tfprintf(stderr, \"### start\\n\");\n")
		}
		for _, c := range calls {
			fmt.Fprintf(buf, "%s", c)
		}
	} else {
		if hasVars || opts.Trace {
			fmt.Fprintf(buf, "\tlong res;")
		}
		localDefs := calls[:localVars]
		for _, c := range localDefs {
			fmt.Fprintf(buf, c)
		}

		calls = calls[localVars:]
		fmt.Fprintf(buf, "\tswitch (call) {\n")
		for i, c := range calls {
			fmt.Fprintf(buf, "\tcase %v:\n", i)
			fmt.Fprintf(buf, "%s", strings.Replace(c, "\t", "\t\t", -1))
			fmt.Fprintf(buf, "\t\tbreak;\n")
		}
		fmt.Fprintf(buf, "\t}\n")
	}
	return buf.String()
}

func (ctx *context) generateSyscallDefines() string {
	var calls []string
	for name, nr := range ctx.calls {
		if !ctx.sysTarget.SyscallNumbers ||
			strings.HasPrefix(name, "syz_") || !ctx.sysTarget.NeedSyscallDefine(nr) {
			continue
		}
		calls = append(calls, name)
	}
	sort.Strings(calls)
	buf := new(bytes.Buffer)
	prefix := ctx.sysTarget.SyscallPrefix
	for _, name := range calls {
		fmt.Fprintf(buf, "#ifndef %v%v\n", prefix, name)
		fmt.Fprintf(buf, "#define %v%v %v\n", prefix, name, ctx.calls[name])
		fmt.Fprintf(buf, "#endif\n")
	}
	if ctx.target.OS == "linux" && ctx.target.PtrSize == 4 {
		// This is a dirty hack.
		// On 32-bit linux mmap translated to old_mmap syscall which has a different signature.
		// mmap2 has the right signature. syz-extract translates mmap to mmap2, do the same here.
		fmt.Fprintf(buf, "#undef __NR_mmap\n")
		fmt.Fprintf(buf, "#define __NR_mmap __NR_mmap2\n")
	}
	return buf.String()
}

func (ctx *context) show(p *prog.Prog) {
	for _, call := range p.Calls {
		fmt.Printf("call: %s\n", call.Meta.CallName)
		// for _, copyin := range call.Copyin {
		// 	fmt.Printf("addr: %x, value: %v\n", copyin.Addr, copyin.Arg)
		// }
	}
}

func (ctx *context) adjustLenArgs(p *prog.Prog) *prog.Prog {
	if p != ctx.p {
		return p
	}

	for _, call := range p.Calls {
		if call.Meta.CallName == "mmap" {
			continue
		}
		if ctx.checkCall(call.Meta.Name) {
			continue
		}
		for _, arg := range call.Args {
			if ctx.checkArg(arg) {
				continue
			}
			switch arg.Type().(type) {
			// case *prog.IntType:
			case *prog.LenType, *prog.IntType:
				const_arg := arg.(*prog.ConstArg)
				var_name := ctx.assignVar(false)
				if ctx.opts.Exploit.Solution[var_name] != nil {
					num := ctx.opts.Exploit.Solution[var_name].([]interface{})
					newVal := "0x"
					for index := int(len(num) - 1); index >= 0; index-- {
						newVal = fmt.Sprintf("%s%02x", newVal, int(num[index].(float64)))
					}
					if v, err := strconv.ParseUint(newVal, 0, 64); err == nil {
						if v != const_arg.Val {
							// fmt.Printf("set val to %v\n", v)
							const_arg.Val = v
						}
					}
				}
			default:
			}
		}
	}
	// reset
	ctx.num_vars = 0
	return p
}

func (ctx *context) adjustCalls(p *prog.Prog) *prog.Prog {
	if p != ctx.p {
		return p
	}
	// adjust copyin: add more data as needed to touch every byte
	for ci, call := range p.Calls {
		// Retrieve the type information of the system call
		if call.Meta.CallName == "mmap" {
			continue
		}
		// fmt.Printf("call: %s\n", call.Meta.CallName)
		s2e_call := ctx.p.Calls[ci]
		for ai, arg := range call.Args {
			s2e_arg := s2e_call.Args[ai]
			i := ctx.getLenIndex(s2e_arg, s2e_call.Args)
			if i == -1 {
				continue
			}
			// fmt.Printf("LenType: %T\n", call.Args[i])
			len_arg, ok := call.Args[i].(*prog.ConstArg)
			if !ok {
				continue
			}
			// v := ctx.getconstArg(*len_arg)
			v := len_arg.Val
			// fmt.Printf("value: %x %T\n", v, arg)
			addr_arg, ok := arg.(*prog.PointerArg)
			if !ok {
				continue
			}
			// fmt.Printf("buff: %T\n", addr_arg.Res)
			buf_arg, ok := addr_arg.Res.(*prog.DataArg)
			if !ok {
				continue
			}

			if buf_arg.Type().Dir() == prog.DirOut {
				continue
			}

			buf_size := buf_arg.Size()
			// fmt.Printf("buff size: %v\n", buf_size)
			data := make([]byte, buf_size)
			copy(data, buf_arg.Data())
			for buf_size < v {
				if buf_size == 0 {
					data = append(data, 0)
					buf_size = 1
					continue
				}
				data = append(data, data...)
				buf_size = buf_size << 1
			}
			if buf_size > v {
				data = data[:v]
				buf_size = v
			}
			buf_arg.SetData(data)
			// fmt.Printf("New buff size: %v\n", len(data))
		}
	}
	return p
}

// func (ctx *context) generateExploit(p *prog.Prog) (string, error) {
// 	target := ctx.opts.ExpTarget
// 	pointer := ctx.opts.Pointer
// 	expTemplate, err := retreiveExpTemplate(target, pointer)
// 	return expTemplate, err
// }

func (ctx *context) generateProgCalls(p *prog.Prog, trace bool) ([]string, []uint64, []string, error) {
	exec := make([]byte, prog.ExecBufferSize)
	p = ctx.adjustLenArgs(p)
	p = ctx.adjustCalls(p)
	progSize, err := p.SerializeForExec(exec)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to serialize program: %v", err)
	}
	decoded, err := ctx.target.DeserializeExec(exec[:progSize])
	if err != nil {
		return nil, nil, nil, err
	}
	calls, vars, local_vars := ctx.generateCalls(decoded, trace)
	return calls, vars, local_vars, nil
}

func (ctx *context) generateCalls(p prog.ExecProg, trace bool) ([]string, []uint64, []string) {
	var calls []string
	var local_vars []string
	csumSeq := 0

	for ci, call := range p.Calls {
		// Retrieve the type information of the system call
		s2e_call := ctx.p.Calls[ci]

		w := new(bytes.Buffer)
		// Copyin.
		for _, copyin := range call.Copyin {
			ctx.copyin(w, &csumSeq, copyin)
		}
		if ctx.opts.Fault && ctx.opts.FaultCall == ci {
			// Note: these files are also hardcoded in pkg/host/host_linux.go.
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/failslab/ignore-gfp-wait\", \"N\");\n")
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/fail_futex/ignore-private\", \"N\");\n")
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/fail_page_alloc/ignore-gfp-highmem\", \"N\");\n")
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/fail_page_alloc/ignore-gfp-wait\", \"N\");\n")
			fmt.Fprintf(w, "\twrite_file(\"/sys/kernel/debug/fail_page_alloc/min-order\", \"0\");\n")
			fmt.Fprintf(w, "\tinject_fault(%v);\n", ctx.opts.FaultNth)
		}
		// Call itself.
		callName := call.Meta.CallName
		resCopyout := call.Index != prog.ExecNoCopyout
		argCopyout := len(call.Copyout) != 0
		emitCall := ctx.opts.EnableTun ||
			callName != "syz_emit_ethernet" &&
				callName != "syz_extract_tcp_res"
		// TODO: if we don't emit the call we must also not emit copyin, copyout and fault injection.
		// However, simply skipping whole iteration breaks tests due to unused static functions.
		if emitCall {
			vars := ctx.emitCall(w, call, ci, resCopyout || argCopyout, trace, *s2e_call)
			local_vars = append(local_vars, vars...)
		} else if trace {
			fmt.Fprintf(w, "\t(void)res;\n")
		}

		// Copyout.
		if resCopyout || argCopyout {
			ctx.copyout(w, call, resCopyout)
		}
		calls = append(calls, w.String())
	}
	if len(ctx.opts.Exploit.Solution) > 0 {
		ow := new(bytes.Buffer)
		for pAddr, tmp := range ctx.opts.Exploit.Solution {
			addr, err := strconv.ParseUint(pAddr[4:], 0, 64)
			if err != nil {
				fmt.Println(err)
			}
			num := tmp.([]interface{})
			size := len(num)
			if size > 8 {
				fmt.Fprintf(ow, "\tmemset((void*)0x%x, 0, %v);\n", addr, size)
				for index := 0; index < size; index++ {
					if int(num[index].(float64)) != 0 {
						val := fmt.Sprintf("0x%x", int(num[index].(float64)))
						fmt.Fprintf(ow, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", 8, addr+uint64(index), val)
					}
				}
			} else {
				val := "0x"
				for index := size - 1; index >= 0; index-- {
					val = fmt.Sprintf("%s%02x", val, int(num[index].(float64)))
				}
				fmt.Fprintf(ow, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", size*8, addr, val)
			}
			delete(ctx.opts.Exploit.Solution, pAddr)
		}
		calls = append([]string{ow.String(), "\n"}, calls...)
	}
	return calls, p.Vars, local_vars
}

func (ctx *context) emitCall(ow *bytes.Buffer, call prog.ExecCall, ci int, haveCopyout, trace bool, s2e_call prog.Call) []string {
	var local_vars []string
	w := new(bytes.Buffer)

	callName := call.Meta.CallName
	native := ctx.sysTarget.SyscallNumbers && !strings.HasPrefix(callName, "syz_")
	fmt.Fprintf(w, "\t")
	if haveCopyout || trace {
		fmt.Fprintf(w, "res = ")
	}
	ctx.emitCallName(w, call, native)
	_, skip := SymbolCall_whitelist[call.Meta.Name]
	// fmt.Printf("Syscall: %s\n", call.Meta.Name)

	for ai, arg := range call.Args {
		if native || ai > 0 {
			fmt.Fprintf(w, ", ")
		}

		if (ctx.opts.S2E || ctx.opts.Exp) && callName != "mmap" && !skip {
			// Retrieve corresponding argument
			s2e_arg := s2e_call.Args[ai]
			switch arg := arg.(type) {
			case prog.ExecArgConst:
				if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
					panic("string format in syscall argument")
				}
				// vars: local variable definition; val: local variable or real value
				ret := ctx.constArgToVar(arg, s2e_arg, s2e_call.Args, 0)
				for _, variable := range ret {
					if variable.Def != "" { // we got a meaningful variable
						local_vars = append(local_vars, variable.Def)
					}
					if ctx.opts.S2E && variable.Size != "" { // make something symbolic
						switch {
						case strings.HasPrefix(variable.Name, "local"):
							fmt.Fprintf(ow, "\ts2e_make_symbolic(&%s, %s, \"%s\");\n", variable.Name, variable.Size, variable.Name)
						case strings.HasPrefix(variable.Name, "0x"):
							fmt.Fprintf(ow, "\ts2e_make_symbolic((void*)%s, %s, \"ptr_%s\");\n", variable.Name, variable.Size, variable.Name)
						default:
						}
					}
				}
				fmt.Fprintf(w, "%v", ret[0].Name)
			case prog.ExecArgResult:
				if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
					panic("sring format in syscall argument")
				}
				val := ctx.resultArgToStr(arg)
				if native && ctx.target.PtrSize == 4 {
					// syscall accepts args as ellipsis, resources are uint64
					// and take 2 slots without the cast, which would be wrong.
					val = "(long)" + val
				}
				fmt.Fprintf(w, "%v", val)
			default:
				panic(fmt.Sprintf("unknown arg type: %+v", arg))
			}

			continue
		}

		switch arg := arg.(type) {
		case prog.ExecArgConst:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}
			fmt.Fprintf(w, "%v", ctx.constArgToStr(arg, true))
		case prog.ExecArgResult:
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("sring format in syscall argument")
			}
			val := ctx.resultArgToStr(arg)
			if native && ctx.target.PtrSize == 4 {
				// syscall accepts args as ellipsis, resources are uint64
				// and take 2 slots without the cast, which would be wrong.
				val = "(long)" + val
			}
			fmt.Fprintf(w, "%v", val)
		default:
			panic(fmt.Sprintf("unknown arg type: %+v", arg))
		}
	}
	for i := 0; i < call.Meta.MissingArgs; i++ {
		if native || len(call.Args) != 0 {
			fmt.Fprintf(w, ", ")
		}
		fmt.Fprintf(w, "0")
	}
	fmt.Fprintf(w, ");\n")
	if trace {
		cast := ""
		if !native && !strings.HasPrefix(callName, "syz_") {
			// Potentially we casted a function returning int to a function returning long.
			// So instead of long -1 we can get 0x00000000ffffffff. Sign extend it to long.
			cast = "(long)(int)"
		}
		fmt.Fprintf(w, "\tfprintf(stderr, \"### call=%v errno=%%u\\n\", %vres == -1 ? errno : 0);\n", ci, cast)
	}

	fmt.Fprintf(ow, w.String())
	return local_vars
}

func (ctx *context) emitCallName(w *bytes.Buffer, call prog.ExecCall, native bool) {
	callName := call.Meta.CallName
	if native {
		fmt.Fprintf(w, "syscall(%v%v", ctx.sysTarget.SyscallPrefix, callName)
	} else if strings.HasPrefix(callName, "syz_") {
		fmt.Fprintf(w, "%v(", callName)
	} else {
		args := strings.Repeat(",long", len(call.Args))
		if args != "" {
			args = args[1:]
		}
		fmt.Fprintf(w, "((long(*)(%v))CAST(%v))(", args, callName)
	}
}

func (ctx *context) generateCsumInet(w *bytes.Buffer, addr uint64, arg prog.ExecArgCsum, csumSeq int) {
	fmt.Fprintf(w, "\tstruct csum_inet csum_%d;\n", csumSeq)
	fmt.Fprintf(w, "\tcsum_inet_init(&csum_%d);\n", csumSeq)
	for i, chunk := range arg.Chunks {
		switch chunk.Kind {
		case prog.ExecArgCsumChunkData:
			fmt.Fprintf(w, "\tNONFAILING(csum_inet_update(&csum_%d, (const uint8*)0x%x, %d));\n",
				csumSeq, chunk.Value, chunk.Size)
		case prog.ExecArgCsumChunkConst:
			fmt.Fprintf(w, "\tuint%d csum_%d_chunk_%d = 0x%x;\n",
				chunk.Size*8, csumSeq, i, chunk.Value)
			fmt.Fprintf(w, "\tcsum_inet_update(&csum_%d, (const uint8*)&csum_%d_chunk_%d, %d);\n",
				csumSeq, csumSeq, i, chunk.Size)
		default:
			panic(fmt.Sprintf("unknown checksum chunk kind %v", chunk.Kind))
		}
	}
	fmt.Fprintf(w, "\tNONFAILING(*(uint16*)0x%x = csum_inet_digest(&csum_%d));\n",
		addr, csumSeq)
}

func (ctx *context) copyin(w *bytes.Buffer, csumSeq *int, copyin prog.ExecCopyin) {
	switch arg := copyin.Arg.(type) {
	case prog.ExecArgConst:
		if arg.BitfieldOffset == 0 && arg.BitfieldLength == 0 {
			ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.constArgToStr(arg, true), arg.Format)
		} else {
			if arg.Format != prog.FormatNative && arg.Format != prog.FormatBigEndian {
				panic("bitfield+string format")
			}
			htobe := ""
			if arg.Format == prog.FormatBigEndian {
				htobe = fmt.Sprintf("htobe%v", arg.Size*8)
			}
			fmt.Fprintf(w, "\tNONFAILING(STORE_BY_BITMASK(uint%v, %v, 0x%x, %v, %v, %v));\n",
				arg.Size*8, htobe, copyin.Addr, ctx.constArgToStr(arg, false),
				arg.BitfieldOffset, arg.BitfieldLength)
		}
	case prog.ExecArgResult:
		ctx.copyinVal(w, copyin.Addr, arg.Size, ctx.resultArgToStr(arg), arg.Format)
	case prog.ExecArgData:
		if ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(copyin.Addr, 16)] != nil {
			num := ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(copyin.Addr, 16)].([]interface{})
			val := fmt.Sprintf("\tNONFAILING(memcpy((void*)0x%x, \"", copyin.Addr)
			for index := 0; index < len(num) && index < len(arg.Data); index++ {
				val = fmt.Sprintf("%s\\x%02x", val, int(num[index].(float64)))
			}
			for index := len(num); index < len(arg.Data); index++ {
				val = fmt.Sprintf("%s\\x%02x", val, arg.Data[index])
			}
			fmt.Fprintf(w, "%s\", %v));\n", val, len(arg.Data))
			delete(ctx.opts.Exploit.Solution, "ptr_0x"+strconv.FormatUint(copyin.Addr, 16))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(memcpy((void*)0x%x, \"%s\", %v));\n",
				copyin.Addr, toCString(arg.Data, arg.Readable), len(arg.Data))
		}
	case prog.ExecArgCsum:
		switch arg.Kind {
		case prog.ExecArgCsumInet:
			*csumSeq++
			ctx.generateCsumInet(w, copyin.Addr, arg, *csumSeq)
		default:
			panic(fmt.Sprintf("unknown csum kind %v", arg.Kind))
		}
	default:
		panic(fmt.Sprintf("bad argument type: %+v", arg))
	}
}

func (ctx *context) copyinVal(w *bytes.Buffer, addr, size uint64, val string, bf prog.BinaryFormat) {
	switch bf {
	case prog.FormatNative, prog.FormatBigEndian:
		if ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)] != nil {
			num := ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)].([]interface{})
			if len(num) > 8 {
				break
			}
			val = "0x"
			for index := int(len(num) - 1); index >= 0; index-- {
				val = fmt.Sprintf("%s%02x", val, int(num[index].(float64)))
			}
			delete(ctx.opts.Exploit.Solution, "ptr_0x"+strconv.FormatUint(addr, 16))
			fmt.Fprintf(w, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", size*8, addr, val)
		} else {
			fmt.Fprintf(w, "\tNONFAILING(*(uint%v*)0x%x = %v);\n", size*8, addr, val)
		}
	case prog.FormatStrDec:
		if size != 20 {
			panic("bad strdec size")
		}
		if ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)] != nil {
			num := ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)].([]interface{})
			val := fmt.Sprintf("\tNONFAILING(*(char*)0x%x = \"", addr)
			for index := int(len(num) - 1); index >= 0; index-- {
				val = fmt.Sprintf("%s\\x%02x", val, int(num[index].(float64)))
			}
			fmt.Fprintf(w, "%s\");\n", val)
			delete(ctx.opts.Exploit.Solution, "ptr_0x"+strconv.FormatUint(addr, 16))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%020llu\", (long long)%v));\n", addr, val)
		}
	case prog.FormatStrHex:
		if size != 18 {
			panic("bad strdec size")
		}
		if ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)] != nil {
			num := ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)].([]interface{})
			val := fmt.Sprintf("\tNONFAILING(*(char*)0x%x = \"", addr)
			for index := int(len(num) - 1); index >= 0; index-- {
				val = fmt.Sprintf("%s\\x%02x", val, int(num[index].(float64)))
			}
			fmt.Fprintf(w, "%s\");\n", val)
			delete(ctx.opts.Exploit.Solution, "ptr_0x"+strconv.FormatUint(addr, 16))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"0x%%016llx\", (long long)%v));\n", addr, val)
		}
	case prog.FormatStrOct:
		if size != 23 {
			panic("bad strdec size")
		}
		if ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)] != nil {
			num := ctx.opts.Exploit.Solution["ptr_0x"+strconv.FormatUint(addr, 16)].([]interface{})
			val := fmt.Sprintf("\tNONFAILING(*(char*)0x%x = \"", addr)
			for index := int(len(num) - 1); index >= 0; index-- {
				val = fmt.Sprintf("%s\\x%02x", val, int(num[index].(float64)))
			}
			fmt.Fprintf(w, "%s\");\n", val)
			delete(ctx.opts.Exploit.Solution, "ptr_0x"+strconv.FormatUint(addr, 16))
		} else {
			fmt.Fprintf(w, "\tNONFAILING(sprintf((char*)0x%x, \"%%023llo\", (long long)%v));\n", addr, val)
		}
	default:
		panic("unknown binary format")
	}
}

func (ctx *context) copyout(w *bytes.Buffer, call prog.ExecCall, resCopyout bool) {
	if ctx.sysTarget.OS == "fuchsia" {
		// On fuchsia we have real system calls that return ZX_OK on success,
		// and libc calls that are casted to function returning long,
		// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
		if strings.HasPrefix(call.Meta.CallName, "zx_") {
			fmt.Fprintf(w, "\tif (res == ZX_OK)")
		} else {
			fmt.Fprintf(w, "\tif ((int)res != -1)")
		}
	} else {
		fmt.Fprintf(w, "\tif (res != -1)")
	}
	copyoutMultiple := len(call.Copyout) > 1 || resCopyout && len(call.Copyout) > 0
	if copyoutMultiple {
		fmt.Fprintf(w, " {")
	}
	fmt.Fprintf(w, "\n")
	if resCopyout {
		fmt.Fprintf(w, "\t\tr[%v] = res;\n", call.Index)
	}
	for _, copyout := range call.Copyout {
		fmt.Fprintf(w, "\t\tNONFAILING(r[%v] = *(uint%v*)0x%x);\n",
			copyout.Index, copyout.Size*8, copyout.Addr)
	}
	if copyoutMultiple {
		fmt.Fprintf(w, "\t}\n")
	}
}

func (ctx *context) constArgToStr(arg prog.ExecArgConst, handleBigEndian bool) string {
	mask := (uint64(1) << (arg.Size * 8)) - 1
	v := arg.Value & mask
	val := fmt.Sprintf("%v", v)
	if v == ^uint64(0)&mask {
		val = "-1"
	} else if v >= 10 {
		val = fmt.Sprintf("0x%x", v)
	}
	if ctx.opts.Procs > 1 && arg.PidStride != 0 {
		val += fmt.Sprintf(" + procid*%v", arg.PidStride)
	}
	if handleBigEndian && arg.Format == prog.FormatBigEndian {
		val = fmt.Sprintf("htobe%v(%v)", arg.Size*8, val)
	}
	return val
}

func (ctx *context) getconstArg(arg prog.Arg) uint64 {
	// mask := (uint64(1) << (arg.Size * 8)) - 1
	// v := arg.Value & mask
	// if v == ^uint64(0)&mask {
	// 	return ^uint64(0)
	// }
	switch res := arg.(type) {
	case *prog.ConstArg:
		return res.Val
	case *prog.PointerArg:
		return res.Address
	}
	return 0
}

func (ctx *context) resultArgToStr(arg prog.ExecArgResult) string {
	res := fmt.Sprintf("r[%v]", arg.Index)
	if arg.DivOp != 0 {
		res = fmt.Sprintf("%v/%v", res, arg.DivOp)
	}
	if arg.AddOp != 0 {
		res = fmt.Sprintf("%v+%v", res, arg.AddOp)
	}
	if arg.Format == prog.FormatBigEndian {
		res = fmt.Sprintf("htobe%v(%v)", arg.Size*8, res)
	}
	return res
}

func (ctx *context) postProcess(result []byte) []byte {
	// Remove NONFAILING, debug, fail, etc calls.
	if !ctx.opts.HandleSegv {
		result = regexp.MustCompile(`\t*NONFAILING\((.*)\);\n`).ReplaceAll(result, []byte("$1;\n"))
	}
	result = bytes.Replace(result, []byte("NORETURN"), nil, -1)
	result = bytes.Replace(result, []byte("doexit("), []byte("exit("), -1)
	result = regexp.MustCompile(`PRINTF\(.*?\)`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*debug_dump_data\((.*\n)*?.*\);\n`).ReplaceAll(result, nil)
	result = regexp.MustCompile(`\t*exitf\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))
	result = regexp.MustCompile(`\t*fail\((.*\n)*?.*\);\n`).ReplaceAll(result, []byte("\texit(1);\n"))

	result = ctx.hoistIncludes(result)
	// if ctx.opts.Exp {
	// 	result = addDenpendences(ctx.opts.ExpTarget, result)
	// }
	result = ctx.removeEmptyLines(result)
	return result
}

// hoistIncludes moves all includes to the top, removes dups and sorts.
func (ctx *context) hoistIncludes(result []byte) []byte {
	includesStart := bytes.Index(result, []byte("#include"))
	if includesStart == -1 {
		return result
	}
	includes := make(map[string]bool)
	includeRe := regexp.MustCompile("#include <.*>\n")
	for _, match := range includeRe.FindAll(result, -1) {
		includes[string(match)] = true
	}
	result = includeRe.ReplaceAll(result, nil)
	// Certain linux and bsd headers are broken and go to the bottom.
	var sorted, sortedBottom, sortedTop []string
	for include := range includes {
		if strings.Contains(include, "<linux/") {
			sortedBottom = append(sortedBottom, include)
		} else if strings.Contains(include, "<netinet/if_ether.h>") {
			sortedBottom = append(sortedBottom, include)
		} else if strings.Contains(include, "<keyutils.h>") {
			sortedBottom = append(sortedBottom, include)
		} else if ctx.target.OS == freebsd && strings.Contains(include, "<sys/types.h>") {
			sortedTop = append(sortedTop, include)
		} else {
			sorted = append(sorted, include)
		}
	}
	sort.Strings(sortedTop)
	sort.Strings(sorted)
	sort.Strings(sortedBottom)
	newResult := append([]byte{}, result[:includesStart]...)
	newResult = append(newResult, strings.Join(sortedTop, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sorted, "")...)
	newResult = append(newResult, '\n')
	newResult = append(newResult, strings.Join(sortedBottom, "")...)
	newResult = append(newResult, result[includesStart:]...)
	return newResult
}

// removeEmptyLines removes duplicate new lines.
func (ctx *context) removeEmptyLines(result []byte) []byte {
	for {
		newResult := bytes.Replace(result, []byte{'\n', '\n', '\n'}, []byte{'\n', '\n'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', '\t'}, []byte{'\n', '\t'}, -1)
		newResult = bytes.Replace(newResult, []byte{'\n', '\n', ' '}, []byte{'\n', ' '}, -1)
		if len(newResult) == len(result) {
			return result
		}
		result = newResult
	}
}

func toCString(data []byte, readable bool) []byte {
	if len(data) == 0 {
		panic("empty data arg")
	}
	buf := new(bytes.Buffer)
	prog.EncodeData(buf, data, readable)
	return buf.Bytes()
}

func (ctx *context) symbolicSize(s2e_arg *prog.LenType, parent []prog.Arg) bool {
	if s2e_arg.Buf == "parent" {
		return true
	}
	for _, field := range parent {
		if s2e_arg.Buf != field.Type().FieldName() {
			continue
		}
		if inner := prog.InnerArg(field); inner != nil {
			switch targetType := inner.Type().(type) {
			case *prog.BufferType:
				// fmt.Printf("BufferType type\n")
				return targetType.Dir() != prog.DirOut
			default:
				// fmt.Printf("Type: %v\n", targetType);
			}
		}
	}
	return false
}

func (ctx *context) getBufIndex(s2e_arg *prog.LenType, parent []prog.Arg) int {
	for i, field := range parent {
		if s2e_arg.Buf == field.Type().FieldName() {
			return i
		}
	}
	return -1
}

func (ctx *context) copyinDefine(name, val string, arg prog.Arg) string {
	var var_name string
	switch {
	case strings.HasPrefix(name, "local"):
		var_name = name
		break
	case strings.HasPrefix(name, "0x"):
		panic("get pointer")
		break
	}

	if ctx.opts.Exploit.Solution[var_name] != nil {
		num := ctx.opts.Exploit.Solution[var_name].([]interface{})
		if len(num) > 8 {
			return ""
		}
		newVal := "0x"
		for index := int(len(num) - 1); index >= 0; index-- {
			newVal = fmt.Sprintf("%s%02x", newVal, int(num[index].(float64)))
		}
		delete(ctx.opts.Exploit.Solution, var_name)
		return fmt.Sprintf("\t%s %s = %s;", getArgType(arg), var_name, newVal)
	} else {
		return fmt.Sprintf("\t%s %s = %s;", getArgType(arg), var_name, val)
	}
}

func (ctx *context) getLenIndex(arg prog.Arg, parent []prog.Arg) int {
	for i, field := range parent {
		if len, ok := field.Type().(*prog.LenType); ok {
			if len.Buf == arg.Type().FieldName() {
				return i
			}
		}
	}
	return -1
}

func (ctx *context) checkCall(name string) bool {
	if _, ok := SymbolCall_whitelist[name]; ok {
		return true
	}
	return false
}

func (ctx *context) checkArg(arg prog.Arg) bool {
	if _, ok := SymbolArg_whitelist[arg.Type().FieldName()]; ok {
		return true
	}
	switch t := arg.Type().(type) {
	case *prog.StructType:
		if _, ok := SymbolArg_whitelist[t.Key.Name]; ok {
			return true
		}
	default:
	}
	return false
}

func (ctx *context) constArgToVar(arg prog.ExecArgConst, s2e_arg prog.Arg, parent []prog.Arg, address uint64) (ret []Variable) {
	// fmt.Printf("%T, %T, %s, %x\n", s2e_arg, s2e_arg.Type(), s2e_arg.Type().FieldName(), address)
	var_name, def, size := "", "", ""
	if s2e_arg == nil {
		return ret
	}

	val := ctx.constArgToStr(arg, true)
	if ctx.checkArg(s2e_arg) {
		if len(ret) == 0 {
			ret = append(ret, Variable{
				Name: val,
				Def:  "",
				Size: "",
			})
		}
		return ret
	}
	// fmt.Printf("%T, %T, %s, %x\n", s2e_arg, s2e_arg.Type(), s2e_arg.Type().FieldName(), address)

	switch mytype := s2e_arg.Type().(type) {
	case *prog.StructType:
		// fmt.Printf("Struct: %T %v\n", s2e_arg, mytype)
		a := s2e_arg.(*prog.GroupArg)
		base_addr := uint64(0)
		if address != 0 {
			base_addr = address
		} else {
			base_addr = arg.Value
		}
		for _, inner := range a.Inner {
			results := ctx.constArgToVar(arg, inner, a.Inner, base_addr)
			ret = append(ret, results...)
			if !inner.Type().BitfieldMiddle() {
				base_addr += inner.Size()
			}
		}
		ret = append([]Variable{Variable{
			Name: val,
			Def:  "",
			Size: "",
		}}, ret...)
		return ret
	case *prog.UnionType:
		a := s2e_arg.(*prog.UnionArg)
		for _, option := range mytype.Fields {
			if a.Option.Type().FieldName() == option.FieldName() {
				results := ctx.constArgToVar(arg, a.Option, parent, address)
				ret = append(ret, results...)
				return ret
			}
		}
	case *prog.ArrayType:
		a := s2e_arg.(*prog.GroupArg)
		base_addr := address
		for _, inner := range a.Inner {
			results := ctx.constArgToVar(arg, inner, a.Inner, base_addr)
			if !inner.Type().BitfieldMiddle() {
				base_addr += inner.Size()
			}
			ret = append(ret, results...)
		}
		ret = append([]Variable{Variable{
			Name: val,
			Def:  "",
			Size: "",
		}}, ret...)
		return ret
	// case *prog.CsumType:
	case *prog.ConstType:
		// fmt.Printf("Const: %v\n", mytype);
	case *prog.BufferType:
		if address != 0 {
			val = fmt.Sprintf("0x%x", address)
		}
		// fmt.Printf("Buffer: %v %d\n", mytype, mytype.Kind)
		if mytype.Kind == prog.BufferString {
			break
		}
		if mytype.Dir() == prog.DirOut {
			// fmt.Printf("Dir: out\n")
			break
		}
		// fmt.Printf("buffer: %v\n", s2e_arg)
		if s2e_arg.Size() != 0 {
			size = fmt.Sprintf("%v", s2e_arg.Size())
		} else if len(parent) == 0 {
			size = "256"
		}
	// case *VmaType:
	// case *ProcType:
	case *prog.IntType:
		const_arg := s2e_arg.(*prog.ConstArg)
		size = fmt.Sprintf("%v", const_arg.Size())
		if address == 0 {
			var_name = ctx.assignVar(false)
			def = ctx.copyinDefine(var_name, fmt.Sprintf("%v", const_arg.Val), s2e_arg)
			val = var_name
		} else {
			val = fmt.Sprintf("0x%x", address)
		}
	case *prog.LenType:
		// fmt.Printf("Len: %v\n", mytype)
		// TODO: check if we symbolize the corresponding buffer
		if !ctx.symbolicSize(mytype, parent) {
			break
		}
		if address == 0 {
			var_name = ctx.assignVar(false)
			def = ctx.copyinDefine(var_name, val, s2e_arg)
			val = var_name
		} else {
			val = fmt.Sprintf("0x%x", address)
		}
		size = getArgSize(s2e_arg)
	case *prog.ResourceType:
		// fmt.Printf("Resource: %v\n", mytype)
	case *prog.PtrType:
		// fmt.Printf("Pointer: %v\n", mytype)
		if mytype.Dir() == prog.DirOut {
			// fmt.Printf("Dir: out\n")
			break
		}
		a := s2e_arg.(*prog.PointerArg)
		// We need analyse a.Res further. If a.Res is a buffer,
		// it needs special process.
		if a.Res == nil {
			break
		}
		return ctx.constArgToVar(arg, a.Res, []prog.Arg{}, ctx.target.DataOffset+a.Address)
	case *prog.FlagsType:
		// fmt.Printf("Flags: %v\n", mytype)
	default:
		// fmt.Printf("unknown: %v %T\n", mytype, mytype)
	}
	// fmt.Printf("%s\n", def)
	ret = append(ret, Variable{
		Name: val,
		Def:  def,
		Size: size,
	})
	return ret
}

func (ctx *context) assignVar(isPointer bool) string {
	ctx.num_vars += 1
	if !isPointer {
		return fmt.Sprintf("local_%d", ctx.num_vars)
	} else {
		return fmt.Sprintf("ptr_%d", ctx.num_vars)
	}
}

func getStringType(size uint64) string {
	switch size {
	case 1:
		return "uint8"
	case 2:
		return "uint16"
	case 4:
		return "uint32"
	case 8:
		return "uint64" //is it ok to use 32bit integer?
	default:
		panic("unknown size")
	}
}

func getArgType(arg prog.Arg) string {
	return getStringType(arg.Size())
}

func getExecType(arg prog.ExecArgConst) string {
	return getStringType(arg.Size)
}

func getStringSize(size uint64) string {
	switch size {
	case 1:
		return "1"
	case 2:
		return "2"
	case 4:
		return "4"
	case 8:
		return "8" //is it ok to use 32bit integer?
	default:
		panic("unknown size")
		return ""
	}
}

func getExecSize(arg prog.ExecArgConst) string {
	return getStringSize(arg.Size)
}

func getArgSize(arg prog.Arg) string {
	return getStringSize(arg.Size())
}
