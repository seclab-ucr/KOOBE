package repro

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	_ "sort"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	instancePkg "github.com/google/syzkaller/pkg/instance"
	_ "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

func S2ERun(crashLog []byte, cfg *mgrconfig.Config, reporter report.Reporter, vmPool *vm.Pool,
	vmIndexes []int) (*Result, *Stats, error) {

	if len(vmIndexes) == 0 {
		return nil, nil, fmt.Errorf("no VMs provided")
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		return nil, nil, err
	}
	entries := target.S2EParseLog(crashLog)
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("crash log does not contain any programs")
	}

	ctx := &context{
		cfg:          cfg,
		reporter:     reporter,
		crashTitle:   "",
		instances:    make(chan *instance, len(vmIndexes)),
		bootRequests: make(chan int, len(vmIndexes)),
		stats:        new(Stats),
	}

	var wg sync.WaitGroup
	wg.Add(len(vmIndexes))
	for _, vmIndex := range vmIndexes {
		ctx.bootRequests <- vmIndex
		go func() {
			defer wg.Done()
			for vmIndex := range ctx.bootRequests {
				var inst *instance
				maxTry := 3
				for try := 0; try < maxTry; try++ {
					select {
					case <-vm.Shutdown:
						try = maxTry
						continue
					default:
					}
					vmInst, err := vmPool.Create(vmIndex)
					if err != nil {
						ctx.reproLog(0, "failed to create VM: %v", err)
						time.Sleep(10 * time.Second)
						continue

					}
					execprogBin, err := vmInst.Copy(cfg.SyzExecprogBin)
					if err != nil {
						ctx.reproLog(0, "failed to copy to VM: %v", err)
						vmInst.Close()
						time.Sleep(10 * time.Second)
						continue
					}
					executorBin, err := vmInst.Copy(cfg.SyzExecutorBin)
					if err != nil {
						ctx.reproLog(0, "failed to copy to VM: %v", err)
						vmInst.Close()
						time.Sleep(10 * time.Second)
						continue
					}
					inst = &instance{
						Instance:    vmInst,
						index:       vmIndex,
						execprogBin: execprogBin,
						executorBin: executorBin,
					}
					break
				}
				if inst == nil {
					break
				}
				ctx.instances <- inst
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ctx.instances)
		for inst := range ctx.instances {
			inst.Close()
		}
	}()
	defer func() {
		close(ctx.bootRequests)
	}()

	res, err := ctx.S2Erepro(entries)
	if err != nil {
		return nil, nil, err
	}
	if res != nil {
		ctx.reproLog(3, "repro crashed as (corrupted=%v):\n%s",
			ctx.report.Corrupted, ctx.report.Report)
		// Try to rerun the repro if the report is corrupted.
		for attempts := 0; ctx.report.Corrupted && attempts < 3; attempts++ {
			ctx.reproLog(3, "report is corrupted, running repro again")
			if res.CRepro {
				_, err = ctx.testCProg(res.Prog, res.Duration, res.Opts)
			} else {
				_, err = ctx.testProg(res.Prog, res.Duration, res.Opts)
			}
			if err != nil {
				return nil, nil, err
			}
		}
		ctx.reproLog(3, "final repro crashed as (corrupted=%v):\n%s",
			ctx.report.Corrupted, ctx.report.Report)
		res.Report = ctx.report
	}
	ctx.reproLog(0, "returning ...")
	return res, ctx.stats, nil
}

func (ctx *context) S2Erepro(entries []*prog.LogEntry) (*Result, error) {

	reproStart := time.Now()
	defer func() {
		ctx.reproLog(3, "reproducing took %s", time.Since(reproStart))
	}()

	_, err := ctx.extractS2EProg(entries)
	if err != nil {
		return nil, err
	}

	for _, res := range ctx.results {
		ctx.reproLog(0, "executing program: %s", res.Prog.Serialize())
	}

	for _, res := range ctx.results {
		res, err = ctx.minimizeS2EProg(res)
		if err != nil {
			continue
		}
	}

	ctx.reproLog(0, "After minimizing...")
	for _, res := range ctx.results {
		ctx.reproLog(0, "executing program: %s", res.Prog.Serialize())
	}

	return nil, nil
}

func (ctx *context) extractS2EProg(entries []*prog.LogEntry) (*Result, error) {
	start := time.Now()
	defer func() {
		ctx.stats.ExtractProgTime = time.Since(start)
	}()

	// The shortest duration is 10 seconds to detect simple crashes (i.e. no races and no hangs).
	// The longest duration is 5 minutes to catch races and hangs. Note that this value must be larger
	// than hang/no output detection duration in vm.MonitorExecution, which is currently set to 3 mins.
	// timeouts := []time.Duration{10 * time.Second, 1 * time.Minute, 5 * time.Minute}

	// Execute every program to eliminate false positive (program that does not crash)
	for _, entry := range entries {
		// for _, timeout := range timeouts {
		res, err := ctx.extractS2EProgSingle(entry, 2*time.Minute)
		if err != nil {
			continue
		}
		if res != nil && res.Cap != nil {
			ctx.reproLog(3, "found reproducer with %d syscalls", len(res.Prog.Calls))
			ctx.compareCapability(res)
		}
		// }
	}

	return nil, nil
}

func (ctx *context) extractCapability(res *Result) *Capability {
	var title string
	if res == nil {
		title = ctx.report.Title
	} else {
		title = res.Report.Title
	}

	index := strings.Index(title, "WARNING:")
	if index == -1 {
		return nil
	}
	msg := title[index+len("WARNING:"):]
	cap := &Capability{}
	if err := json.Unmarshal([]byte(msg), cap); err != nil {
		ctx.reproLog(0, "failed to parse json %s", msg)
		return nil
	}
	return cap
}

func (ctx *context) compareCapability(res *Result) bool {
	needed := true
	for i, each := range ctx.results {
		score := ctx.compare(res.Cap, each.Cap)
		if score == 0 {
			continue
		} else if score > 0 {
			ctx.results[i] = nil
		} else {
			needed = false
		}
	}
	if needed {
		ctx.results = append(ctx.results, res)
	}
	// remove nil
	start, tail := 0, len(ctx.results)-1
	for start < tail {
		if ctx.results[start] == nil {
			ctx.results[start] = ctx.results[tail]
			ctx.results[tail] = nil
			tail -= 1
		} else {
			start += 1
		}
	}
	ctx.results = ctx.results[:tail+1]
	return true
}

func (ctx *context) compare(a, b *Capability) int {
	// compare length
	if len(a.Offsets) > len(b.Offsets) {
		return 1
	}
	if len(a.Offsets) <= len(b.Offsets) {
		return -1
	}
	// compare offset
	return 0
}

func (ctx *context) extractS2EProgSingle(ent *prog.LogEntry, duration time.Duration) (*Result, error) {
	ctx.reproLog(3, "single: executing programs separately with timeout %s", duration)

	opts := csource.DefaultOpts(ctx.cfg)
	opts.Fault = ent.Fault
	opts.FaultCall = ent.FaultCall
	opts.FaultNth = ent.FaultNth
	if opts.FaultCall < 0 || opts.FaultCall >= len(ent.P.Calls) {
		opts.FaultCall = len(ent.P.Calls) - 1
	}
	crashed, err := ctx.testS2EProg(ent.P, duration, opts)
	if err != nil {
		return nil, err
	}
	if crashed {
		res := &Result{
			Prog:     ent.P,
			Duration: duration * 3 / 2,
			Opts:     opts,
			Report:   ctx.report,
			Cap:      ctx.extractCapability(nil),
		}
		ctx.reproLog(3, "single: successfully extracted reproducer")
		return res, nil
	}

	ctx.reproLog(3, "single: failed to extract reproducer")
	return nil, nil
}

func (ctx *context) testS2EProg(p *prog.Prog, duration time.Duration, opts csource.Options) (crashed bool, err error) {
	entry := prog.LogEntry{P: p}
	if opts.Fault {
		entry.Fault = true
		entry.FaultCall = opts.FaultCall
		entry.FaultNth = opts.FaultNth
	}
	return ctx.testS2EProgs([]*prog.LogEntry{&entry}, duration, opts)
}

func (ctx *context) testS2EProgs(entries []*prog.LogEntry, duration time.Duration, opts csource.Options) (
	crashed bool, err error) {
	inst := <-ctx.instances
	if inst == nil {
		return false, fmt.Errorf("all VMs failed to boot")
	}
	defer ctx.returnInstance(inst)
	if len(entries) == 0 {
		return false, fmt.Errorf("no programs to execute")
	}

	pstr := encodeEntries(entries)
	progFile, err := osutil.WriteTempFile(pstr)
	if err != nil {
		return false, err
	}
	defer os.Remove(progFile)
	vmProgFile, err := inst.Copy(progFile)
	if err != nil {
		return false, fmt.Errorf("failed to copy to VM: %v", err)
	}

	if !opts.Fault {
		opts.FaultCall = -1
	}
	program := entries[0].P.String()
	if len(entries) > 1 {
		program = "["
		for i, entry := range entries {
			program += fmt.Sprintf("%v", len(entry.P.Calls))
			if i != len(entries)-1 {
				program += ", "
			}
		}
		program += "]"
	}

	command := instancePkg.S2EExecprogCmd(inst.execprogBin, inst.executorBin,
		ctx.cfg.TargetOS, ctx.cfg.TargetArch, opts.Sandbox, 1, // opts.Repeat,
		opts.Threaded, opts.Collide, opts.Procs, -1, -1, vmProgFile)
	ctx.reproLog(2, "testing program (duration=%v, %+v): %s", duration, opts, program)
	ctx.reproLog(3, "detailed listing:\n%s", pstr)
	return ctx.testS2EImpl(inst.Instance, command, duration)
}

func (ctx *context) testS2EImpl(inst *vm.Instance, command string, duration time.Duration) (crashed bool, err error) {
	outc, errc, err := inst.Run(duration, nil, command)
	if err != nil {
		return false, fmt.Errorf("failed to run command in VM: %v", err)
	}
	rep := inst.MonitorExecution(outc, errc, ctx.reporter,
		vm.ExitTimeout|vm.ExitNormal|vm.ExitError)
	if rep == nil {
		ctx.reproLog(2, "program did not crash")
		return false, nil
	}
	if rep.Suppressed {
		ctx.reproLog(2, "suppressed program crash: %v", rep.Title)
		return false, nil
	}
	ctx.report = rep
	rep.Title = ctx.extractDescription()
	ctx.reproLog(2, "program crashed: %v", rep.Title)
	return true, nil
}

func (ctx *context) extractDescription() string {
	desp := []byte("WARNING:")
	start := bytes.Index(ctx.report.Report, desp)
	if start == -1 {
		return ""
	}
	out := ctx.report.Report[start:]
	end := bytes.IndexByte(out, '}')
	if end == -1 {
		return ""
	}
	return string(out[:end+1])
}

// Minimize calls.
func (ctx *context) minimizeS2EProg(res *Result) (*Result, error) {
	ctx.reproLog(2, "minimizing guilty program")
	start := time.Now()
	defer func() {
		ctx.stats.MinimizeProgTime = time.Since(start)
	}()

	call := -1
	if res.Opts.Fault {
		call = res.Opts.FaultCall
	}

	// ctx.reproLog(0, "results: %s", res.Report.Title)
	orig_cap := ctx.extractCapability(res)
	ctx.reproLog(0, "origin cap: %v", orig_cap.Size)
	res.Prog, res.Opts.FaultCall = prog.S2EMinimize(res.Prog, call, true,
		func(p1 *prog.Prog, callIndex int) bool {
			crashed, err := ctx.testS2EProg(p1, res.Duration, res.Opts)
			if err != nil {
				ctx.reproLog(0, "minimization failed with %v", err)
				return false
			}
			if crashed {
				cap := ctx.extractCapability(nil)
				ctx.reproLog(0, "new cap: %v", cap.Size)
				// if (cap.Size == 0) {
				// 	return false
				// }
				if ctx.compare(orig_cap, cap) > 0 {
					return false
				}
			}
			return crashed
		})

	return res, nil
}
