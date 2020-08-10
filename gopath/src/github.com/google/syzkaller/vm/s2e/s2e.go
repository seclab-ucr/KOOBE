package s2e

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

const (
	hostAddr = "10.0.2.10"
)

func init() {
	vmimpl.Register("s2e", ctor, false)
}

type Config struct {
	Count       int    `json:"count"`       // number of VMs to use
	S2E_project string `json:"s2e_project"` // qemu binary name (qemu-system-arch by default)
	QemuArgs    string `json:"qemu_args"`   // additional command line arguments for qemu binary
	// Kernel      string `json:"kernel"`       // kernel for injected boot (e.g. arch/x86/boot/bzImage)
	Cmdline string `json:"cmdline"` // kernel command line (can only be specified with kernel)
	// Initrd      string `json:"initrd"`       // linux initial ramdisk. (optional)
	// ImageDevice string `json:"image_device"` // qemu image device (hda by default)
	CPU int `json:"cpu"` // number of VM CPUs
	Mem int `json:"mem"` // amount of VM memory in MBs
	// Snapshot    bool   `json:"snapshot"`     // For building kernels without -snapshot (for pkg/build)
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	debug       bool
	s2e         *exec.Cmd
	s2e_project string
	workdir     string
	port        int
	rpipe       io.ReadCloser
	wpipe       io.WriteCloser
	merger      *vmimpl.OutputMerger
	files       []string
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Count: 1,
		CPU:   1,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse qemu vm config: %v", err)
	}
	if _, err := os.Stat(cfg.S2E_project); err != nil {
		return nil, fmt.Errorf("failed to parse s2e qemu config: %v", err)
	}

	num := 0
	for i := 0; ; i++ {
		path := filepath.Join(cfg.S2E_project, fmt.Sprintf("syzkaller-%d", i))
		if _, err := os.Stat(path); err != nil {
			break
		}
		num += 1
	}
	if cfg.Count > num {
		return nil, fmt.Errorf("invalid config param count: %v, maximum %d", cfg.Count, num)
	}
	if env.Debug && cfg.Count > 1 {
		log.Logf(0, "limiting number of VMs from %v to 1 in debug mode", cfg.Count)
		cfg.Count = 1
	}

	pool := &Pool{
		env: env,
		cfg: cfg,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return pool.cfg.Count
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		s2e_project: filepath.Join(pool.cfg.S2E_project, fmt.Sprintf("syzkaller-%d", index)),
		workdir:     workdir,
		debug:       pool.env.Debug,
	}
	var err error
	inst.rpipe, inst.wpipe, err = osutil.LongPipe()
	if err != nil {
		return nil, err
	}

	// Start output merger.
	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	inst.merger = vmimpl.NewOutputMerger(tee)
	inst.merger.Add("s2e", inst.rpipe)
	inst.rpipe = nil
	return inst, nil
}

// interface for s2e instance
func (inst *instance) Forward(port int) (string, error) {
	addr := hostAddr
	inst.port = port
	return fmt.Sprintf("%v:%v", addr, port), nil
}

func getChildren(pid int) []int {
	var ret []int
	cmd := []string{"/bin/ps", "-o", "pid,ppid,cmd"}
	out, err := exec.Command(cmd[0], cmd[1:]...).Output()
	if err != nil {
		log.Fatal(fmt.Errorf("Failed to get children processes: %v", err))
	}
	target_pid := fmt.Sprintf("%d", pid)
	compRegEx := regexp.MustCompile(`(?P<pid>[\d]+)\s+(?P<ppid>[\d]+)`)
	for _, line := range strings.Split(string(out), "\n")[1:] {
		match := compRegEx.FindStringSubmatch(line)
		if len(match) != 0 && match[2] == target_pid {
			if num, err := strconv.Atoi(match[1]); err == nil {
				ret = append(ret, num)
			}
		}
	}
	return ret
}

func (inst *instance) killS2E() {
	if inst.s2e != nil {
		// kill qemu first
		children := getChildren(inst.s2e.Process.Pid)
		for _, child := range children {
			if err := syscall.Kill(child, syscall.SIGKILL); err != nil {
				log.Logf(0, "kill process failed %v", err)
			}
		}
		// kill the script that launched qemu
		if inst.s2e != nil {
			inst.s2e.Process.Kill()
			inst.s2e.Wait()
		}
	}
	inst.s2e = nil
}

func (inst *instance) Close() {
	inst.killS2E()

	if inst.merger != nil {
		inst.merger.Wait()
	}
	if inst.rpipe != nil {
		inst.rpipe.Close()
	}
	if inst.wpipe != nil {
		inst.wpipe.Close()
	}

	// clean up
	for _, filename := range inst.files {
		dstfile := filepath.Join(inst.s2e_project, filename)
		if _, err := os.Stat(dstfile); err == nil {
			if err = os.Remove(dstfile); err != nil {
				log.Logf(0, "error: delete file %s", dstfile)
			}
		}
	}
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	log.Logf(0, "copying %s", hostSrc)

	handled := []string{"syz-fuzzer", "syz-executor", "syz-execprog"}
	_, filename := filepath.Split(hostSrc)
	inst.files = append(inst.files, filename)
	for _, name := range handled {
		if name == filename {
			return filename, nil
		}
	}

	// copy the unhandled file to the project dir
	dstfile := filepath.Join(inst.s2e_project, filename)
	cmd := exec.Command("cp", hostSrc, dstfile)
	if err := cmd.Run(); err != nil {
		return filename, err
	}
	return filename, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (
	<-chan []byte, <-chan error, error) {
	log.Logf(0, "start to run %s", command)
	args := strings.Split(command, " ")
	args[0] = fmt.Sprintf("./%s", args[0])
	s2ebin := filepath.Join(inst.s2e_project, "launch-s2e.sh")
	for index, arg := range args {
		if arg == "-executor=syz-executor" {
			args[index] = "-executor=/home/s2e/syz-executor"
		} else if strings.HasPrefix(arg, "-procs=") {
			if arg != "-procs=1" {
				log.Logf(1, "Only 1 proc is allowed")
				args[index] = "-procs=1"
			}
		}
	}

	bootstrap_template := filepath.Join(inst.s2e_project, "bootstrap.sh.template")
	bootstrap := filepath.Join(inst.s2e_project, "bootstrap.sh")
	data, err := ioutil.ReadFile(bootstrap_template)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to load file bootstrap.sh")
	}

	tranfiles := ""
	for _, file := range inst.files {
		tranfiles = fmt.Sprintf("%s\n${S2EGET} \"%s\"", tranfiles, file)
	}

	new_content := strings.Replace(string(data[:]), "{{TARGET}}", strings.Join(args, " "), 1)
	new_content2 := []byte(strings.Replace(new_content, "{{GETFILE}}", tranfiles, 1))
	if err := osutil.WriteFile(bootstrap, new_content2); err != nil {
		return nil, nil, fmt.Errorf("failed to create bootstrap file: %v", err)
	}

	cmd := osutil.Command(s2ebin)
	cmd.Dir = inst.workdir
	cmd.Stdout = inst.wpipe
	cmd.Stderr = inst.wpipe
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		inst.wpipe.Close()
		return nil, nil, err
	}
	inst.wpipe.Close()
	inst.wpipe = nil
	inst.s2e = cmd
	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		// retry:
		select {
		case <-time.After(timeout):
			signal(vmimpl.ErrTimeout)
		case <-stop:
			signal(vmimpl.ErrTimeout)
		// case <-inst.diagnose:
		// 	cmd.Process.Kill()
		// 	goto retry
		case err := <-inst.merger.Err:
			// cmd.Process.Kill()
			inst.killS2E()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		inst.killS2E()
		// cmd.Process.Kill()
		// cmd.Wait()
	}()
	return inst.merger.Output, errc, nil
}

func (inst *instance) Diagnose() ([]byte, bool) {
	return nil, false
}
