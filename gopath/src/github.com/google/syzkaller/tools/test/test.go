package main

import (
	"flag"
	"path/filepath"
	"runtime"
	_ "strings"

	"github.com/google/syzkaller/pkg/db"
	_ "github.com/google/syzkaller/pkg/ifuzz/generated"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func main() {
	var (
		flagOS   = flag.String("os", runtime.GOOS, "target OS")
		flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	)
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// log.Logf(0, "%d", prog.DirOut)
	// for _, sys := range target.Syscalls {
	// 	// if sys.Name == "getsockopt$inet6_IPV6_XFRM_POLICY" {
	// 	if strings.HasPrefix(sys.Name, "recvmsg") {
	// 		log.Logf(0, "%s %v", sys.Name, isAllowed(sys))
	// 	}
	// }
	corpusDB, err := db.Open(filepath.Join("workdir", "corpus.db"))
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}
	for _, rec := range corpusDB.Records {
		item, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			log.Logf(0, "deleting broken program: %v\n%s", err, rec.Val)
			continue
		}
		mutattion(item)
	}
}

func mutattion(p *prog.Prog) {
	item := p.Clone()
	for _, c := range item.Calls {
		prog.ForeachArg(c, func(arg prog.Arg, _ *prog.ArgCtx) {
			log.Logf(0, "%v %T %v\n", arg, arg, arg.Type())
			switch typ := arg.Type().(type) {
			case *prog.StructType:
				return
				// These special structs are mutated as a whole.
			case *prog.UnionType:
				return
			case *prog.ArrayType:
				// Don't mutate fixed-size arrays.
				if typ.Kind == prog.ArrayRangeLen && typ.RangeBegin == typ.RangeEnd {
					return
				}
			case *prog.CsumType:
				return // Checksum is updated when the checksummed data changes.
			case *prog.ConstType:
				return // Well, this is const.
			case *prog.BufferType:
				if typ.Kind == prog.BufferString && len(typ.Values) == 1 {
					return // string const
				}
			case *prog.PtrType:
				if arg.(*prog.PointerArg).IsSpecial() {
					// TODO: we ought to mutate this, but we don't have code for this yet.
					return
				}
				return
			// Do not mutate the following types
			case *prog.ResourceType:
				return
			case *prog.FlagsType:
				return
			case *prog.LenType:
				return
			}
			typ := arg.Type()
			if typ == nil || typ.Dir() == prog.DirOut || !typ.Varlen() && typ.Size() == 0 {
				return
			}
			log.Logf(0, "saved: %v %T %v\n", arg, arg, arg.Type())
		})
		break
	}
}

func isAllowedType(typ prog.Type, depth int) bool {
	if typ.Dir() == prog.DirOut || typ.Dir() == prog.DirInOut {
		return false
	}

	if depth > 4 {
		return false
	}

	// log.Logf(0, "%T %v %d", typ, typ, typ.Dir())
	switch a := typ.(type) {
	case *prog.PtrType:
		return isAllowedType(a.Type, depth+1)
	case *prog.StructType:
		for _, subtyp := range a.Fields {
			if !isAllowedType(subtyp, depth+1) {
				return false
			}
		}
		return true
	case *prog.UnionType:
		for _, subtyp := range a.Fields {
			if !isAllowedType(subtyp, depth+1) {
				return false
			}
		}
		return true
	case *prog.ArrayType:
		return isAllowedType(a.Type, depth+1)
	}
	return true
}

func isAllowed(meta *prog.Syscall) bool {
	for _, typ := range meta.Args {
		if !isAllowedType(typ, 0) {
			return false
		}
	}
	return true
}
