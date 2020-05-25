// Inspired by https://github.com/erszcz/callgraph

// The callgraph tool generates call graphs by tracing executables using GDB.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kr/pretty"
	"github.com/pkg/errors"
)

func main() {
	// Parse command line arguments.
	var (
		// Output path.
		output string
	)
	flag.StringVar(&output, "o", "", "output path")
	flag.Parse()
	// Generate call graph by capturing trace of stack frames while debugging in
	// GDB.
	for _, binPath := range flag.Args() {
		if err := genCallGraph(binPath, output); err != nil {
			log.Fatalf("%+v", err)
		}
	}
}

// genCallGraph generates a call graph by tracing the given binary exectuable.
// The output is stored to the specified output path in Graphviz DOT format.
func genCallGraph(binPath, output string) error {
	fns, err := getFuncs(binPath)
	if err != nil {
		return errors.WithStack(err)
	}
	edges, err := trace(binPath, fns)
	if err != nil {
		return errors.WithStack(err)
	}
	var w io.Writer
	w = os.Stdout
	if len(output) > 0 {
		f, err := os.Create(output)
		if err != nil {
			return errors.WithStack(err)
		}
		defer f.Close()
		w = f
	}
	buf := callGraphString(w, edges)
	if _, err := fmt.Fprintln(w, buf); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// callGraphString returns a string representation of the given call graph in
// Graphviz DOT format.
func callGraphString(w io.Writer, edges []Edge) string {
	buf := &bytes.Buffer{}
	buf.WriteString("digraph {\n")
	zero := StackFrame{}
	for _, edge := range edges {
		if edge.Src == zero {
			// Caller information missing.
			fmt.Fprintf(buf, "\t%q\n", edge.Dst.FuncName)
			continue
		}
		if len(edge.Dst.Args) > 0 {
			args := "(" + edge.Dst.Args + ")"
			fmt.Fprintf(buf, "\t%q -> %q [label=%q]\n", edge.Src.FuncName, edge.Dst.FuncName, args)
		} else {
			fmt.Fprintf(buf, "\t%q -> %q\n", edge.Src.FuncName, edge.Dst.FuncName)
		}
	}
	buf.WriteString("}")
	return buf.String()
}

// Edge in call graph.
type Edge struct {
	// Caller function.
	Src StackFrame
	// Callee function.
	Dst StackFrame
	// Source code of callee source line.
	SrcLine string
}

// trace traces the call graph of the specified functions in the given binary
// and returns the edges of the call graph.
func trace(binPath string, fns []Func) ([]Edge, error) {
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}
	errbuf := &bytes.Buffer{}
	fmt.Fprintf(input, "set width 0\n")
	fmt.Fprintf(input, "set height 0\n")
	fmt.Fprintf(input, "set verbose off\n")
	// Add breakpoints.
	for _, fn := range fns {
		fmt.Fprintf(input, "break %s:%d\n", fn.File, fn.Line)
	}
	// Hook backtrace command for each breakpoint.
	for i := range fns {
		breakNr := i + 1
		fmt.Fprintf(input, "commands %d\n", breakNr)
		//fmt.Fprintf(input, "info args\n")
		fmt.Fprintf(input, "backtrace 2\n")
		fmt.Fprintf(input, "continue\n")
		fmt.Fprintf(input, "end\n")
	}
	fmt.Fprintf(input, "run\n")
	// Run GDB.
	cmd := exec.Command("gdb", "-q", binPath)
	cmd.Stdin = input
	cmd.Stdout = output
	cmd.Stderr = errbuf
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "GDB error: %v", errbuf)
	}
	edges, err := parseEdges(output.String(), fns)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return edges, nil
}

// parseEdges parses call graph edges in the given GDB output.
//
// Example GDB output:
//
//    Breakpoint 1, main (argc=1, argv=0x7fffffffe6a8) at test.c:11
//    11      foo(23);
//    #0  main (argc=1, argv=0x7fffffffe6a8) at test.c:11
//
//    Breakpoint 2, foo (n=23) at test.c:19
//    19      bar(n);
//    #0  foo (n=23) at test.c:19
//    #1  0x0000555555555152 in main (argc=1, argv=0x7fffffffe6a8) at test.c:11
//
//    Breakpoint 3, bar (n=23) at test.c:25
//    25      baz(n);
//    #0  bar (n=23) at test.c:25
//    #1  0x0000555555555171 in foo (n=23) at test.c:19
//
//    Breakpoint 4, baz (n=23) at test.c:31
//    31      return;
//    #0  baz (n=23) at test.c:31
//    #1  0x0000555555555189 in bar (n=23) at test.c:25
func parseEdges(s string, fns []Func) ([]Edge, error) {
	const breakpointPrefix = "\nBreakpoint "
	bps := strings.Split(s, breakpointPrefix)
	bps = bps[1:] // skip preamble output e.g. "Reading symbols from ./test"
	var edges []Edge
	for _, bp := range bps {
		lines := strings.Split(bp, "\n")
		// Source code of callee source line.
		srcLine := lines[1]
		var sts []StackFrame
		for _, line := range lines {
			if !strings.HasPrefix(line, "#") {
				continue
			}
			st, err := parseStrackTrace(line)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			sts = append(sts, st)
		}
		edge := Edge{}
		switch len(sts) {
		case 0:
			log.Printf("unable to determine caller/callee of stack frame %q", bp)
			continue
		case 1:
			edge.Dst = sts[0]
		case 2:
			edge.Dst = sts[0]
			edge.Src = sts[1]
		default: // > 2
			for i := 0; i < len(sts); i++ {
				dst := sts[i]
				if dst.StackFrameNum != 0 {
					log.Printf("invalid stack frame number; expected #0, got #%d", dst.StackFrameNum)
					break
				}
				edge := Edge{
					Dst: dst,
				}
				if i+1 < len(sts) {
					src := sts[i+1]
					if src.StackFrameNum != 0 {
						edge.Src = src
						i++
					}
				}
				// TODO: handle srcLine?
				edges = append(edges, edge)
			}
			continue
		}
		// Source code of callee source line.
		//
		// Example:
		//
		//    25      baz(n);
		lineNumPrefix := strconv.Itoa(edge.Dst.LineNum)
		if strings.HasPrefix(srcLine, lineNumPrefix) {
			edge.SrcLine = srcLine
		}
		pretty.Logln("edge:", edge)
		edges = append(edges, edge)
	}
	return edges, nil
}

// StackFrame records information about a stack frame line.
type StackFrame struct {
	// Stack frame number (e.g. #0).
	StackFrameNum int
	// Function name. Callee if (#0), otherwise caller.
	FuncName string
	// Function arguments.
	Args string
	// Source file name at function call site.
	SrcFile string
	// Line number at function call site.
	LineNum int
}

// parseStrackTrace parses the given stack frame line.
//
// Example stack frame lines:
//
//    "#0  foo (n=23) at test.c:19"
//    "#1  0x0000555555555171 in foo (n=23) at test.c:19"
//    "#1  0x56598d16 in CCritSect::CCritSect (this=0x5686a728 <sgMemCrit>) at ./src/storm.h:2079"
//    "#1  0x5655c988 in _GLOBAL__sub_I_mainmenu.cpp ()"
//    "#1  0x5655d176 in myDebugBreak () at src/appfat.cpp:87"
func parseStrackTrace(line string) (StackFrame, error) {
	re1 := regexp.MustCompile(`#([0-9]+)[ \t]+(0x[0-9A-Fa-f]+ in )?([^ ]+) [(]([^)]*)[)]( at ([^:]+):([0-9]+))?`)
	if matches := re1.FindStringSubmatch(line); len(matches) > 0 {
		// ["#0  foo (n=23) at test.c:19" "0" "" "foo" "n=23" " at test.c:19" "test.c" "19"]
		// ["#1  0x0000555555555171 in foo (n=23) at test.c:19" "1" "0x0000555555555171 in " "foo" "n=23" " at test.c:19" "test.c" "19"]
		// ["#1  0x56598d16 in CCritSect::CCritSect (this=0x5686a728 <sgMemCrit>) at ./src/storm.h:2079" "1" "0x56598d16 in " "CCritSect::CCritSect" "this=0x5686a728 <sgMemCrit>" " at ./src/storm.h:2079" "./src/storm.h" "2079"]
		// ["#1  0x5655c988 in _GLOBAL__sub_I_mainmenu.cpp ()" "1" "0x5655c988 in " "_GLOBAL__sub_I_mainmenu.cpp" "" "" "" ""]
		rawStackFrameNum := matches[1]
		stackFrameNum, err := strconv.Atoi(rawStackFrameNum)
		if err != nil {
			return StackFrame{}, errors.WithStack(err)
		}
		st := StackFrame{
			StackFrameNum: stackFrameNum,
			FuncName:      matches[3],
			Args:          matches[4],
			SrcFile:       matches[6],
		}
		rawLineNum := matches[7]
		if len(rawLineNum) > 0 {
			lineNum, err := strconv.Atoi(rawLineNum)
			if err != nil {
				return StackFrame{}, errors.WithStack(err)
			}
			st.LineNum = lineNum
		}
		return st, nil
	}
	return StackFrame{}, errors.Errorf("unable to parse stack frame line %q", line)
}

// Func contains debug information about a function.
type Func struct {
	// Source code file path.
	File string
	// Line number in source code.
	Line int
	// Function signature.
	Sig string
}

// GDB command to retrieve debug information of function signatures.
//
// Example GDB output:
//    All defined functions:
//
//    File test.c:
//    9:    int main(int, char **);
//    23:   static void bar(int);
//    29:   static void baz(int);
//    17:   static void foo(int);
//
//    Non-debugging symbols:
//    0x0000000000001000  _init
//    0x0000000000001030  exit@plt
//    0x0000000000001040  _start
//    0x0000000000001070  deregister_tm_clones
//    0x00000000000010a0  register_tm_clones
//    0x00000000000010e0  __do_global_dtors_aux
//    0x0000000000001130  frame_dummy
//    0x00000000000011a0  __libc_csu_init
//    0x0000000000001210  __libc_csu_fini
//    0x0000000000001218  _fini
const gdbGetFuncs = `
set width 0
set height 0
set verbose off
info functions
`

// getFuncs retrieves debug information about functions of the given binary
// executable.
func getFuncs(binPath string) ([]Func, error) {
	input := &bytes.Buffer{}
	output := &bytes.Buffer{}
	errbuf := &bytes.Buffer{}
	input.WriteString(gdbGetFuncs)
	cmd := exec.Command("gdb", "-q", binPath)
	cmd.Stdin = input
	cmd.Stdout = output
	cmd.Stderr = errbuf
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "GDB error: %v", errbuf)
	}
	fns, err := parseFuncs(output.String())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return fns, nil
}

// parseFuncs parses debug information about functions of the given GDB output.
//
// Example GDB output:
//    All defined functions:
//
//    File test.c:
//    9:    int main(int, char **);
//    23:   static void bar(int);
//    29:   static void baz(int);
//    17:   static void foo(int);
//
//    Non-debugging symbols:
//    0x0000000000001000  _init
//    0x0000000000001030  exit@plt
//    0x0000000000001040  _start
//    0x0000000000001070  deregister_tm_clones
//    0x00000000000010a0  register_tm_clones
//    0x00000000000010e0  __do_global_dtors_aux
//    0x0000000000001130  frame_dummy
//    0x00000000000011a0  __libc_csu_init
//    0x0000000000001210  __libc_csu_fini
//    0x0000000000001218  _fini
func parseFuncs(s string) ([]Func, error) {
	const startPrefix = "All defined functions:"
	start := strings.Index(s, startPrefix)
	if start == -1 {
		return nil, errors.Errorf("unable to find start position of defined functions; expected %q, got %q", startPrefix, s)
	}
	s = s[start:]
	// Parse file functions.
	lines := strings.Split(s, "\n")
	// Current source code file name.
	srcFile := ""
	var fns []Func
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		// File test.c:
		if strings.HasPrefix(line, "File ") && strings.HasSuffix(line, ":") {
			srcFile = line[len("File ") : len(line)-len(":")]
			continue
		}
		if len(line) == 0 {
			srcFile = ""
			continue
		}
		if len(srcFile) == 0 {
			continue
		}
		parts := strings.Split(line, ":")
		// 9:	int main(int, char **);
		if len(parts) == 2 {
			rawLine := strings.TrimSpace(parts[0])
			sig := strings.TrimSpace(parts[1])
			line, err := strconv.Atoi(rawLine)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			fn := Func{
				File: srcFile,
				Line: line,
				Sig:  sig,
			}
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool {
		a := fns[i]
		b := fns[j]
		switch {
		case a.File < b.File:
			return true
		case a.File > b.File:
			return false
		// a.File == b.File:
		default:
			return a.Line < b.Line
		}
	})
	return fns, nil
}
