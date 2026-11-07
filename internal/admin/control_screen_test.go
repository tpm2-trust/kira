package admin

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tpm2-trust/go-tui-slim/panel"
	"github.com/tpm2-trust/go-tui-slim/tui"
	"golang.org/x/sys/unix"
)

// sealedMachine is wired() with the key and the standard pair of slots.
func sealedMachine() *controller {
	c := wired()
	c.facts.Keys = "local key files"
	c.facts.Status.Slots = []StatusSlot{{Slot: 0, PCRs: "0e,2e,7e,11u", Signed: true, TOTP: true}, {Slot: 1, PCRs: "0e,7e", Fallback: true, Signed: true, TOTP: true}}
	c.o.HelpTopics = []string{"control", "luks"}
	return c
}

func frameText(rows []string) string { return tui.StripSGR(strings.Join(rows, "\n")) }

// The frame of kira's model at the sizes a person meets: every row exactly as
// wide as the terminal, as many rows as it has; the overview's facts beside the
// sections when there is room; a slot's detail; ASCII where the locale is not UTF-8;
// the screen up while the facts come.
func TestControlFrame(t *testing.T) {
	c := sealedMachine()
	m := c.panelSections(c.model())
	g := tui.GlyphsFor(true)
	v := panel.View{Header: "[ KIRA ] control test · host"}
	for _, size := range [][2]int{{80, 25}, {132, 43}, {40, 24}, {30, 12}} {
		st := &panel.State{}
		rows := st.Frame(m, v, size[0], size[1], g)
		if len(rows) != size[1] {
			t.Errorf("%dx%d: %d rows", size[0], size[1], len(rows))
		}
		text := frameText(rows)
		if !strings.Contains(text, "Overview") || !strings.Contains(text, "[ KIRA ] control") {
			t.Errorf("%dx%d:\n%s", size[0], size[1], text)
		}
		wide := size[0] >= 72
		if wide != strings.Contains(text, "What this machine has") {
			t.Errorf("%dx%d: the overview's facts beside the sections: %v\n%s", size[0], size[1], wide, text)
		}
	}
	// A step's detail: what it does, its state, the command, what a destroy removes.
	st := &panel.State{Section: sectionIndex("keys"), Focus: panel.Steps, Step: 1}
	text := frameText(st.Frame(m, panel.View{Header: "h"}, 100, 40, g))
	for _, want := range []string{"Slot 0", "Done: sealed to 0e,2e,7e,11u", "Destroys: slot 0 whole", "The command: kira slot delete --nvram 0", "⚠"} {
		if !strings.Contains(text, want) {
			t.Errorf("the slot's detail lacks %q:\n%s", want, text)
		}
	}
	text = frameText(st.Frame(m, panel.View{Header: "h"}, 100, 40, tui.GlyphsFor(false)))
	if strings.ContainsAny(text, "✓⚠│─") {
		t.Errorf("Unicode in an ASCII frame:\n%s", text)
	}
	// The boot chain's intro carries the prerequisites.
	text = frameText((&panel.State{Section: sectionIndex("chain")}).Frame(m, panel.View{Header: "h"}, 100, 40, g))
	if !strings.Contains(text, "Prerequisites") {
		t.Errorf("the boot chain:\n%s", text)
	}
}

func sectionIndex(key string) int {
	for i, s := range controlSections {
		if s.key == key {
			return i
		}
	}
	return -1
}

// kira's steps on the panel's keys: a destroying slot runs (its question asks for
// the word), a blocked step says why instead of running, an overview line opens its
// section, search finds a step anywhere; the step run is the model's.
func TestControlScreenKeys(t *testing.T) {
	c := sealedMachine()
	steps := c.model()
	m := c.panelSections(steps)
	st := &panel.State{}
	key := func(names ...string) panel.Cmd {
		var cmd panel.Cmd
		for _, n := range names {
			k := tui.Key{Name: n}
			if len(n) == 1 {
				k = tui.Key{Name: tui.KeyRune, Rune: rune(n[0])}
			}
			cmd = st.Key(k, m, 10)
		}
		return cmd
	}
	key(tui.KeyDown, tui.KeyDown)
	if st.Section != sectionIndex("keys") || st.Focus != panel.Sections {
		t.Fatalf("down twice: %+v", st)
	}
	// keys: setup, slot 0, ...
	if cmd := key(tui.KeyEnter, tui.KeyDown, tui.KeyEnter); cmd != panel.RunStep || steps[st.Section][st.Step].Key != "slot:0" {
		t.Fatalf("Enter on slot 0: %v %+v", cmd, st)
	}
	st = &panel.State{Section: sectionIndex("phone"), Focus: panel.Steps}
	if cmd := key(tui.KeyEnter); cmd != panel.None || !strings.Contains(st.Message, "no Bluetooth adapter") {
		t.Fatalf("a blocked step ran: %v %q", cmd, st.Message)
	}
	st = &panel.State{Section: sectionIndex("overview"), Focus: panel.Steps}
	for i, s := range steps[st.Section] {
		if s.Key == "menu:keys" {
			st.Step = i
		}
	}
	if key(tui.KeyEnter); st.Section != sectionIndex("keys") {
		t.Fatalf("an overview line opens its section: %+v", st)
	}
	st = &panel.State{}
	key("/", "a", "p", "p", "r", "o", "v", "e", tui.KeyEnter)
	if st.Selected(m) == nil || steps[st.Section][st.Step].Key != "approve" || st.Focus != panel.Steps {
		t.Fatalf("search: %+v", st)
	}
	if !strings.Contains(screenHelp, "Ctrl-L") {
		t.Fatal("the keys' help")
	}
}

// openTestPty is a pseudo-terminal of the size given: its master and its slave.
func openTestPty(t *testing.T, cols, rows int) (ptm, pts *os.File) {
	t.Helper()
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ptm.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(int(ptm.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	pts, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.IoctlSetWinsize(int(ptm.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(cols), Row: uint16(rows)})
	t.Cleanup(func() { ptm.Close(); pts.Close() })
	return ptm, pts
}

// The full screen on a pseudo-terminal: up at once while the facts come, the slow
// ones after; keys move it; a step runs below it and the screen comes back; q leaves
// and the terminal is as it was.
func TestControlScreenOnAPty(t *testing.T) {
	ptm, pts := openTestPty(t, 100, 30)
	before, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	var mu sync.Mutex
	var seen bytes.Buffer
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := ptm.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			seen.Write(b[:n])
			mu.Unlock()
		}
	}()
	text := func() string {
		mu.Lock()
		defer mu.Unlock()
		return tui.StripSGR(seen.String())
	}
	waitFor := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(text(), want); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the screen never showed %q:\n%q", want, text())
			}
		}
	}
	slowDone := make(chan struct{})
	c := sealedMachine()
	facts := c.facts
	c.in, c.out = pts, pts
	c.p = newPrompter(pts, pts)
	c.fast = func(string, bool) machineFacts { f := facts; f.Checking = true; return f }
	c.slow = func(f *machineFacts) {
		<-slowDone
		f.Checking = false
	}
	ran := make(chan string, 1)
	defer func(old func(string, []string) error) { runSelf = old }(runSelf)
	runSelf = func(_ string, args []string) error { ran <- strings.Join(args, " "); return nil }

	done := make(chan error, 1)
	go func() { done <- c.screenLoop() }()
	waitFor("Overview")
	waitFor("checking ...")
	close(slowDone)
	// To Tools, into it, run the first view (status), back with Enter.
	ptm.Write([]byte("\033[B\033[B\033[B\033[B\033[B\033[B\033[B")) // the 8th section: Tools
	ptm.Write([]byte("\r"))
	waitFor("Status")
	ptm.Write([]byte("\r"))
	select {
	case got := <-ran:
		if got != "status" {
			t.Fatalf("ran %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the view did not run:\n%q", text())
	}
	waitFor("Back to control")
	ptm.Write([]byte("\r"))
	waitFor("1049h") // the screen is back
	ptm.Write([]byte("q"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("q did not leave:\n%q", text())
	}
	after, _ := unix.IoctlGetTermios(int(pts.Fd()), unix.TCGETS)
	if after.Lflag != before.Lflag || !strings.Contains(seen.String(), "\033[?1049l") || !strings.Contains(seen.String(), "\033[?25h") {
		t.Fatalf("the terminal is not as it was: %x/%x", after.Lflag, before.Lflag)
	}
}
