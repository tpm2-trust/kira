package admin

import (
	"fmt"
	"os"

	"github.com/tpm2-trust/go-tui-slim/panel"
	"github.com/tpm2-trust/go-tui-slim/tui"
	"github.com/tpm2-trust/tpm2-kira/internal/nvslot"
)

// control's full screen is go-tui-slim's panel: the sections on the left, the selected
// section's steps and the selected step's detail on the right, the keys at the bottom.
// It draws the same model as the line menus (control_model.go). A step runs in the
// terminal as the line menus run it: the screen is given back for it, its questions are
// prompt's, and the screen comes back when it is read. The facts come in the
// background: the screen is up at once.

// controlPanel is the controller as the panel's Source.
type controlPanel struct {
	c     *controller
	steps [][]controlStep // the last model drawn: what Run runs
}

// controlModel is every section's steps.
func (c *controller) model() [][]controlStep {
	m := make([][]controlStep, len(controlSections))
	for i, sec := range controlSections {
		m[i] = c.annotated(c.sectionSteps(sec.key))
	}
	return m
}

// panelStep is a step as the panel draws it.
func panelStep(s controlStep) panel.Step {
	p := panel.Step{Title: s.Title, Done: s.Done, Blocked: s.Blocked, Dirty: s.Dirty, Explain: s.Explain,
		Command: s.Command, Destroys: s.Destroys, Danger: s.Danger, Check: s.Check, Runnable: s.Run != nil}
	if s.Menu != "" {
		p.Jump = sectionOf(s.Menu)
	}
	return p
}

// panelSections are the sections with their steps, and their intros with, for the
// overview and the boot chain, the machine's facts.
func (c *controller) panelSections(m [][]controlStep) []panel.Section {
	out := make([]panel.Section, len(controlSections))
	for i, sec := range controlSections {
		out[i] = panel.Section{Key: sec.key, Title: sec.title, Intro: sec.intro}
		if m == nil {
			continue
		}
		switch sec.key {
		case "overview":
			status := c.factsText()
			if notes := c.facts.Status.Notes; len(notes) > 0 {
				status += "\n" + heading("Notes")
				for _, n := range notes {
					status += "\n- " + n
				}
			}
			out[i].Intro += "\n\n" + heading("What this machine has") + "\n" + status
		case "chain":
			out[i].Intro += "\n\n" + heading("Prerequisites") + "\n" + c.prereqText()
		}
		for _, s := range m[i] {
			out[i].Steps = append(out[i].Steps, panelStep(s))
		}
	}
	return out
}

func (p *controlPanel) Header(loading bool) string { return p.c.screenHeader(loading) }
func (p *controlPanel) Checking() bool             { return p.c.facts.Checking }

func (p *controlPanel) Sections(loading bool) []panel.Section {
	if loading {
		return p.c.panelSections(nil)
	}
	p.steps = p.c.model()
	return p.c.panelSections(p.steps)
}

// Collect is the facts: the fast ones first, the slow ones after.
func (p *controlPanel) Collect() <-chan func() {
	got := make(chan func(), 2)
	go func() {
		defer close(got)
		f := p.c.fastFacts()
		fast := f
		got <- func() { p.c.facts = fast }
		p.c.slowFacts(&f)
		got <- func() { p.c.facts = f }
	}()
	return got
}

func (p *controlPanel) Run(section, step int) { p.c.runStep(p.steps[section][step]) }

// screenHelp is the keys, on '?'.
const screenHelp = `Keys

  Up, Down, j, k     move in the sections, or in a section's steps
  Right, Tab, l      from the sections into the steps
  Left, h, Esc       back to the sections
  Enter              open a section; run a step (a blocked one says why)
  PgUp, PgDn         scroll the detail
  /                  search every step of every section
  r                  look at the machine again
  Ctrl-L             draw the screen again
  ?                  this help, again to close it
  q, Esc, Ctrl-C     leave: the boot image is built then, when it is out of date

A step that changes the machine runs in the terminal below the screen, asks what it
needs, and comes back here. One that destroys (marked) asks for its word: the slot's
or keyslot's number, or "delete".`

// fullScreen says whether control draws its full screen: a terminal with a size, not
// dumb, not --lines, not --debug (whose output would run through the frame).
func (c *controller) fullScreen() bool {
	if c.o.Lines || c.o.Debug || !c.tty || !tui.IsTerminal(os.Stdout) || os.Getenv("TERM") == "dumb" {
		return false
	}
	cols, rows, ok := tui.Open(c.input(), c.out).Size()
	return ok && cols >= 40 && rows >= 12
}

// header is the full screen's top row: the version, the host, Secure Boot, the image.
func (c *controller) screenHeader(loading bool) string {
	v := nvslot.AppVersion
	if v == "" {
		v = "unknown"
	}
	host, _ := os.Hostname()
	h := fmt.Sprintf("[ \033[1;33mKIRA\033[0m ] control %s · %s", v, host)
	if loading {
		return h
	}
	f := &c.facts
	switch {
	case !f.SecureBoot.Known:
		h += " · " + bad("Secure Boot unknown")
	case f.SecureBoot.SetupMode:
		h += " · " + bad("Secure Boot: Setup Mode")
	case f.SecureBoot.Enabled:
		h += " · " + good("Secure Boot on")
	default:
		h += " · " + bad("Secure Boot off")
	}
	if n := len(f.Pending); n > 0 {
		h += " · " + amber(fmt.Sprintf("image out of date (%d)", n))
	}
	return h
}

// screenLoop is control on its full screen, until it is left; then the image is built
// when it is out of date (leave).
func (c *controller) screenLoop() error {
	cfg := panel.Config{In: c.input(), Help: screenHelp, Loading: "Looking at this machine ...", Again: "Looking at this machine again ..."}
	if c.in != nil { // the tests' terminal: drawn on it, not on a hushed stdout
		cfg.Out = c.in
	}
	if err := panel.Run(&controlPanel{c: c}, cfg); err != nil {
		return err
	}
	c.leave()
	return nil
}

// runStep runs a step in the terminal, below the screen: its title, what it does, its
// questions, its result, and a key before the screen comes back.
func (c *controller) runStep(s controlStep) {
	fmt.Fprint(c.out, clearScreen)
	if s.Done != "" && !s.SelfConfirm {
		again, err := c.confirm(s.Title+" is done: "+s.Done+". Run it again?", "")
		if err != nil || !again {
			return
		}
	}
	fmt.Fprintf(c.out, "\n\033[1m%s\033[0m\n%s\n\n", s.Title, s.Explain)
	if err := s.Run(c); err != nil {
		fmt.Fprintf(c.out, "\n\033[0;31mNot done:\033[0m %v\n", err)
	}
	c.ask().Wait("Back to control", "", "OK")
}
