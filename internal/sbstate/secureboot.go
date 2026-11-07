// Package sbstate reads the firmware's Secure Boot state from its EFI
// variables and says, in one line, what is wrong with it. It needs no TPM: the
// boot's lines come from here as well. It never stops anything: kira informs,
// and has no enforced mode.
package sbstate

import (
	"github.com/tpm2-trust/go-uefi-slim/efivar"
	"github.com/tpm2-trust/kira/internal/efivars"
)

// State is what the firmware says. Known is false when either variable cannot be
// read, Why says what went wrong; the other fields then hold what could be read.
type State struct {
	Enabled   bool
	SetupMode bool
	Known     bool
	Why       string
}

// Read is the state now, from the variables under efivars.Dir (go-uefi-slim's
// efivar.SecureBootState).
func Read() State {
	st := efivar.Store{Dir: efivars.Dir}.SecureBootState()
	return State{Enabled: st.Enabled, SetupMode: st.SetupMode, Known: st.Known, Why: st.Why}
}

// Risk says in one line what is wrong with this state, without a prefix; empty
// when Secure Boot is on and out of Setup Mode.
func (s State) Risk() string {
	return efivar.SecureBootState{Enabled: s.Enabled, SetupMode: s.SetupMode, Known: s.Known, Why: s.Why}.Risk()
}

// WarningPrefix starts a Warning's line: a hook that has said it already finds it by this.
const WarningPrefix = "WARNING: Secure Boot"

// Warning is Risk as a line of a command's output; empty when there is no risk.
func (s State) Warning() string {
	if r := s.Risk(); r != "" {
		return "WARNING: " + r
	}
	return ""
}
