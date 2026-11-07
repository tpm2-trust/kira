package phonegate

import (
	"bytes"
	"testing"
)

// The phone salt's derivation, pinned: every keyslot of 0x1300, 0x1302 and of the TPM salt (0x1200,
// whose part T goes through it too) was enrolled with exactly these bytes. A change here is a
// change of every such disk's key: it needs a "what breaks" and the owner's word (AGENTS.md).
func TestFactorSaltKnownAnswer(t *testing.T) {
	f := bytes.Repeat([]byte{0xF0}, 32)
	for label, want := range map[string]string{
		"":     "d5e6805fa2eb1ada7411e9f9de5308e9523a91cb080390546ba5abdb57bdc801",
		"luks": "d5e6805fa2eb1ada7411e9f9de5308e9523a91cb080390546ba5abdb57bdc801",
		"home": "3488e6ebc6f12b325d5eb9c05c09029aa168806b37d04b5dd6a568bcd7dc2e4f",
	} {
		if got := string(FactorSalt(f, label)); got != want {
			t.Errorf("FactorSalt(F, %q) = %s, want %s", label, got, want)
		}
	}
	// docs/PROTOCOL-BLE.md §9's: F = f0 ... ff.
	doc := make([]byte, 16)
	for i := range doc {
		doc[i] = 0xF0 + byte(i)
	}
	if got := string(FactorSalt(doc, "luks")); got != "e2803855c3bb181b969d772739394ebe5abcad11f59611056de17a3a89b77b9a" {
		t.Errorf("FactorSalt of the protocol's vector = %s", got)
	}
}
