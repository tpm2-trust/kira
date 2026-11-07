package vaultkey

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The vault's derivations, pinned: every keyslot of 0x14xx and 0x24xx was enrolled with exactly
// these bytes, and PepperCheck is in every slot's blob with a pepper. A change here is a change of
// every such disk's key: it needs a "what breaks" and the owner's word (AGENTS.md).
func TestVaultDerivationsKnownAnswer(t *testing.T) {
	local, remote := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	for name, c := range map[string]struct{ got, want string }{
		"Salt":               {string(Salt(remote, "luks", nil)), "22831ef1fa603fbf23e45ff1da3cf9c6ff71aaebb83987e13ed2c7b9d4789ae3"},
		"Salt with a pepper": {string(Salt(remote, "luks", []byte("pepper"))), "17c75294af9222df61201c9d8bb997283e96becefdfb380d66bd70c522652ea6"},
		"Salt, label home":   {string(Salt(remote, "home", nil)), "7ed97c93724ef8cb8a55deecdc449edd7adda7aa04d6b466c87a3e98acee4bd4"},
		"Password":           {string(Password(local, "luks")), "22cf68182b58bc800f99de295e7648086d413aaf3b15e6aada1c395892a57e82"},
		"PepperCheck":        {hex.EncodeToString(PepperCheck([]byte("a key of the combiner\n"))), "2678432aa303845306a2980f9a120056"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}
}
