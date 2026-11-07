package attest_test

import (
	"bytes"
	"testing"

	. "github.com/tpm2-trust/kira/core/attest"
)

// The layout a seed stands for, pinned: the phone and the vault make it with their core, the
// machine with its own, of another version perhaps. Another permutation for the same seed would
// show one layout and take another. A change here needs a "what breaks" and the owner's word.
func TestKeyboardLayoutKnownAnswer(t *testing.T) {
	for b, want := range map[byte]string{
		0x00: "1jnq5if40badv8g9e2yrlmx63cz7puswtkoh",
		0x5a: "8i6hwla9cnrst05pdumyeq72fxzkv1jbog34",
	} {
		l, err := KeyboardLayoutOf(bytes.Repeat([]byte{b}, KeyboardSeedSize))
		if err != nil {
			t.Fatal(err)
		}
		if l.String() != want {
			t.Errorf("seed %#02x: %s, want %s", b, l, want)
		}
	}
}
