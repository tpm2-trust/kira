package admin

// assh.conf: the settings of what aSSH does for kira's SSH server at
// boot, in aSSH's own file (github.com/tpm2-trust/assh/config), beside
// control.conf. control.conf holds what is kira's - whether the
// server runs, how long the boot waits, the image's network; assh.conf
// what is aSSH's - the SSH CA (where it is kept, its key, its slots and
// their PCRs), the port, the keys that may log in, the host
// certificate's name. control writes both: the CA's slots when it creates
// the CA, worked out from this machine (remote_hostkey.go), and the port.
// An edit of the slots is followed by the next reseal or control, which
// make the CA's slots the file's before they approve (config.Match). The
// image carries a copy, which 'run --ssh' reads; the file itself is
// trusted with nothing - the TPM checks the CA and its approvals.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/tpm2-trust/assh/config"
)

// sshConfHeader heads a new assh.conf.
const sshConfHeader = `aSSH's settings for kira's SSH server at boot (ASSH_*,
github.com/tpm2-trust/assh config): the SSH CA, its slots and their PCRs,
the port, the keys that may log in. Written by 'kira control'; an
edit of the slots takes effect at the next approval or control, which make
the CA's slots these. Whether the server runs is control.conf's.`

// sshConfPath is the assh.conf beside the control.conf at path.
func sshConfPath(controlPath string) string {
	return filepath.Join(filepath.Dir(controlPath), "assh.conf")
}

// notKiras are the keys of assh.conf that kira has no use for,
// and why.
var notKiras = map[string]string{
	"ASSH_TPM":            "the TPM is kira's --tpm",
	"ASSH_AUTHORITY":      "the CA's authority is kira's signing key",
	"ASSH_AUTHORITY_TPM":  "the CA's authority is kira's signing key",
	"ASSH_PIN_HANDLE":     "the CA's authority is kira's signing key",
	"ASSH_COUNTER_HANDLE": "the CA's authority is kira's signing key",
	"ASSH_STATE":          "slot approve approves the values the next boot will have, not a recorded state",
	"ASSH_USER":           "a login is a session of the code screen",
	"ASSH_SOCKET":         "a login is a session of the code screen",
	"ASSH_AGENT_DIR":      "kira runs no agent",
	"ASSH_AGENT_UID":      "kira runs no agent",
}

// loadSSHConf reads the assh.conf at path, beside the control.conf at
// controlPath; a missing file is kira's defaults.
func loadSSHConf(path, controlPath string) (config.Config, error) {
	c, err := config.Load(path)
	if err != nil && !os.IsNotExist(err) {
		return sshConfDefaults(config.Default(), controlPath), err
	}
	for k := range c.Set {
		if why, ok := notKiras[k]; ok {
			return sshConfDefaults(config.Default(), controlPath), fmt.Errorf("%s: %s is not kira's to set: %s. Remove the line", path, k, why)
		}
	}
	return sshConfDefaults(c, controlPath), nil
}

// sshConfDefaults gives what c leaves out kira's defaults: the CA in
// its EFI variable (DefaultSSHCA) with kira's policy ref; the keys in kira's own authorized_keys; the
// certificate named "kira boot". The slots have none: control writes
// them when it creates the CA.
func sshConfDefaults(c config.Config, controlPath string) config.Config {
	unset := func(k string) bool { return !c.Set[k] }
	if unset("ASSH_CA") {
		c.CA = sshCAPath(controlPath)
	}
	if unset("ASSH_CA_REF") {
		c.PolicyRef = sshCARef
	}
	if unset("ASSH_KEY_ID") {
		c.KeyID = "kira boot"
	}
	if unset("ASSH_AUTHORIZED_KEYS") {
		c.AuthorizedKeys = sshAuthorizedKeysPath(controlPath)
	}
	return c
}

// listenPort is the port of an ASSH_LISTEN address, 0 when it has none.
func listenPort(listen string) int {
	_, p, err := net.SplitHostPort(listen)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// writeSSHConf writes c to the assh.conf beside the control.conf at
// controlPath; the rest of the file stays.
func writeSSHConf(controlPath string, c config.Config) error {
	return config.Write(sshConfPath(controlPath), c, sshConfHeader)
}
