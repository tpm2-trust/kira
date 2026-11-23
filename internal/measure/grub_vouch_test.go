package measure

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// records points the records and dpkg's database at the test's own.
func records(t *testing.T) (recordDir, infoDir string) {
	t.Helper()
	oldRecords, oldInfo := kernelRecordDir, dpkgInfoDir
	t.Cleanup(func() { kernelRecordDir, dpkgInfoDir = oldRecords, oldInfo })
	kernelRecordDir = filepath.Join(t.TempDir(), "kernels")
	dpkgInfoDir = t.TempDir()
	return kernelRecordDir, dpkgInfoDir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// A file is vouched for by the hooks' record of its version or by dpkg's of
// its path, with the bytes it has now; the digest is always of those bytes.
func TestVouchedFile(t *testing.T) {
	recordDir, infoDir := records(t)
	boot := t.TempDir()
	image, initrd := filepath.Join(boot, "vmlinuz-6.1"), filepath.Join(boot, "initrd.img-6.1")
	writeFile(t, image, "the kernel")
	writeFile(t, initrd, "the initrd")
	check := func(what, version, path string, found, vouched bool) {
		t.Helper()
		d, f, v := vouchedFile(version, path)
		if f != found || v != vouched {
			t.Errorf("%s: found %v vouched %v, want %v %v", what, f, v, found, vouched)
		}
		if b, err := os.ReadFile(path); err == nil && hex.EncodeToString(d) != sha256Hex(string(b)) {
			t.Errorf("%s: the digest is not the file's", what)
		}
	}
	check("no record", "6.1", image, true, false)
	check("not there", "6.1", filepath.Join(boot, "vmlinuz-6.2"), false, false)

	writeFile(t, filepath.Join(recordDir, "vmlinuz-6.1"), sha256Hex("the kernel")+"\n")
	writeFile(t, filepath.Join(recordDir, "initrd.img-6.1"), sha256Hex("the initrd")+"\n")
	check("the kernel hook's record", "6.1", image, true, true)
	check("the initramfs record", "6.1", initrd, true, true)
	// The same bytes under a version nothing installed: no record of it.
	copied := filepath.Join(boot, "vmlinuz-99.0")
	writeFile(t, copied, "the kernel")
	check("a copy under another version", "99.0", copied, true, false)
	// Changed on /boot after it was recorded.
	writeFile(t, initrd, "another initrd")
	check("an initrd changed", "6.1", initrd, true, false)
	for _, v := range []string{"", ".", "..", "../kernels/6.1", ".6.1"} {
		check("version "+v, v, image, true, false)
	}

	// dpkg's record: the package's file at its path, by MD5.
	md := md5.Sum([]byte("the kernel"))
	rel := strings.TrimPrefix(image, "/")
	writeFile(t, filepath.Join(infoDir, "linux-image-6.1.md5sums"), "0123456789abcdef0123456789abcdef  usr/share/doc/x\n"+hex.EncodeToString(md[:])+"  "+rel+"\n")
	os.Remove(filepath.Join(recordDir, "vmlinuz-6.1"))
	check("dpkg's record", "6.1", image, true, true)
	check("dpkg's record of another path", "99.0", copied, true, false)
	writeFile(t, image, "another kernel")
	check("a packaged file changed", "6.1", image, true, false)
}

// The hooks' records are what the prediction reads: an initrd update-initramfs
// wrote and an image a kernel install was given are vouched for, in a directory
// only root opens; a file changed afterwards is not; a removal takes both
// records. A version that could name another place records nothing, and no case
// fails the package's install.
func TestHooksRecordWhatTheyInstall(t *testing.T) {
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Skip("no sha256sum: ", err)
	}
	recordDir, _ := records(t)
	dir := t.TempDir()
	// A kira that is installed and set up nowhere: each hook records, then stops.
	bin := filepath.Join(dir, "bin")
	writeFile(t, filepath.Join(bin, "kira"), "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(filepath.Join(bin, "kira"), 0o755); err != nil {
		t.Fatal(err)
	}
	hook := func(src, place string) string {
		b, err := os.ReadFile(filepath.Join("../../initramfs/initramfs-tools", src))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ReplaceAll(string(b), "/etc/kira/keys", filepath.Join(dir, "no-keys"))
		text = strings.ReplaceAll(text, "/var/lib/kira/kernels", recordDir)
		if strings.Contains(text, "/var/lib/kira") {
			t.Fatalf("%s names a place of kira's the test does not replace", src)
		}
		path := filepath.Join(dir, place)
		writeFile(t, path, text)
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	postUpdate := hook("post-update.d/kira", "post-update.d/kira")
	postinst := hook("kernel/zzz-kira", "postinst.d/zzz-kira")
	postrm := hook("kernel/zzz-kira", "postrm.d/zzz-kira")
	run := func(script string, args ...string) {
		t.Helper()
		cmd := exec.Command(script, args...)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", script, args, err, out)
		}
	}
	boot := filepath.Join(dir, "boot")
	image, initrd := filepath.Join(boot, "vmlinuz-6.1+deb13"), filepath.Join(boot, "initrd.img-6.1+deb13")
	writeFile(t, image, "the kernel")
	writeFile(t, initrd, "the initrd")

	run(postUpdate, "6.1+deb13", initrd)
	run(postinst, "6.1+deb13", image)
	if fi, err := os.Stat(recordDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the records' directory: %v %v", fi, err)
	}
	for _, path := range []string{image, initrd} {
		if _, found, vouched := vouchedFile("6.1+deb13", path); !found || !vouched {
			t.Errorf("%s is not vouched for", path)
		}
	}
	writeFile(t, initrd, "another initrd")
	if _, _, vouched := vouchedFile("6.1+deb13", initrd); vouched {
		t.Error("an initrd changed after the hook is vouched for")
	}

	// Nothing to record: no record, and the install goes on.
	run(postUpdate, "6.2", filepath.Join(boot, "absent"))
	run(postinst, "6.2", filepath.Join(boot, "absent"))
	for _, v := range []string{"", ".x", "../x", "a/b"} {
		run(postUpdate, v, initrd)
		run(postinst, v, image)
	}
	entries, err := os.ReadDir(recordDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != "initrd.img-6.1+deb13 vmlinuz-6.1+deb13" {
		t.Errorf("records: %v", names)
	}

	// The kernel removed: both records go, nothing else.
	writeFile(t, filepath.Join(recordDir, "vmlinuz-6.3"), sha256Hex("x")+"\n")
	run(postrm, "6.1+deb13", image)
	if _, _, vouched := vouchedFile("6.1+deb13", image); vouched {
		t.Error("a removed kernel is vouched for")
	}
	if entries, _ := os.ReadDir(recordDir); len(entries) != 1 || entries[0].Name() != "vmlinuz-6.3" {
		t.Errorf("after the removal: %v", entries)
	}
}
