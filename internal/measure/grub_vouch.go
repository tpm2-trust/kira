package measure

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Which files of a kernel the running system vouches for. The prediction
// takes a kernel other than the booted one (grub_predict.go) from /boot,
// which on Debian is not encrypted: whoever has the disk can put a kernel
// and an initrd there, under a name the version sort puts first. A file of
// such a kernel goes into the prediction only when what is on the
// encrypted root file system says this system installed those bytes:
//
//	the kernel hook's record  kernelRecordDir/vmlinuz-<version>     the image /etc/kernel/postinst.d/zzz-kira was given
//	the initramfs record      kernelRecordDir/initrd.img-<version>  the initrd update-initramfs wrote (post-update.d/kira)
//	dpkg's record             dpkgInfoDir/<package>.md5sums          a file a package installed, at this path
//
// A record holds the SHA-256 in hex; it goes with its kernel (postrm.d). A
// file whose bytes match none, one put on /boot or changed there offline,
// leaves its kernel out of the prediction.

// kernelRecordDir is where the hooks record what they installed. A
// variable so the tests can point it elsewhere.
var kernelRecordDir = "/var/lib/kira/kernels"

// dpkgInfoDir is dpkg's database. A variable so the tests can point it
// elsewhere.
var dpkgInfoDir = "/var/lib/dpkg/info"

// vouchedFile reads a file of kernel version once, for the SHA-256 the
// prediction uses and the MD5 dpkg records: its digest, whether it is
// there, and whether a record vouches for it.
func vouchedFile(version, path string) ([]byte, bool, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, false
	}
	defer f.Close()
	sum, md := sha256.New(), md5.New()
	if _, err := io.Copy(io.MultiWriter(sum, md), f); err != nil {
		return nil, false, false
	}
	d := sum.Sum(nil)
	return d, true, hookRecorded(version, d) || dpkgRecorded(path, md.Sum(nil))
}

// hookRecorded is whether a hook recorded digest as the image or the initrd
// of version. A version that could name another place has no record.
func hookRecorded(version string, digest []byte) bool {
	if version == "" || strings.HasPrefix(version, ".") || strings.ContainsAny(version, "/\x00") {
		return false
	}
	for _, name := range []string{"vmlinuz-" + version, "initrd.img-" + version} {
		b, err := os.ReadFile(filepath.Join(kernelRecordDir, name))
		if err != nil {
			continue
		}
		if rec, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && bytes.Equal(rec, digest) {
			return true
		}
	}
	return false
}

// dpkgRecorded is whether a package installed the file at path with these
// bytes: a line "<md5>  <path without the leading slash>" in one of dpkg's
// md5sums lists. MD5 is what dpkg keeps; a match is a second preimage of a
// packaged file, which MD5 still resists.
func dpkgRecorded(path string, md5sum []byte) bool {
	line := hex.EncodeToString(md5sum) + "  " + strings.TrimPrefix(filepath.Clean(path), "/")
	lists, _ := filepath.Glob(filepath.Join(dpkgInfoDir, "*.md5sums"))
	for _, list := range lists {
		b, err := os.ReadFile(list)
		if err != nil || !bytes.Contains(b, []byte(line)) {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l == line {
				return true
			}
		}
	}
	return false
}
