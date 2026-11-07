package attest_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	. "github.com/tpm2-trust/kira/core/attest"
)

// Golden vectors for every canonical computation. docs/PROTOCOL-BLE.md §9
// publishes the same values for implementers; if this test changes, the
// protocol changed, and the document and the label versions must change too.

func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestGoldenVectors(t *testing.T) {
	cb := seq(0x00, 32)
	nonceA, nonceV := seq(0x20, 32), seq(0x40, 32)
	nonceP, nonceM := seq(0x60, 32), seq(0x80, 32)
	sel, _ := NewPCRSelection(AlgSHA256, []int{0, 2, 4, 7})
	qd, _ := QualifyingData(nonceA, nonceV, cb, sel)
	receipt := &Receipt{
		Verdict: VerdictOK, DeviceID: seq(0xA0, 16), AKName: append([]byte{0x00, 0x0B}, seq(0xB0, 32)...),
		QD: qd, QuoteDigest: seq(0xC0, 32), PolicyID: "default",
		IssuedAt: 1790000000, ExpiresAt: 1790000300, VerifierID: "pixel-1",
	}
	anchor := bytes.Repeat([]byte{0x5A}, 91)

	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"qd", qd, "a0e99eadbcbeda0789ad2c2b80115cbd9cbaf5a01fab14e33f2233ce8160c938"},
		{"enrol_qd", EnrolQualifyingData(cb), "cf3737cc06ad638d7045d7f2800cdcb825047dec5bc4c36915df629083857037"},
		{"offline_qd", OfflineQualifyingData(seq(0xD0, 32)), "b63bbd6fe21254e8bfa45ba110430d4708c1da602807e4c0f3f6ec59e420b3b9"},
		{"sas_commit", SASCommitment(cb, nonceM), "bb38912f91a5bf22c192320df338c74c180c7c1710945917b51f0a8f3c8fa214"},
		{"receipt_tbs", ReceiptTBS(receipt), "6b6972612f726563656970742f76310110000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf22000000000bb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf20000000a0e99eadbcbeda0789ad2c2b80115cbd9cbaf5a01fab14e33f2233ce8160c93820000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf0700000064656661756c74803bb16a00000000ac3cb16a0000000007000000706978656c2d31"},
		{"enrol_accept_tbs", EnrolAcceptTBS(receipt.DeviceID, cb, receipt.AKName, anchor, "pixel-1", "default"), "6b6972612f656e726f6c2d6163636570742f763110000000a0a1a2a3a4a5a6a7a8a9aaabacadaeaf20000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f22000000000bb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf5b0000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a07000000706978656c2d310700000064656661756c74"},
		{"anchor_digest", AnchorDigest(anchor), "90321eefa2e28e447b0888ef46deb0f82b8bae182a45cf199b371f428f834543"},
		{"service_data", BuildServiceData(AdvFlagAttest, []byte{1, 2, 3, 4}, seq(0xE0, 32)), "02010203046c87bad73025a4f7"},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, h(c.want)) {
			t.Errorf("%s:\n got  %x\n want %s", c.name, c.got, c.want)
		}
	}
	if got := ShortAuthString(cb, nonceP, nonceM); got != "979216" {
		t.Errorf("sas: got %s want 979216", got)
	}
	if !MatchServiceData(h("02010203046c87bad73025a4f7"), seq(0xE0, 32)) {
		t.Error("service data does not match its own key")
	}
}
