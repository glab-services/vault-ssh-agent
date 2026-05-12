package kwp

import (
	"encoding/hex"
	"testing"
)

// Test vectors from RFC 5649 section 6 (AES Key Wrap with Padding).
func TestWrap_RFC5649Vectors(t *testing.T) {
	t.Parallel()

	type vec struct {
		kekHex string
		ptHex  string
		ctHex  string
	}

	vectors := []vec{
		{
			kekHex: "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
			ptHex:  "c37b7e6492584340bed12207808941155068f738",
			ctHex:  "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
		},
		{
			kekHex: "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
			ptHex:  "466f7250617369",
			ctHex:  "afbeb0f07dfbf5419200f2ccb50bb24f",
		},
	}

	for _, v := range vectors {
		kek, _ := hex.DecodeString(v.kekHex)
		pt, _ := hex.DecodeString(v.ptHex)
		want, _ := hex.DecodeString(v.ctHex)

		got, err := Wrap(kek, pt)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Fatalf("ciphertext mismatch\nwant %x\ngot  %x", want, got)
		}
	}
}
