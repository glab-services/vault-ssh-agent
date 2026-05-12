package vault

import "testing"

func TestKeyEntryNormalize(t *testing.T) {
	t.Parallel()

	e := &KeyEntry{Name: "n", Enabled: true}
	changed := e.Normalize("transit")
	if !changed {
		t.Fatalf("expected changed")
	}
	if e.TransitMount != "transit" {
		t.Fatalf("unexpected mount: %q", e.TransitMount)
	}
	if e.TransitKey != "n" {
		t.Fatalf("unexpected transit key: %q", e.TransitKey)
	}
}
