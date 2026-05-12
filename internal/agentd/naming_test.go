package agentd

import (
	"strings"
	"testing"
)

func TestTransitKeyNameForFingerprint(t *testing.T) {
	t.Parallel()

	fp := "SHA256:AbC+De/Fg=="
	got := transitKeyNameForFingerprint(fp)
	if got != "ssh-abc-de_fg" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestShortFingerprint(t *testing.T) {
	t.Parallel()

	fp := "SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=="
	got := shortFingerprint(fp)
	if len(got) == 0 || len(got) > 10 {
		t.Fatalf("unexpected length: %q", got)
	}
	if strings.ContainsAny(got, "+/=") {
		t.Fatalf("unexpected chars: %q", got)
	}
}
