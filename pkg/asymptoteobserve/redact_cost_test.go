package asymptoteobserve

import (
	"strings"
	"testing"
)

// BenchmarkRedactStringRepeatedAssignments covers the bare-copy pass, which removes every
// assigned value in one sweep. One strings.ReplaceAll per assignment was quadratic in the text:
// 300 KiB of "token=AAAAAAAA " took about 6 s, of which this pass is now a small part.
func BenchmarkRedactStringRepeatedAssignments(b *testing.B) {
	value := strings.Repeat("token=AAAAAAAA ", 20_000)
	b.SetBytes(int64(len(value)))
	for b.Loop() {
		RedactString(value)
	}
}

func TestRedactStringRemovesBareCopiesLongestFirst(t *testing.T) {
	out := RedactString("token=hunter2hunter2 password=hunter2hunter2xyz later hunter2hunter2xyz and hunter2hunter2")
	if strings.Contains(out, "hunter2") || strings.Contains(out, "xyz") {
		t.Fatalf("copy left in %q", out)
	}
}

func TestIsSecretKeyName(t *testing.T) {
	for key, want := range map[string]bool{"password": true, "AWS_SECRET_ACCESS_KEY": true, "client_secret": true, "X-Api-Key": true, "input_tokens": false, "author": false} {
		if got := IsSecretKeyName(key); got != want {
			t.Errorf("IsSecretKeyName(%q) = %v, want %v", key, got, want)
		}
	}
}
