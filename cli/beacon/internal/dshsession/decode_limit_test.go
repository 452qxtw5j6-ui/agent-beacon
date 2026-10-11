package dshsession

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func withDecodedLimit(t *testing.T, limit uint64) {
	t.Helper()
	old := maxDecodedBytes
	t.Cleanup(func() { maxDecodedBytes = old })
	maxDecodedBytes = limit
}

// streamedFrame encodes data the way a streaming writer does, without a declared content size, so
// the decoder only learns the size by decoding.
func streamedFrame(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enc.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodeRefusesASessionThatDecompressesPastTheLimit(t *testing.T) {
	withDecodedLimit(t, 1<<20)
	big := bytes.Repeat([]byte{'a'}, 4<<20)
	half := bytes.Repeat([]byte{'b'}, 700<<10)

	cases := map[string][]byte{
		"one frame declaring its size":               zstdFrame(t, big),
		"one streamed frame":                         streamedFrame(t, big),
		"frames each under the limit, together over": append(zstdFrame(t, half), zstdFrame(t, half)...),
	}
	for name, data := range cases {
		if len(data) > 64<<10 {
			t.Fatalf("%s: fixture is %d bytes on disk; it should be a small file that expands", name, len(data))
		}
		out, partial, err := decodeZstdFrames(data)
		if !errors.Is(err, errDecodedTooLarge) {
			t.Fatalf("%s: err = %v (decoded %d bytes, partial %t), want the size limit", name, err, len(out), partial)
		}
	}

	ok := zstdFrame(t, half)
	if out, _, err := decodeZstdFrames(ok); err != nil || len(out) != len(half) {
		t.Fatalf("a session under the limit: %d bytes, %v", len(out), err)
	}
}

func TestReadRefusesADecompressionBomb(t *testing.T) {
	withDecodedLimit(t, 1<<20)
	dir := filepath.Join(t.TempDir(), "sessions", "bomb")
	path := filepath.Join(dir, "session.v3.jsonl.zstd")
	writeBytes(t, path, zstdFrame(t, bytes.Repeat([]byte("\n"), 8<<20)))
	store := &Store{SessionsDir: filepath.Dir(dir)}
	_, _, err := store.Read(SessionRef{ID: "bomb", Path: path, Dir: dir, Compressed: true})
	if !errors.Is(err, errDecodedTooLarge) {
		t.Fatalf("Read = %v, want the size limit", err)
	}
}
