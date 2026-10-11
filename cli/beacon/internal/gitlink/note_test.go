package gitlink

import (
	"reflect"
	"strings"
	"testing"
)

func TestLinkLineRoundTrips(t *testing.T) {
	for _, link := range []Link{
		{Harness: "claude_code", SessionID: "0f8e2c1a-5b6d-4e7f-8a9b-0c1d2e3f4a5b"},
		{Harness: "codex", SessionID: "rollout-2026-09-27T10:00:00"},
		{Harness: "cursor", SessionID: "a/b"}, // only the first slash separates the harness
	} {
		got, ok := ParseLine(link.Line())
		if !ok || got != link {
			t.Fatalf("ParseLine(%q) = %+v, %v; want %+v", link.Line(), got, ok, link)
		}
	}
}

func TestParseLineRejectsWhatItCannotWriteBack(t *testing.T) {
	for _, line := range []string{
		"",
		"traces:abc",
		"beacon:",
		"beacon:claude_code",      // no session
		"beacon:claude_code/",     // empty session
		"beacon:Claude/abc",       // harness is lowercase snake case
		"beacon:claude-code/abc",  // ... with no dashes
		"beacon:/abc",             // empty harness
		"beacon:codex/ab\x1b[2Jc", // terminal escape in the id
		"beacon:codex/café",       // non-ASCII
		"beacon:codex/" + strings.Repeat("a", MaxSessionIDLength+1),
	} {
		if link, ok := ParseLine(line); ok {
			t.Errorf("ParseLine(%q) = %+v, want rejection", line, link)
		}
	}
}

func TestParseLineIgnoresTrailingFields(t *testing.T) {
	got, ok := ParseLine("  beacon:codex/abc future=field  ")
	if !ok || got != (Link{Harness: "codex", SessionID: "abc"}) {
		t.Fatalf("got %+v, %v", got, ok)
	}
}

func TestParseNoteDedupesInOrder(t *testing.T) {
	note := "beacon:codex/b\nsomeone's text\nbeacon:claude_code/a\n\nbeacon:codex/b\n"
	got := keys(ParseNote(note))
	want := []string{"codex/b", "claude_code/a"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMergeNoteKeepsOtherLinesAndAppends(t *testing.T) {
	note := "Reviewed-by: a person\nbeacon:codex/a\nbeacon:v2 something newer\n"
	got := MergeNote(note, []Link{{Harness: "codex", SessionID: "a"}, {Harness: "claude_code", SessionID: "b"}, {Harness: "BAD", SessionID: "c"}})
	want := "Reviewed-by: a person\nbeacon:codex/a\nbeacon:v2 something newer\nbeacon:claude_code/b\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestMergeNoteIsIdempotent(t *testing.T) {
	links := []Link{{Harness: "codex", SessionID: "a"}, {Harness: "cursor", SessionID: "b"}}
	once := MergeNote("", links)
	if twice := MergeNote(once, links); twice != once {
		t.Fatalf("second merge changed the note:\n%q\n%q", once, twice)
	}
	if once != "beacon:codex/a\nbeacon:cursor/b\n" {
		t.Fatalf("got %q", once)
	}
}

func TestMergeNoteNormalizesBlankLinesAndRepeats(t *testing.T) {
	// `git notes append` separates paragraphs with a blank line, and a note merged with the
	// cat_sort_uniq strategy can hold a link twice if one copy carries CRLF.
	got := MergeNote("beacon:codex/a\r\n\nbeacon:codex/a\n", nil)
	if got != "beacon:codex/a\n" {
		t.Fatalf("got %q", got)
	}
	if MergeNote("\n\n", nil) != "" {
		t.Fatal("an empty note must stay empty")
	}
}

func TestNoteLinesCarryAllowlistedShareURLs(t *testing.T) {
	link, ok := ParseLine("beacon:claude_code/s1 https://beacon.sh/s/k3x future-field")
	if !ok || link.URL != "https://beacon.sh/s/k3x" || link.Key() != "claude_code/s1" {
		t.Fatalf("link = %+v %v", link, ok)
	}
	for _, line := range []string{
		"beacon:claude_code/s1 https://evil.example/s/k3x",
		"beacon:claude_code/s1 http://beacon.sh/s/k3x",
		"beacon:claude_code/s1 https://user:pw@beacon.sh/s/k3x",
		"beacon:claude_code/s1 not-a-url",
	} {
		link, ok := ParseLine(line)
		if !ok || link.URL != "" || link.SessionID != "s1" {
			t.Errorf("%q = %+v %v; want the link without a URL", line, link, ok)
		}
	}
	if got := (Link{Harness: "codex", SessionID: "a", URL: "https://evil.example/x"}).Line(); got != "beacon:codex/a" {
		t.Fatalf("disallowed URL written: %q", got)
	}
	AllowShareHost("beacon.internal.example")
	if !ValidShareURL("https://beacon.internal.example/s/1") {
		t.Fatal("configured host refused")
	}
}

func TestMergeNoteAndSetLinkURLsKeepTheURL(t *testing.T) {
	// cat_sort_uniq puts the bare line first; the URL line must win.
	merged := MergeNote("beacon:codex/a\nbeacon:codex/a https://beacon.sh/s/1\nReviewed-by: x\n", nil)
	if merged != "beacon:codex/a https://beacon.sh/s/1\nReviewed-by: x\n" {
		t.Fatalf("merged = %q", merged)
	}
	merged = MergeNote("beacon:codex/a\n", []Link{{Harness: "codex", SessionID: "a", URL: "https://beacon.sh/s/2"}, {Harness: "cursor", SessionID: "b", URL: "https://beacon.sh/s/3"}})
	if merged != "beacon:codex/a https://beacon.sh/s/2\nbeacon:cursor/b https://beacon.sh/s/3\n" {
		t.Fatalf("merged = %q", merged)
	}
	note := "beacon:codex/a\nbeacon:codex/b https://beacon.sh/s/old\nbeacon:codex/c newer-field\nperson line\n"
	got := SetLinkURLs(note, map[string]string{"codex/a": "https://beacon.sh/s/1", "codex/b": "https://beacon.sh/s/2", "codex/c": "https://beacon.sh/s/3", "codex/x": "https://evil.example/"})
	want := "beacon:codex/a https://beacon.sh/s/1\nbeacon:codex/b https://beacon.sh/s/old\nbeacon:codex/c newer-field\nperson line\n"
	if got != want {
		t.Fatalf("SetLinkURLs = %q, want %q", got, want)
	}
	links := ParseNote("beacon:codex/a\nbeacon:codex/a https://beacon.sh/s/1\n")
	if len(links) != 1 || links[0].URL != "https://beacon.sh/s/1" {
		t.Fatalf("ParseNote = %+v", links)
	}
}

// Merging keeps a link's line with trailing fields over the bare line even when this process
// cannot validate the URL in it: merging never loses data.
func TestMergeNoteKeepsAnUnvalidatedURLOverTheBareLine(t *testing.T) {
	url := "https://beacon.unknown-host.example/s/abc"
	if ValidShareURL(url) {
		t.Fatal("the test host must not be allowed")
	}
	got := MergeNote("beacon:cursor/s1\nbeacon:cursor/s1 "+url+"\n", nil)
	if got != "beacon:cursor/s1 "+url+"\n" {
		t.Fatalf("merged %q", got)
	}
	// The first line with fields still wins over a later one.
	got = MergeNote("beacon:cursor/s1 "+url+"\nbeacon:cursor/s1 https://beacon.sh/s/x\n", nil)
	if got != "beacon:cursor/s1 "+url+"\n" {
		t.Fatalf("merged %q", got)
	}
}
