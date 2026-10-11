package gitlink

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// NotesRef is the notes ref Beacon's links live under. It is a contract: `beacon git notes`, the
// hooks, and anyone who fetched the ref from a teammate read it by this name.
const NotesRef = "refs/notes/beacon"

// linePrefix starts every line Beacon writes. Lines without it are someone else's -- a person who
// ran `git notes append` by hand, or a tool that shares the ref -- and are kept as they are.
const linePrefix = "beacon:"

// MaxSessionIDLength bounds a session id in a note. Runtime session ids are UUIDs or short
// tokens; anything longer is not one, and a note line has no business carrying it.
const MaxSessionIDLength = 256

var harnessPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// Link names one session a commit is linked to.
type Link struct {
	Harness   string `json:"harness"`
	SessionID string `json:"session_id"`
	// URL is the session's shared trace on beacon.sh, when it has been shared. It is the note
	// line's first reserved trailing field: an identifier like the session id, never content.
	URL string `json:"url,omitempty"`
}

// MaxShareURLLength bounds a share URL in a note line.
const MaxShareURLLength = 512

var (
	shareHostsMu sync.RWMutex
	shareHosts   = map[string]bool{"beacon.sh": true}
)

// AllowShareHost adds a host whose https URLs a note line may carry as a share URL, besides
// beacon.sh: the Beacon service the CLI is configured to use.
func AllowShareHost(host string) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	shareHostsMu.Lock()
	shareHosts[host] = true
	shareHostsMu.Unlock()
}

// ValidShareURL reports whether raw may be written into, or read from, a note as a share URL: an
// absolute https URL on an allowed host, with no userinfo, whitespace or control characters. A
// note can come from anyone who pushes to the remote, so a URL on another host is never shown as a
// session's link.
func ValidShareURL(raw string) bool {
	if raw == "" || len(raw) > MaxShareURLLength {
		return false
	}
	for _, r := range raw {
		if r <= ' ' || r >= 0x7f {
			return false
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Opaque != "" {
		return false
	}
	shareHostsMu.RLock()
	defer shareHostsMu.RUnlock()
	return shareHosts[strings.ToLower(u.Host)]
}

// Key is the link's identity, harness and session together: two runtimes may reuse an id.
func (l Link) Key() string { return l.Harness + "/" + l.SessionID }

// Valid reports whether the link can be written as a note line and read back unchanged.
func (l Link) Valid() bool {
	if !harnessPattern.MatchString(l.Harness) {
		return false
	}
	if l.SessionID == "" || len(l.SessionID) > MaxSessionIDLength {
		return false
	}
	for _, r := range l.SessionID {
		// No whitespace, since a line ends at it, and no control or non-ASCII characters, since a
		// note is displayed by `git log` and must not be able to move the terminal's cursor.
		if r <= ' ' || r >= 0x7f {
			return false
		}
	}
	return true
}

// Line is the note line for the link, with its share URL when it has a valid one.
func (l Link) Line() string {
	if ValidShareURL(l.URL) {
		return linePrefix + l.Key() + " " + l.URL
	}
	return linePrefix + l.Key()
}

// ParseLine reads one note line, returning false for a line that is not a Beacon link.
func ParseLine(line string) (Link, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(line), linePrefix)
	if !ok {
		return Link{}, false
	}
	// Fields after whitespace are reserved. The first is a share URL; it is kept only when it is
	// one (ValidShareURL), and anything else there is ignored, so a line written by a newer
	// version still reads as its link.
	trailing := ""
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		rest, trailing = rest[:i], strings.TrimSpace(rest[i:])
	}
	harness, session, ok := strings.Cut(rest, "/")
	if !ok {
		return Link{}, false
	}
	link := Link{Harness: harness, SessionID: session}
	if !link.Valid() {
		return Link{}, false
	}
	if fields := strings.Fields(trailing); len(fields) > 0 && ValidShareURL(fields[0]) {
		link.URL = fields[0]
	}
	return link, true
}

// SetLinkURLs returns note with a share URL added to each Beacon line that names a session in urls
// (keyed by Link.Key) and has no trailing fields yet. Every other line is kept verbatim, including
// a line that already carries a URL or fields this version does not know.
func SetLinkURLs(note string, urls map[string]string) string {
	if len(urls) == 0 {
		return note
	}
	lines := strings.Split(note, "\n")
	for i, line := range lines {
		link, ok := ParseLine(line)
		if !ok || strings.TrimSpace(strings.TrimRight(line, "\r")) != linePrefix+link.Key() {
			continue
		}
		if u := urls[link.Key()]; ValidShareURL(u) {
			link.URL = u
			lines[i] = link.Line()
		}
	}
	return strings.Join(lines, "\n")
}

// ParseNote returns the Beacon links in a note, in the order they first appear, without repeats.
// A link repeated with a share URL (a teammate's copy of a note, merged) takes the URL.
func ParseNote(note string) []Link {
	var links []Link
	index := map[string]int{}
	for _, line := range strings.Split(note, "\n") {
		link, ok := ParseLine(line)
		if !ok {
			continue
		}
		if i, seen := index[link.Key()]; seen {
			if links[i].URL == "" {
				links[i].URL = link.URL
			}
			continue
		}
		index[link.Key()] = len(links)
		links = append(links, link)
	}
	return links
}

// MergeNote returns note with links added. Every existing line is kept verbatim and in place --
// lines that are not Beacon links belong to a person or another tool, and a Beacon line carrying
// fields this version does not know was written by a newer one -- except that blank lines and a
// repeat of a link already seen are dropped. New links are appended in the order given. Merging
// links a note already has returns it unchanged apart from that normalization.
//
// The one exception to "the first line wins" is the share URL: when the kept line is the bare
// `beacon:<harness>/<id>` and a repeat carries trailing fields (a URL, valid here or not), or a new
// link carries a valid URL, that line takes its place. Git's cat_sort_uniq merge sorts the bare line first, and without this a teammate's
// URL would be dropped by the next normalization.
//
// Links are never removed here. A note is shared history, and a teammate's link on the same commit
// is as true as ours.
func MergeNote(note string, links []Link) string {
	var lines []string
	index := map[string]int{}
	bare := func(i int, link Link) bool { return strings.TrimSpace(lines[i]) == linePrefix+link.Key() }
	for _, line := range strings.Split(note, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if link, ok := ParseLine(line); ok {
			if i, seen := index[link.Key()]; seen {
				// Any trailing fields beat the bare line, whether or not this process can
				// validate the URL in them (a self-hosted Beacon this process was not told
				// about, or a field a newer version writes): merging never loses data, and
				// validation applies only when a URL is shown or used.
				if bare(i, link) && strings.TrimSpace(line) != linePrefix+link.Key() {
					lines[i] = line
				}
				continue
			}
			index[link.Key()] = len(lines)
		}
		lines = append(lines, line)
	}
	for _, link := range links {
		if !link.Valid() {
			continue
		}
		if i, seen := index[link.Key()]; seen {
			if ValidShareURL(link.URL) && bare(i, link) {
				lines[i] = link.Line()
			}
			continue
		}
		index[link.Key()] = len(lines)
		lines = append(lines, link.Line())
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// SortLinks orders links by key, for output that must not depend on note order.
func SortLinks(links []Link) {
	sort.Slice(links, func(i, j int) bool { return links[i].Key() < links[j].Key() })
}
