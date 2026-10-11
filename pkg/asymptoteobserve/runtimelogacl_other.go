//go:build !linux

package asymptoteobserve

// hasPOSIXACL is false off Linux: macOS ACLs are separate from the mode bits, so narrowing the
// group bits there never cancels a grant, and Windows does not use the mode bits at all.
var hasPOSIXACL = func(string) bool { return false }
