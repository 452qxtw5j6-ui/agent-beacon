//go:build !unix

package asymptoteobserve

// processOwnsHome is always true off Unix: file modes there do not decide who can append (Windows
// uses the profile's ACL), so the root-in-another-home hazard does not arise.
func processOwnsHome(string) bool { return true }
