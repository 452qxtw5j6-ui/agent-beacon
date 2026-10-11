//go:build !windows

package writer

import "testing"

// requireSystemACLRights is a no-op where the system log has no ACL step to apply.
func requireSystemACLRights(t *testing.T) { t.Helper() }
