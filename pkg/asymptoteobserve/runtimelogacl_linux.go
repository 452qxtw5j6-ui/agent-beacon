//go:build linux

package asymptoteobserve

import (
	"errors"

	"golang.org/x/sys/unix"
)

// hasPOSIXACL reports whether the file carries a POSIX access ACL, whose mask is the file's group
// bits. A variable so tests can stand in for a filesystem with ACLs.
var hasPOSIXACL = func(path string) bool {
	_, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	return err == nil || errors.Is(err, unix.ERANGE)
}
