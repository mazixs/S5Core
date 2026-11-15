//go:build !unix && !windows

package logging

// No O_NOFOLLOW here; the Lstat check in OpenRotating refuses a link.
const noFollow = 0
