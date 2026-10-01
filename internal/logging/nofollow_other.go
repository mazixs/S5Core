//go:build !unix

package logging

// Windows has no O_NOFOLLOW; the Lstat check in OpenRotating refuses a link.
const noFollow = 0
