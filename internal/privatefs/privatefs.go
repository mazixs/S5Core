// Package privatefs creates files and directories that only the process user
// can reach. On POSIX that is mode 0600 or 0700, which the standard library
// already gives. On Windows the mode bits do nothing and a new file inherits
// the access of its directory, so the file or directory gets, at creation, a
// protected DACL of its own: the process user, SYSTEM and local
// Administrators, owned by the process user. CheckDir tells whether a
// directory that already exists is as private as one MkdirAll creates.
//
// It may depend on nothing of ours: internal/logging and internal/userstore
// make their files private through it.
package privatefs
