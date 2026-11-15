// Package privatefstest checks, for the tests of every package that makes
// files private, that a file or a directory really is: the mode bits on POSIX,
// the DACL on Windows. It reads the result on its own and does not ask
// privatefs. Only tests import it.
package privatefstest
