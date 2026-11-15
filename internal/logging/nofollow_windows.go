package logging

import "golang.org/x/sys/windows"

// os.OpenFile hands FILE_FLAG_* in the high bits of its flags to CreateFile:
// a reparse point on the path is opened itself, and the regular-file check
// refuses it.
const noFollow = windows.FILE_FLAG_OPEN_REPARSE_POINT
