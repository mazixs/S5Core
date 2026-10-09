//go:build !linux

package tcptune

import "syscall"

func setListenFastOpen(uintptr) error { return errUnsupported }

func setConnectFastOpen(uintptr) error { return errUnsupported }

func synData(syscall.Conn) (bool, bool) { return false, false }

func synSent(syscall.Conn) (bool, bool) { return false, false }

func dialsFastOpen(syscall.Conn) (bool, bool) { return false, false }

func fastOpenClientFail(syscall.Conn) (int, bool) { return 0, false }

func ProbeFastOpenConnect() error { return errUnsupported }

func FastOpenMode() (int, bool) { return 0, false }

func FastOpenPassive() (uint64, bool) { return 0, false }
