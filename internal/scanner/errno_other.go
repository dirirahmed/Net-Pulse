//go:build !windows

package scanner

import "syscall"

const (
	errConnRefused     = syscall.ECONNREFUSED
	errNetUnreachable  = syscall.ENETUNREACH
	errHostUnreachable = syscall.EHOSTUNREACH
)
