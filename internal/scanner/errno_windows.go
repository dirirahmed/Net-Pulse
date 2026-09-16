//go:build windows

package scanner

import "syscall"

// On Windows, net errors carry raw Winsock error codes (via
// os.SyscallError -> syscall.Errno), not the POSIX-style syscall.ECONNREFUSED
// etc from the syscall package - those are compatibility constants that
// don't actually get returned by the network stack. So we need the real
// WSA codes here instead.
const (
	errConnRefused     = syscall.Errno(10061) // WSAECONNREFUSED
	errNetUnreachable  = syscall.Errno(10051) // WSAENETUNREACH
	errHostUnreachable = syscall.Errno(10065) // WSAEHOSTUNREACH
)
