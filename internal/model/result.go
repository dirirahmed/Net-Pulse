// Package model holds the data types shared between the scanner and the
// report/output code. Keeping these separate means the scanner never has to
// know how results get printed.
package model

import "time"

// State is the outcome of probing a single port.
type State int

const (
	StateOpen State = iota
	StateClosed
	StateTimeout
	StateError
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "OPEN"
	case StateClosed:
		return "CLOSED"
	case StateTimeout:
		return "TIMEOUT"
	case StateError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// ErrorType classifies why a probe didn't come back OPEN. It's only
// meaningful when State isn't StateOpen.
type ErrorType int

const (
	ErrNone ErrorType = iota
	ErrConnectionRefused
	ErrTimeout
	ErrNetworkUnreachable
	ErrHostUnreachable
	ErrUnknown
)

func (e ErrorType) String() string {
	switch e {
	case ErrNone:
		return "-"
	case ErrConnectionRefused:
		return "CONNECTION_REFUSED"
	case ErrTimeout:
		return "TIMEOUT"
	case ErrNetworkUnreachable:
		return "NETWORK_UNREACHABLE"
	case ErrHostUnreachable:
		return "HOST_UNREACHABLE"
	case ErrUnknown:
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

// Result is what a single port probe produces.
type Result struct {
	Address string // host:port that was actually dialed
	Port    int
	Service string // service hint from the registry, not a verified protocol
	State   State
	ErrType ErrorType

	// Latency is the TCP connect time. Only set when State == StateOpen.
	// See README for exactly what this measures (it's not pure network
	// propagation delay).
	Latency time.Duration
}
