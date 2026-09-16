package scanner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// serviceRegistry maps well-known ports to a short service name. This is
// just a hint based on the port number - it does NOT mean the port was
// verified to actually be running that protocol.
var serviceRegistry = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3306: "MySQL",
	5432: "PostgreSQL",
	6379: "Redis",
	8080: "HTTP-Alt",
}

// ServiceHint returns the well-known service name for a port, or "unknown"
// if we don't have one registered. This is a guess based on port number
// only, not something we actually verified.
func ServiceHint(port int) string {
	if name, ok := serviceRegistry[port]; ok {
		return name
	}
	return "unknown"
}

// DefaultPorts returns the ports in the service registry, sorted. This is
// what gets scanned when the user doesn't pass --ports.
func DefaultPorts() []int {
	ports := make([]int, 0, len(serviceRegistry))
	for p := range serviceRegistry {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// ParsePorts parses a port spec like "80", "22,80,443", "1-1000", or
// "22,80,443,8000-8100" into a sorted, deduplicated list of ports.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("port spec is empty")
	}

	seen := make(map[int]bool)
	var ports []int

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port segment in %q", spec)
		}

		if strings.Contains(part, "-") {
			lo, hi, err := parseRange(part)
			if err != nil {
				return nil, err
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}

		p, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}

	sort.Ints(ports)
	return ports, nil
}

func parseRange(part string) (lo, hi int, err error) {
	bounds := strings.SplitN(part, "-", 2)
	if len(bounds) != 2 {
		return 0, 0, fmt.Errorf("bad port range %q", part)
	}

	lo, err = parsePort(strings.TrimSpace(bounds[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("bad range start in %q: %w", part, err)
	}
	hi, err = parsePort(strings.TrimSpace(bounds[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("bad range end in %q: %w", part, err)
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("reversed port range %q", part)
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range (must be 1-65535)", p)
	}
	return p, nil
}
