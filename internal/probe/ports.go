package probe

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Service is a well-known port description. The short Name goes into structured
// results; Description is human-facing text for the CLI.
type Service struct {
	Name        string
	Description string
}

var services = map[int]Service{
	21:    {"FTP", "File transfer - old school file sharing"},
	22:    {"SSH", "Secure Shell - remote command line access"},
	25:    {"SMTP", "Email routing"},
	53:    {"DNS", "Internet phonebook - turns names into IPs"},
	80:    {"HTTP", "Standard web - unencrypted"},
	443:   {"HTTPS", "Secure web - encrypted"},
	3306:  {"MySQL", "Database - where app data is stored"},
	5432:  {"PostgreSQL", "Database - another common app DB"},
	6379:  {"Redis", "In-memory cache / queue"},
	8080:  {"HTTP-Alt", "Common for web development testing"},
	8443:  {"HTTPS-Alt", "TLS on a non-standard port"},
	27017: {"MongoDB", "Document database"},
}

// ServiceName returns the short service label for a port.
func ServiceName(port int) string {
	if s, ok := services[port]; ok {
		return s.Name
	}
	return ""
}

// ServiceDescription returns the human-facing blurb for a port.
func ServiceDescription(port int) string {
	if s, ok := services[port]; ok {
		return s.Description
	}
	return "Unknown custom service"
}

// DefaultPorts returns the known service ports, sorted.
func DefaultPorts() []int {
	ports := make([]int, 0, len(services))
	for p := range services {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// ParsePorts accepts "default", "all", or a comma separated list of ports and
// inclusive ranges such as "22,80,443,8000-8010". Results are deduplicated and
// sorted.
func ParsePorts(spec string) ([]int, error) {
	trimmed := strings.ToLower(strings.TrimSpace(spec))
	switch trimmed {
	case "", "default", "common":
		return DefaultPorts(), nil
	case "all":
		ports := make([]int, 0, 65535)
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	seen := make(map[int]bool)
	var ports []int
	add := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range 1-65535", p)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
		return nil
	}

	for _, field := range strings.Split(trimmed, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(field, "-")
		if !isRange {
			p, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", field)
			}
			if err := add(p); err != nil {
				return nil, err
			}
			continue
		}
		start, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", field)
		}
		end, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return nil, fmt.Errorf("invalid port range %q", field)
		}
		if start > end {
			return nil, fmt.Errorf("invalid port range %q: start is above end", field)
		}
		for p := start; p <= end; p++ {
			if err := add(p); err != nil {
				return nil, err
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports in %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

// PrimaryAddress picks the address to dial from a resolved set, preferring IPv4
// so results stay comparable across runs.
func PrimaryAddress(addrs []string) string {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}
