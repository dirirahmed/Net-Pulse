package scanner

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{"single port", "80", []int{80}, false},
		{"comma list", "22,80,443", []int{22, 80, 443}, false},
		{"range", "1-5", []int{1, 2, 3, 4, 5}, false},
		{"mixed list and range", "22,80,443,8000-8003", []int{22, 80, 443, 8000, 8001, 8002, 8003}, false},
		{"unsorted input gets sorted", "443,22,80", []int{22, 80, 443}, false},
		{"duplicates get removed", "80,80,443,80", []int{80, 443}, false},
		{"overlapping range and list", "1-3,2,3,4", []int{1, 2, 3, 4}, false},
		{"single port range", "22-22", []int{22}, false},
		{"whitespace around parts", " 22 , 80 ", []int{22, 80}, false},

		{"empty spec", "", nil, true},
		{"blank spec", "   ", nil, true},
		{"empty segment", "22,,80", nil, true},
		{"trailing comma", "22,80,", nil, true},
		{"not a number", "abc", nil, true},
		{"port zero", "0", nil, true},
		{"port too high", "65536", nil, true},
		{"negative port", "-5", nil, true},
		{"reversed range", "100-50", nil, true},
		{"range with zero", "0-10", nil, true},
		{"range too high", "65530-65536", nil, true},
		{"malformed range", "1-2-3", nil, true},
		{"dangling dash", "1-", nil, true},
		{"leading dash", "-1", nil, true},
		{"garbage", "80;443", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePorts(%q) = %v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q) unexpected error: %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParsePortsNeverPanics(t *testing.T) {
	inputs := []string{
		"", "-", "--", ",", "1,,2", "a-b", "1-2-3", "99999999999999999999",
		"1-99999999999999999999", strings1000dashes(),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParsePorts(%q) panicked: %v", in, r)
				}
			}()
			_, _ = ParsePorts(in)
		}()
	}
}

func strings1000dashes() string {
	s := make([]byte, 1000)
	for i := range s {
		s[i] = '-'
	}
	return string(s)
}

func TestServiceHint(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{3306, "MySQL"},
		{9999, "unknown"},
	}
	for _, tt := range tests {
		if got := ServiceHint(tt.port); got != tt.want {
			t.Errorf("ServiceHint(%d) = %q, want %q", tt.port, got, tt.want)
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) == 0 {
		t.Fatal("DefaultPorts() returned empty list")
	}
	for i := 1; i < len(ports); i++ {
		if ports[i-1] >= ports[i] {
			t.Fatalf("DefaultPorts() not sorted/deduped: %v", ports)
		}
	}
}
