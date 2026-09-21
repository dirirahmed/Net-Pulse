package probe

import "testing"

func TestParsePortsList(t *testing.T) {
	ports, err := ParsePorts("443,22,80")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []int{22, 80, 443}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestParsePortsRangeAndDedupe(t *testing.T) {
	ports, err := ParsePorts("8000-8003,8002,80")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []int{80, 8000, 8001, 8002, 8003}
	if len(ports) != len(want) {
		t.Fatalf("got %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("got %v, want %v", ports, want)
		}
	}
}

func TestParsePortsDefault(t *testing.T) {
	ports, err := ParsePorts("default")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	if len(ports) != len(DefaultPorts()) {
		t.Fatalf("default returned %d ports, want %d", len(ports), len(DefaultPorts()))
	}
}

func TestParsePortsInvalid(t *testing.T) {
	for _, spec := range []string{"abc", "0", "70000", "100-50", "80-", "-80", ""} {
		if spec == "" {
			continue
		}
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) succeeded, want error", spec)
		}
	}
}

func TestServiceLookup(t *testing.T) {
	if got := ServiceName(443); got != "HTTPS" {
		t.Errorf("ServiceName(443) = %q, want HTTPS", got)
	}
	if got := ServiceName(9999); got != "" {
		t.Errorf("ServiceName(9999) = %q, want empty", got)
	}
	if ServiceDescription(9999) == "" {
		t.Error("ServiceDescription should always return something")
	}
}

func TestPrimaryAddressPrefersIPv4(t *testing.T) {
	if got := PrimaryAddress([]string{"2606:4700::1111", "1.1.1.1"}); got != "1.1.1.1" {
		t.Errorf("PrimaryAddress = %q, want 1.1.1.1", got)
	}
	if got := PrimaryAddress([]string{"2606:4700::1111"}); got != "2606:4700::1111" {
		t.Errorf("PrimaryAddress = %q, want the only address", got)
	}
	if got := PrimaryAddress(nil); got != "" {
		t.Errorf("PrimaryAddress(nil) = %q, want empty", got)
	}
}
