package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

func TestWriteTableNonVerboseOnlyShowsOpen(t *testing.T) {
	results := []model.Result{
		{Port: 22, Service: "SSH", State: model.StateOpen, Latency: 2 * time.Millisecond},
		{Port: 23, Service: "Telnet", State: model.StateClosed, ErrType: model.ErrConnectionRefused},
		{Port: 24, Service: "unknown", State: model.StateTimeout, ErrType: model.ErrTimeout},
	}

	var buf bytes.Buffer
	WriteTable(&buf, results, false)
	out := buf.String()

	if !strings.Contains(out, "22") || !strings.Contains(out, "SSH") {
		t.Errorf("expected open port 22/SSH in output, got:\n%s", out)
	}
	if strings.Contains(out, "23") || strings.Contains(out, "24") {
		t.Errorf("non-verbose output should not include closed/timeout ports, got:\n%s", out)
	}
	if strings.Contains(out, "ERROR") {
		t.Errorf("non-verbose output should not have an ERROR column, got:\n%s", out)
	}
}

func TestWriteTableVerboseShowsEverything(t *testing.T) {
	results := []model.Result{
		{Port: 22, Service: "SSH", State: model.StateOpen, Latency: 2 * time.Millisecond},
		{Port: 23, Service: "Telnet", State: model.StateClosed, ErrType: model.ErrConnectionRefused},
	}

	var buf bytes.Buffer
	WriteTable(&buf, results, true)
	out := buf.String()

	for _, want := range []string{"22", "SSH", "23", "Telnet", "CONNECTION_REFUSED"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output missing %q, got:\n%s", want, out)
		}
	}
}

func TestWriteTableNoOpenPortsMessage(t *testing.T) {
	results := []model.Result{
		{Port: 23, Service: "Telnet", State: model.StateClosed, ErrType: model.ErrConnectionRefused},
	}

	var buf bytes.Buffer
	WriteTable(&buf, results, false)
	if !strings.Contains(buf.String(), "no open ports") {
		t.Errorf("expected a no-open-ports message, got:\n%s", buf.String())
	}
}

func TestWriteTableClosedPortHasNoLatency(t *testing.T) {
	results := []model.Result{
		{Port: 23, Service: "Telnet", State: model.StateClosed, ErrType: model.ErrConnectionRefused},
	}

	var buf bytes.Buffer
	WriteTable(&buf, results, true)
	if strings.Contains(buf.String(), "0s") {
		t.Errorf("closed port should show '-' for latency, not a zero duration, got:\n%s", buf.String())
	}
}
