// Package report turns scan results into the plain-text tables netpulse
// prints to stdout.
package report

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/dirirahmed/Net-Pulse/internal/model"
)

// WriteTable prints results as a tab-aligned table. In non-verbose mode
// only OPEN results are shown; verbose mode shows everything plus the
// error classification column.
func WriteTable(w io.Writer, results []model.Result, verbose bool) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)

	if verbose {
		fmt.Fprintln(tw, "PORT\tSTATE\tSERVICE\tLATENCY\tERROR")
	} else {
		fmt.Fprintln(tw, "PORT\tSTATE\tSERVICE\tLATENCY")
	}

	shown := 0
	for _, r := range results {
		if !verbose && r.State != model.StateOpen {
			continue
		}
		shown++

		latency := "-"
		if r.State == model.StateOpen {
			latency = r.Latency.Round(time.Microsecond).String()
		}

		if verbose {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Port, r.State, r.Service, latency, r.ErrType)
		} else {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", r.Port, r.State, r.Service, latency)
		}
	}

	tw.Flush()

	if shown == 0 {
		if verbose {
			fmt.Fprintln(w, "(no results)")
		} else {
			fmt.Fprintln(w, "(no open ports found - use --verbose to see closed/filtered/error results)")
		}
	}
}
