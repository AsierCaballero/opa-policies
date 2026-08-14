package reporter

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/AsierCaballero/opa-policies/pkg/engine"
)

type Reporter interface {
	Report([]engine.Result) error
}

type TableReporter struct {
	Out io.Writer
}

func (r *TableReporter) Report(results []engine.Result) error {
	w := tabwriter.NewWriter(r.Out, 0, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Policy\tFile\tSeverity\tStatus\tMessage")
	fmt.Fprintln(w, "------\t----\t--------\t------\t-------")

	for _, res := range results {
		status := "PASS"
		if !res.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			truncate(res.Policy, 40),
			truncate(res.File, 30),
			res.Severity,
			status,
			truncate(res.Message, 60),
		)
	}

	return w.Flush()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func (r *TableReporter) summary(results []engine.Result) {
    passed, failed := 0, 0
    for _, res := range results {
        if res.Passed { passed++ } else { failed++ }
    }
    fmt.Fprintf(r.Out, "\n%d passed, %d failed\n", passed, failed)
}
