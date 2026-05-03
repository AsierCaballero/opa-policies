package reporter

import (
	"fmt"
	"io"
	"time"

	"github.com/AsierCaballero/opa-policies/pkg/engine"
)

type JUnitReporter struct {
	Out io.Writer
}

func (r *JUnitReporter) Report(results []engine.Result) error {
	now := time.Now().Format("2006-01-02T15:04:05")

	fmt.Fprintf(r.Out, `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="opa-policies" time="%s" tests="%d" failures="%d">
  <testsuite name="policies" tests="%d" failures="%d">
`,
		now, len(results), countFailures(results),
		len(results), countFailures(results))

	for _, res := range results {
		if res.Passed {
			fmt.Fprintf(r.Out, `    <testcase name="%s" classname="%s" />`+"\n",
				res.Policy, res.File)
		} else {
			fmt.Fprintf(r.Out, `    <testcase name="%s" classname="%s">
      <failure message="%s" />
    </testcase>`+"\n",
				res.Policy, res.File, res.Message)
		}
	}

	fmt.Fprintln(r.Out, `  </testsuite>
</testsuites>`)

	return nil
}

func countFailures(results []engine.Result) int {
	n := 0
	for _, r := range results {
		if !r.Passed {
			n++
		}
	}
	return n
}
