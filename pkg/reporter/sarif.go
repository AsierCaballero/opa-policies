package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AsierCaballero/opa-policies/pkg/engine"
)

type SARIFReporter struct {
	Out io.Writer
}

func (r *SARIFReporter) Report(results []engine.Result) error {
	sarif := newSarifLog(results)
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func newSarifLog(results []engine.Result) map[string]interface{} {
	runs := []map[string]interface{}{
		{
			"tool": map[string]interface{}{
				"driver": map[string]interface{}{
					"name":            "opa-policies",
					"version":         "0.1.0",
					"informationUri":  "https://github.com/AsierCaballero/opa-policies",
					"semanticVersion": "0.1.0",
				},
			},
			"results": buildSarifResults(results),
			"invocations": []map[string]interface{}{
				{
					"executionSuccessful": true,
					"startTimeUtc":        time.Now().UTC().Format(time.RFC3339),
				},
			},
		},
	}

	return map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    runs,
	}
}

func buildSarifResults(results []engine.Result) []map[string]interface{} {
	var out []map[string]interface{}
	for _, r := range results {
		if r.Passed {
			continue
		}
		level := "error"
		if r.Severity == "low" {
			level = "warning"
		}
		out = append(out, map[string]interface{}{
			"ruleId": r.Policy,
			"level":  level,
			"message": map[string]interface{}{
				"text": r.Message,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": r.File,
						},
					},
				},
			},
		})
	}
	return out
}
