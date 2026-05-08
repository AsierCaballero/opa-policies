package engine

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AsierCaballero/opa-policies/pkg/reporter"
)

func TestTableReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &reporter.TableReporter{Out: &buf}
	results := []Result{
		{Policy: "k8s/security", File: "pod.yaml", Message: "test", Severity: "high", Passed: false},
		{Policy: "tf/aws", File: "main.tf", Message: "ok", Severity: "info", Passed: true},
	}
	if err := r.Report(results); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "PASS") {
		t.Error("expected PASS in output")
	}
	if !strings.Contains(buf.String(), "FAIL") {
		t.Error("expected FAIL in output")
	}
}

func TestJUnitReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &reporter.JUnitReporter{Out: &buf}
	results := []Result{
		{Policy: "test", File: "x.yaml", Message: "fail", Passed: false},
	}
	if err := r.Report(results); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "failure") {
		t.Error("expected failure element in JUnit output")
	}
}
