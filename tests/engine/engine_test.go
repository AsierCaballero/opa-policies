package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AsierCaballero/opa-policies/pkg/engine"
)

func TestNewEngine(t *testing.T) {
	dir := t.TempDir()

	policy := `package test
deny["test violation"] { true }`

	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	e, err := engine.New(dir)
	if err != nil {
		t.Fatalf("New() err = %v", err)
	}

	policies := e.Policies()
	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestValidateFileYAML(t *testing.T) {
	dir := t.TempDir()

	policy := `package test
deny["always fails"] { true }`

	if err := os.WriteFile(filepath.Join(dir, "test.rego"), []byte(policy), 0644); err != nil {
		t.Fatal(err)
	}

	input := "key: value\n"

	inputPath := filepath.Join(dir, "input.yaml")
	if err := os.WriteFile(inputPath, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	e, err := engine.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	results, err := e.ValidateFile(inputPath)
	if err != nil {
		t.Fatalf("ValidateFile() err = %v", err)
	}

	if len(results) == 0 {
		t.Error("expected at least 1 result")
	}

	failed := false
	for _, r := range results {
		if !r.Passed {
			failed = true
		}
	}
	if !failed {
		t.Error("expected at least one failure")
	}
}

func TestValidateFileNotFound(t *testing.T) {
	dir := t.TempDir()
	e, err := engine.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.ValidateFile("/nonexistent/file.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
