package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/ast"
)

type Result struct {
	Policy   string `json:"policy"`
	File     string `json:"file"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Passed   bool   `json:"passed"`
}

type Policy struct {
	Path      string
	Namespace string
	Module    *ast.Module
}

type Engine struct {
	policies []Policy
	modules  map[string]*ast.Module
}

func New(policyDir string) (*Engine, error) {
	e := &Engine{
		modules: make(map[string]*ast.Module),
	}

	err := filepath.Walk(policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".rego") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		mod, err := ast.ParseModule(path, string(raw))
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		rel, _ := filepath.Rel(policyDir, path)
		ns := filepath.Dir(rel)

		e.policies = append(e.policies, Policy{
			Path:      rel,
			Namespace: ns,
			Module:    mod,
		})
		e.modules[rel] = mod

		return nil
	})

	return e, err
}

func (e *Engine) Policies() []string {
	var out []string
	for _, p := range e.policies {
		out = append(out, p.Path)
	}
	return out
}

func (e *Engine) ValidateFile(path string) ([]Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	input := make(map[string]interface{})
	if err := parseInput(string(raw), &input); err != nil {
		// try plain string
		input["content"] = string(raw)
		input["path"] = path
	}

	return e.validate(input, path)
}

func (e *Engine) validate(input map[string]interface{}, source string) ([]Result, error) {
	var results []Result

	for _, p := range e.policies {
		r := rego.New(
			rego.Query("x = data"),
			rego.Module(p.Path, p.Module.String()),
			rego.Input(input),
		)

		ctx := context.Background()
		rs, err := r.Eval(ctx)
		if err != nil {
			results = append(results, Result{
				Policy:   p.Path,
				File:     source,
				Message:  fmt.Sprintf("eval error: %v", err),
				Severity: "error",
				Passed:   false,
			})
			continue
		}

		if len(rs) == 0 {
			continue
		}

		extracted := extractDenials(rs, p.Path)
		for _, d := range extracted {
			d.File = source
			results = append(results, d)
		}
	}

	if len(results) == 0 {
		results = append(results, Result{
			Policy:   "(all)",
			File:     source,
			Message:  "no policy violations",
			Severity: "info",
			Passed:   true,
		})
	}

	return results, nil
}

func (e *Engine) RunTests() error {
	// TODO: shell out to opa test for now
	// proper in-process test runner later
	return fmt.Errorf("not implemented: use opa test ./policies/...")
}

func extractDenials(rs rego.ResultSet, policy string) []Result {
	var out []Result
	for _, r := range rs {
		for k, v := range r.Bindings {
			if k != "x" {
				continue
			}
			data, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			out = append(out, walkData(data, policy, "")...)
		}
	}
	return out
}

func walkData(data map[string]interface{}, policy, prefix string) []Result {
	var out []Result
	for k, v := range data {
		full := prefix + "/" + k
		switch val := v.(type) {
		case map[string]interface{}:
			out = append(out, walkData(val, policy, full)...)
		case []interface{}:
			for _, item := range val {
				if m, ok := item.(map[string]interface{}); ok {
					out = append(out, walkData(m, policy, full)...)
				}
			}
		case string:
			if isDenyPrefix(k) {
				out = append(out, Result{
					Policy:   policy,
					Message:  val,
					Severity: "high",
					Passed:   false,
				})
			}
		}
	}
	return out
}

func isDenyPrefix(k string) bool {
	return k == "deny" || strings.HasPrefix(k, "deny_")
}
// TODO: cache compiled queries per policy for repeated calls

func (e *Engine) ValidateFileWithNamespace(path, namespace string) ([]Result, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("read input: %w", err)
    }
    input := make(map[string]interface{})
    if err := parseInput(string(raw), &input); err != nil {
        input["content"] = string(raw)
        input["path"] = path
    }
    return e.validate(input, path)
}
