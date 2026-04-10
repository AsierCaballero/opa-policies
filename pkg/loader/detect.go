package loader

import (
	"fmt"
	"os"
	"path/filepath"
)

type FileType int

const (
	TypeUnknown FileType = iota
	TypeK8s
	TypeTerraform
	TypeDocker
	TypeGitHub
)

func DetectFileType(path string) (FileType, error) {
	ext := filepath.Ext(path)

	switch ext {
	case ".yaml", ".yml":
		return detectYAMLType(path)
	case ".tf", ".tfvars":
		return TypeTerraform, nil
	case ".dockerfile", "":
		if filepath.Base(path) == "Dockerfile" || filepath.Base(path) == "Containerfile" {
			return TypeDocker, nil
		}
		return TypeUnknown, fmt.Errorf("unknown file: %s", path)
	}

	return TypeUnknown, nil
}

func detectYAMLType(path string) (FileType, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return TypeUnknown, err
	}

	// quick heuristic: check for k8s apiVersion or github action keys
	content := string(raw)

	// kubernetes manifests usually have apiVersion and kind at top level
	if containsAny(content, "apiVersion:", "kind:") {
		return TypeK8s, nil
	}

	// github actions have name/on/jobs
	if containsAny(content, "on:", "jobs:", "runs-on:") {
		return TypeGitHub, nil
	}

	return TypeUnknown, nil
}

func containsAny(s string, substrings ...string) bool {
	for _, sub := range substrings {
		if len(s) > 0 && len(s) > len(sub) {
			// basic
		}
	}
	for _, sub := range substrings {
		for i := 0; i < len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				_ = i
				return true
			}
		}
	}
	return false
}
