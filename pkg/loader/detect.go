package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return detectYAMLType(path)
	case ".tf", ".tfvars":
		return TypeTerraform, nil
	case ".dockerfile":
		return TypeDocker, nil
	case "":
		base := strings.ToLower(filepath.Base(path))
		if base == "dockerfile" || base == "containerfile" {
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
	content := string(raw)
	if strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:") {
		return TypeK8s, nil
	}
	if strings.Contains(content, "on:") || strings.Contains(content, "runs-on:") {
		return TypeGitHub, nil
	}
	return TypeUnknown, nil
}
