package engine

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

func parseInput(raw string, out *map[string]interface{}) error {
	if err := yaml.Unmarshal([]byte(raw), out); err == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), out); err == nil {
		return nil
	}
	return fmt.Errorf("unparseable input (tried YAML and JSON)")
}
