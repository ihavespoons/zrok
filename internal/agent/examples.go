package agent

import (
	"embed"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed configs/examples/*.yaml
var embeddedExamples embed.FS

// Example represents a single vulnerable/patched code pair
type Example struct {
	CWE         string `yaml:"-"`
	Name        string `yaml:"-"`
	Language    string `yaml:"language"`
	Vulnerable  string `yaml:"vulnerable"`
	Patched     string `yaml:"patched"`
	Explanation string `yaml:"explanation"`
}

// exampleFile represents the YAML structure of an example file
type exampleFile struct {
	CWE      string `yaml:"cwe"`
	Name     string `yaml:"name"`
	Examples []Example `yaml:"examples"`
}

var (
	loadedExamples     map[string][]Example // keyed by CWE ID
	loadedExamplesOnce sync.Once
)

// loadExamples loads all embedded examples into the cache
func loadExamples() {
	loadedExamplesOnce.Do(func() {
		loadedExamples = make(map[string][]Example)

		entries, err := embeddedExamples.ReadDir("configs/examples")
		if err != nil {
			return
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			data, err := embeddedExamples.ReadFile("configs/examples/" + entry.Name())
			if err != nil {
				continue
			}

			var ef exampleFile
			if err := yaml.Unmarshal(data, &ef); err != nil {
				continue
			}

			for i := range ef.Examples {
				ef.Examples[i].CWE = ef.CWE
				ef.Examples[i].Name = ef.Name
			}

			loadedExamples[ef.CWE] = ef.Examples
		}
	})
}

// GetExamplesForCWEs returns examples matching the given CWE IDs
func GetExamplesForCWEs(cweIDs []string) []Example {
	loadExamples()

	var results []Example
	for _, id := range cweIDs {
		if examples, ok := loadedExamples[id]; ok {
			results = append(results, examples...)
		}
	}
	return results
}

// GetExamplesForCWEAndLanguage returns examples matching a CWE ID and language
func GetExamplesForCWEAndLanguage(cweID, language string) []Example {
	loadExamples()

	examples, ok := loadedExamples[cweID]
	if !ok {
		return nil
	}

	var results []Example
	for _, ex := range examples {
		if ex.Language == language {
			results = append(results, ex)
		}
	}
	return results
}
