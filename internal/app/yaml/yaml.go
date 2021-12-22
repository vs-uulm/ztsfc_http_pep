package yaml

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadYamlFile(yamlFilePath string, target interface{}) error {
	if yamlFilePath == "" {
		return errors.New("yaml: LoadYamlFile(): no yaml file path was provided")
	}

	if target == nil {
		return errors.New("yaml: LoadYamlFile(): provided target pointer is nil")
	}

	file, err := os.Open(yamlFilePath)
	if err != nil {
		return fmt.Errorf("yaml: LoadYamlFile(): could not open yaml file: %w", err)
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	err = d.Decode(target)
	if err != nil {
		return fmt.Errorf("yaml: LoadYamlFile(): could not decode yaml file: %w", err)
	}

	return nil

}
