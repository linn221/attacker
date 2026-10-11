package fuzz

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// MarshalConfigurations encodes cfgs as a YAML list.
// A nil slice is written as an empty list.
func MarshalConfigurations(cfgs []Configuration) ([]byte, error) {
	if cfgs == nil {
		cfgs = []Configuration{}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfgs); err != nil {
		return nil, fmt.Errorf("encode configurations: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode configurations: %w", err)
	}
	return buf.Bytes(), nil
}

// UnmarshalConfigurations decodes a YAML list of configurations.
func UnmarshalConfigurations(data []byte) []Configuration {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfgs []Configuration
	if err := dec.Decode(&cfgs); err != nil {
		if err == io.EOF {
			return []Configuration{}
		}
		panic(err.Error())
	}
	if cfgs == nil {
		cfgs = []Configuration{}
	}
	return cfgs
}

// LoadConfigurations reads a YAML list of configurations from path.
func LoadConfigurations(path string) []Configuration {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return UnmarshalConfigurations(data)
}

// SaveConfigurations writes cfgs to path as a YAML list.
func SaveConfigurations(path string, cfgs []Configuration) error {
	data, err := MarshalConfigurations(cfgs)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadConfigurationFile reads a YAML list and applies each configuration as its own shot.
func (fz *Fuzz) LoadConfigurationFile(path string) error {
	cfgs := LoadConfigurations(path)
	fz.AndFunc(ApplyConfigurations(cfgs))
	return nil
}
