package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type File struct {
	Serve   Serve    `yaml:"serve"`
	MITM    MITM     `yaml:"mitm"`
	Modules []Module `yaml:"modules"`
	Capture Capture  `yaml:"capture"`
}

type Serve struct {
	Listen         string `yaml:"listen"`
	AdminListen    string `yaml:"admin_listen"`
	CADir          string `yaml:"ca_dir"`
	DialTimeout    string `yaml:"dial_timeout"`
	UDPMaxSessions int    `yaml:"udp_max_sessions"`
	UDPIdleTimeout string `yaml:"udp_idle_timeout"`
}

type MITM struct {
	All   bool     `yaml:"all"`
	Hosts []string `yaml:"hosts"`
}

type Module struct {
	Name      string         `yaml:"name"`
	Enable    *bool          `yaml:"enable"`
	Path      string         `yaml:"path"`
	Arguments map[string]any `yaml:"arguments"`
}

type Capture struct {
	Enabled      bool     `yaml:"enabled"`
	MaxEntries   int      `yaml:"max_entries"`
	MaxBodyBytes int64    `yaml:"max_body_bytes"`
	ContentTypes []string `yaml:"content_types"`
	HAROut       string   `yaml:"har_out"`
}

func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &File{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return cfg, nil
}
