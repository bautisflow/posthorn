package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/craigmccaskill/posthorn/config"
)

// FR76: the optional [storage] block.

func TestLoad_StorageBlock(t *testing.T) {
	toml := minimalTOML + `
[storage]
path = "/var/lib/posthorn/posthorn.db"
retention = "168h"
max_size = "256MB"
`
	cfg, err := loadString(t, toml)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage == nil {
		t.Fatal("Storage nil")
	}
	if cfg.Storage.Path != "/var/lib/posthorn/posthorn.db" {
		t.Errorf("Path = %q", cfg.Storage.Path)
	}
	if got := cfg.Storage.EffectiveRetention(); got != 168*time.Hour {
		t.Errorf("EffectiveRetention = %v", got)
	}
	if got := cfg.Storage.EffectiveMaxSize(); got != "256MB" {
		t.Errorf("EffectiveMaxSize = %q", got)
	}
}

func TestLoad_NoStorageBlock_NilAndDefaults(t *testing.T) {
	cfg, err := loadString(t, minimalTOML)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage != nil {
		t.Fatal("Storage should be nil without a [storage] block (NFR25)")
	}
	// Nil-safe defaults for callers that consult them anyway.
	if got := cfg.Storage.EffectiveRetention(); got != config.DefaultStorageRetention {
		t.Errorf("nil EffectiveRetention = %v", got)
	}
	if got := cfg.Storage.EffectiveMaxSize(); got != config.DefaultStorageMaxSize {
		t.Errorf("nil EffectiveMaxSize = %q", got)
	}
}

func TestLoad_StorageDefaultsApplied(t *testing.T) {
	toml := minimalTOML + `
[storage]
path = "/tmp/p.db"
`
	cfg, err := loadString(t, toml)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Storage.EffectiveRetention(); got != 30*24*time.Hour {
		t.Errorf("default retention = %v", got)
	}
	if got := cfg.Storage.EffectiveMaxSize(); got != "1GB" {
		t.Errorf("default max_size = %q", got)
	}
}

func TestLoad_StoragePathRequired(t *testing.T) {
	toml := minimalTOML + "\n[storage]\nretention = \"24h\"\n"
	_, err := loadString(t, toml)
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("want path-required error, got %v", err)
	}
}

func TestLoad_StoragePathAndInMemoryExclusive(t *testing.T) {
	toml := minimalTOML + "\n[storage]\npath = \"/tmp/p.db\"\nin_memory = true\n"
	_, err := loadString(t, toml)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want exclusivity error, got %v", err)
	}
}

func TestLoad_StorageUnknownKeyRejected(t *testing.T) {
	toml := minimalTOML + "\n[storage]\npath = \"/tmp/p.db\"\nretenshun = \"24h\"\n"
	if _, err := loadString(t, toml); err == nil {
		t.Fatal("unknown [storage] key must be a parse error (strict TOML)")
	}
}
