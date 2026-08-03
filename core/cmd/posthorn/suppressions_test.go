package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// FR87: the suppressions CLI round-trip against a real storage file.

func suppressionsConfig(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "posthorn.db")
	return writeConfig(t, validTOML+`
[storage]
path = "`+dbPath+`"
`)
}

func TestSuppressionsCLI_AddListRemove(t *testing.T) {
	cfgPath := suppressionsConfig(t)

	if err := runSuppressions([]string{"add", "bounced@example.com", "--config", cfgPath}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := runSuppressions([]string{"list", "--config", cfgPath}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := runSuppressions([]string{"remove", "bounced@example.com", "--config", cfgPath}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// Second remove is a no-op, not an error.
	if err := runSuppressions([]string{"remove", "bounced@example.com", "--config", cfgPath}); err != nil {
		t.Fatalf("second remove: %v", err)
	}
}

func TestSuppressionsCLI_AddWithReason(t *testing.T) {
	cfgPath := suppressionsConfig(t)
	if err := runSuppressions([]string{"add", "x@example.com", "--reason", "hard_bounce", "--config", cfgPath}); err != nil {
		t.Fatalf("add --reason: %v", err)
	}
}

func TestSuppressionsCLI_Errors(t *testing.T) {
	cfgPath := suppressionsConfig(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{}, "subcommand required"},
		{"unknown subcommand", []string{"purge", "--config", cfgPath}, "unknown subcommand"},
		{"add without email", []string{"add", "--config", cfgPath}, "email argument required"},
		{"remove without email", []string{"remove", "--config", cfgPath}, "email argument required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runSuppressions(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestSuppressionsCLI_RequiresStorageBlock(t *testing.T) {
	cfgPath := writeConfig(t, validTOML) // no [storage]
	err := runSuppressions([]string{"list", "--config", cfgPath})
	if err == nil || !strings.Contains(err.Error(), "[storage]") {
		t.Fatalf("err = %v, want storage-required error", err)
	}
}
