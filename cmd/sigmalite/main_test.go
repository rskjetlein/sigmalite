package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEntriesJSONL(t *testing.T) {
	data := []byte(`{"message":"first","fields":{"EventID":"1"}}
{"message":"second","foo":"bar"}`)
	entries, err := parseJSONLines(data)
	if err != nil {
		t.Fatalf("parseJSONLines() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("parseJSONLines() len = %d; want 2", len(entries))
	}
	if entries[0].Message != "first" {
		t.Errorf("entries[0].Message = %q; want %q", entries[0].Message, "first")
	}
	if got := entries[1].Fields["foo"]; got != "bar" {
		t.Errorf("entries[1].Fields[foo] = %q; want %q", got, "bar")
	}
}

func TestParseEntriesRaw(t *testing.T) {
	data := []byte("hello\nworld\n\n")
	entries := parseRawLines(data)
	if len(entries) != 2 {
		t.Fatalf("parseRawLines() len = %d; want 2", len(entries))
	}
	if entries[0].Message != "hello" {
		t.Errorf("entries[0].Message = %q; want %q", entries[0].Message, "hello")
	}
	if entries[1].Fields["message"] != "world" {
		t.Errorf("entries[1].Fields[message] = %q; want %q", entries[1].Fields["message"], "world")
	}
}

func TestLoadRules(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.yaml")
	content := `---
title: Example One
detection:
  sel:
    message|contains: foo
  condition: sel
---
title: Example Two
detection:
  sel:
    message|contains: bar
  condition: sel
`
	if err := os.WriteFile(rulePath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	rules, err := loadRules([]string{rulePath})
	if err != nil {
		t.Fatalf("loadRules() error = %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("loadRules() len = %d; want 2", len(rules))
	}
	if rules[0].Title != "Example One" {
		t.Errorf("rules[0].Title = %q; want %q", rules[0].Title, "Example One")
	}
}

func TestRunMatches(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.yaml")
	ruleContent := `title: Contains Foo
detection:
  sel:
    message|contains: foo
  condition: sel
`
	if err := os.WriteFile(rulePath, []byte(ruleContent), 0o600); err != nil {
		t.Fatalf("WriteFile(rule) error = %v", err)
	}

	logPath := filepath.Join(dir, "logs.txt")
	if err := os.WriteFile(logPath, []byte("foo here\nnope\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(logs) error = %v", err)
	}

	var out strings.Builder
	if err := run(&out, io.Discard, []string{"-input", logPath, "-input-format", "raw", "-rule", rulePath}); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	dec := json.NewDecoder(strings.NewReader(out.String()))
	var match map[string]any
	if err := dec.Decode(&match); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if match["rule_title"] != "Contains Foo" {
		t.Errorf("match[rule_title] = %v; want %q", match["rule_title"], "Contains Foo")
	}
}
