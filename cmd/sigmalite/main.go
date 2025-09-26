package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/runreveal/sigmalite"
	"gopkg.in/yaml.v3"
)

type stringSlice []string

func (s *stringSlice) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if err := run(os.Stdout, os.Stderr, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(stdout io.Writer, stderr io.Writer, args []string) error {
	fs := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	fs.SetOutput(stderr)

	var inputPath string
	var inputFormat string
	var rulePaths stringSlice

	fs.StringVar(&inputPath, "input", "", "Path to the log input file")
	fs.StringVar(&inputFormat, "input-format", "tshark-json", "Format of the input logs (tshark-json, jsonl, raw)")
	fs.Var(&rulePaths, "rule", "Path to a Sigma rule file (repeatable)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if inputPath == "" {
		return errors.New("missing required -input")
	}
	if len(rulePaths) == 0 {
		return errors.New("at least one -rule must be provided")
	}

	entries, err := parseEntries(inputPath, inputFormat)
	if err != nil {
		return err
	}

	rules, err := loadRules(rulePaths)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(stdout)
	for _, entry := range entries {
		for _, rule := range rules {
			if rule.Detection.Matches(entry, nil) {
				result := map[string]any{
					"rule_title": rule.Title,
					"rule_id":    rule.ID,
					"message":    entry.Message,
					"fields":     entry.Fields,
				}
				if err := enc.Encode(result); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func parseEntries(path string, format string) ([]*sigmalite.LogEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read input %s: %w", path, err)
	}

	switch format {
	case "tshark-json":
		return sigmalite.ParseTSharkJSON(data)
	case "jsonl":
		return parseJSONLines(data)
	case "raw":
		return parseRawLines(data), nil
	default:
		return nil, fmt.Errorf("unknown input format %q", format)
	}
}

func parseJSONLines(data []byte) ([]*sigmalite.LogEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]*sigmalite.LogEntry, 0)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		entry, err := decodeJSONLine(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func decodeJSONLine(line string) (*sigmalite.LogEntry, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()

	raw := make(map[string]any)
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	message := ""
	fields := make(map[string]string)

	if msg, ok := raw["message"]; ok {
		if s, ok := stringifyValue(msg); ok {
			message = s
		}
		delete(raw, "message")
	}

	if fieldBlock, ok := raw["fields"]; ok {
		switch typed := fieldBlock.(type) {
		case map[string]any:
			for k, v := range typed {
				if s, ok := stringifyValue(v); ok {
					fields[k] = s
				}
			}
		case map[string]string:
			for k, v := range typed {
				fields[k] = v
			}
		default:
			return nil, fmt.Errorf("fields must be a JSON object")
		}
		delete(raw, "fields")
	}

	for k, v := range raw {
		if s, ok := stringifyValue(v); ok {
			fields[k] = s
		}
	}

	if message == "" {
		message = fields["message"]
	}

	return &sigmalite.LogEntry{
		Message: message,
		Fields:  fields,
	}, nil
}

func stringifyValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case uint64:
		return strconv.FormatUint(v, 10), true
	case bool:
		return strconv.FormatBool(v), true
	case nil:
		return "", false
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v), true
		}
		return string(data), true
	}
}

func parseRawLines(data []byte) []*sigmalite.LogEntry {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]*sigmalite.LogEntry, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := map[string]string{"message": line}
		entries = append(entries, &sigmalite.LogEntry{
			Message: line,
			Fields:  fields,
		})
	}
	return entries
}

func loadRules(paths []string) ([]*sigmalite.Rule, error) {
	rules := make([]*sigmalite.Rule, 0)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule %s: %w", path, err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var doc any
			if err := dec.Decode(&doc); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("decode rule %s: %w", path, err)
			}
			if doc == nil {
				continue
			}
			encoded, err := yaml.Marshal(doc)
			if err != nil {
				return nil, fmt.Errorf("marshal rule %s: %w", path, err)
			}
			rule, err := sigmalite.ParseRule(encoded)
			if err != nil {
				return nil, fmt.Errorf("parse rule %s: %w", path, err)
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}
