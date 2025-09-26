// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ParseTSharkJSON parses the JSON output produced by "tshark -T json" and returns a slice of LogEntry values.
//
// TShark emits either a single JSON array of packets or a stream of JSON objects separated by newlines.
// This helper accepts both formats. Each resulting LogEntry contains a flattened map of all values in the
// packet's `layers` section. Array values are stored twice: once as comma-separated strings under the
// original field name, and once per element with an index suffix (e.g. `dns.a[0]`). A few commonly-used
// summary fields, such as `frame.col.info`, are promoted to the LogEntry.Message field when present.
func ParseTSharkJSON(data []byte) ([]*LogEntry, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, nil
	}

	packets, err := parseTSharkJSONPackets(data)
	if err != nil {
		return nil, err
	}

	entries := make([]*LogEntry, 0, len(packets))
	for i, raw := range packets {
		entry, err := buildTSharkLogEntry(raw)
		if err != nil {
			return nil, fmt.Errorf("parse tshark json packet %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func parseTSharkJSONPackets(data []byte) ([]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var arr []json.RawMessage
	if err := dec.Decode(&arr); err == nil {
		// Successfully parsed as a JSON array.
		return arr, nil
	}

	// Fall back to a stream of JSON objects.
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	packets := make([]json.RawMessage, 0)
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, fmt.Errorf("parse tshark json: %w", err)
		}
		packets = append(packets, raw)
	}
	if len(packets) == 0 {
		return nil, fmt.Errorf("parse tshark json: unsupported format")
	}
	return packets, nil
}

func buildTSharkLogEntry(raw json.RawMessage) (*LogEntry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var packet map[string]any
	if err := dec.Decode(&packet); err != nil {
		return nil, fmt.Errorf("decode packet: %w", err)
	}

	fields := make(map[string]string)

	layers := extractTSharkLayers(packet)
	if layers != nil {
		flattenTSharkLayer(fields, layers)
	} else {
		flattenInto(fields, "", packet)
	}

	if ts, ok := packet["timestamp"]; ok {
		if s, ok := stringifyScalar(ts); ok {
			fields["timestamp"] = s
		}
	}

	message := selectTSharkMessage(fields)

	return &LogEntry{
		Message: message,
		Fields:  fields,
	}, nil
}

func extractTSharkLayers(packet map[string]any) map[string]any {
	if layers, ok := packet["layers"].(map[string]any); ok {
		return layers
	}
	if src, ok := packet["_source"].(map[string]any); ok {
		if layers, ok := src["layers"].(map[string]any); ok {
			return layers
		}
	}
	return nil
}

func flattenTSharkLayer(dst map[string]string, layers map[string]any) {
	keys := sortedKeys(layers)
	for _, layer := range keys {
		value := layers[layer]
		if m, ok := value.(map[string]any); ok {
			flattenInto(dst, "", m)
			continue
		}
		flattenInto(dst, layer, value)
	}
}

func flattenInto(dst map[string]string, prefix string, value any) {
	switch v := value.(type) {
	case map[string]any:
		if len(v) == 0 {
			if prefix != "" {
				dst[prefix] = ""
			}
			return
		}
		keys := sortedKeys(v)
		for _, k := range keys {
			next := k
			if prefix != "" {
				next = prefix + "." + k
			}
			flattenInto(dst, next, v[k])
		}
	case []any:
		if prefix == "" {
			for i, elem := range v {
				idx := fmt.Sprintf("[%d]", i)
				flattenInto(dst, idx, elem)
			}
			return
		}
		simpleValues := make([]string, 0, len(v))
		for i, elem := range v {
			idx := fmt.Sprintf("%s[%d]", prefix, i)
			flattenInto(dst, idx, elem)
			if s, ok := stringifyScalar(elem); ok {
				simpleValues = append(simpleValues, s)
			}
		}
		if len(simpleValues) > 0 {
			dst[prefix] = strings.Join(simpleValues, ",")
		}
	default:
		if prefix == "" {
			return
		}
		if s, ok := stringifyScalar(v); ok {
			dst[prefix] = s
		} else {
			dst[prefix] = fmt.Sprint(v)
		}
	}
}

func stringifyScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	case bool:
		return strconv.FormatBool(v), true
	case nil:
		return "", false
	default:
		return "", false
	}
}

func selectTSharkMessage(fields map[string]string) string {
	for _, key := range []string{"frame.col.info", "frame.col_info", "frame.info"} {
		if v, ok := fields[key]; ok {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
