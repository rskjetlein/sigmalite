// Copyright 2024 RunReveal Inc.
// SPDX-License-Identifier: Apache-2.0

package sigmalite

import "testing"

func TestParseTSharkJSON(t *testing.T) {
	data := []byte(`[
  {
    "_index": "packets-2024.08.20",
    "_type": "doc",
    "_score": null,
    "_source": {
      "layers": {
        "frame": {
          "frame.interface_id": ["0"],
          "frame.number": ["1"],
          "frame.time": ["Aug 20, 2024 12:34:56.789012000 UTC"],
          "frame.col_info": "GET /index.html HTTP/1.1"
        },
        "ip": {
          "ip.src": ["192.168.0.1"],
          "ip.dst": ["93.184.216.34"]
        },
        "http": {
          "http.request.method": "GET",
          "http.request.full_uri": "http://example.com/index.html"
        }
      }
    }
  },
  {
    "timestamp": "2024-08-20T12:34:57.123456Z",
    "layers": {
      "frame": {
        "frame.number": ["2"],
        "frame.col.info": "Standard query 0x0001 A example.com"
      },
      "dns": {
        "dns.qry.name": ["example.com", "www.example.com"]
      }
    }
  }
]`)

	entries, err := ParseTSharkJSON(data)
	if err != nil {
		t.Fatalf("ParseTSharkJSON() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	first := entries[0]
	if first.Message != "GET /index.html HTTP/1.1" {
		t.Fatalf("unexpected message: %q", first.Message)
	}
	if got := first.Fields["frame.number"]; got != "1" {
		t.Fatalf("frame.number = %q, want 1", got)
	}
	if got := first.Fields["ip.src"]; got != "192.168.0.1" {
		t.Fatalf("ip.src = %q, want 192.168.0.1", got)
	}
	if got := first.Fields["http.request.full_uri"]; got != "http://example.com/index.html" {
		t.Fatalf("http.request.full_uri = %q, want http://example.com/index.html", got)
	}

	second := entries[1]
	if got := second.Fields["timestamp"]; got != "2024-08-20T12:34:57.123456Z" {
		t.Fatalf("timestamp = %q, want 2024-08-20T12:34:57.123456Z", got)
	}
	if got := second.Fields["dns.qry.name"]; got != "example.com,www.example.com" {
		t.Fatalf("dns.qry.name = %q, want example.com,www.example.com", got)
	}
	if got := second.Fields["dns.qry.name[1]"]; got != "www.example.com" {
		t.Fatalf("dns.qry.name[1] = %q, want www.example.com", got)
	}
}
