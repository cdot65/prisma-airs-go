package internal

import (
	"net/url"
	"strings"
)

// PathSeg escapes a caller-supplied identifier for use as exactly one URL path
// segment. Besides url.PathEscape it neutralises "." and "..", which
// PathEscape leaves intact and which servers or proxies may treat as
// path-traversal elements.
func PathSeg(s string) string {
	if s == "." || s == ".." {
		return strings.ReplaceAll(s, ".", "%2E")
	}
	return url.PathEscape(s)
}
