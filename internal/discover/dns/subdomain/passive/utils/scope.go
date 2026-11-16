package utils

import (
	"strings"
)

// NormalizeDomain canonicalizes DNS names for scope comparisons.
func NormalizeDomain(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// IsDomainInScope matches the target itself and descendants at a DNS label boundary.
func IsDomainInScope(name, target string) bool {
	name = NormalizeDomain(name)
	target = NormalizeDomain(target)
	if target == "" || (name != target && !strings.HasSuffix(name, "."+target)) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || strings.ContainsAny(label, "* /\\\t\r\n") {
			return false
		}
	}
	return true
}
