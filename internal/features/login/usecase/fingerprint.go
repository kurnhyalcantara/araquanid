package usecase

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// computeFingerprint implements FR-DEVICE-001's canonical fingerprint hash:
// SHA-256 over user_agent|accept_language|screen_resolution|timezone|
// platform|color_depth|language|ip_subnet, each component trimmed,
// lowercased, and empty-if-null, in that exact order. user_agent and
// accept_language are always the server-observed header values (headerUA/
// headerAcceptLanguage) — the request body's DeviceFingerprint carries its
// own copies of those two fields, but the FRD's source table designates the
// header as authoritative for them, making the body copies vestigial.
func computeFingerprint(headerUA, headerAcceptLanguage string, body DeviceFingerprintInput, ip netip.Addr) string {
	components := []string{
		normalize(truncate(headerUA, 512)),
		normalize(truncate(headerAcceptLanguage, 64)),
		normalize(body.ScreenResolution),
		normalize(body.Timezone),
		normalize(body.Platform),
		strconv.Itoa(int(body.ColorDepth)),
		normalize(body.Language),
		ipSubnet(ip),
	}
	sum := sha256.Sum256([]byte(strings.Join(components, "|")))
	return hex.EncodeToString(sum[:])
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ipSubnet returns the first 24 bits of an IPv4 address (e.g.
// "203.0.113.0/24"), or "" for any other/invalid address — FR-DEVICE-001
// does not specify an IPv6 form.
func ipSubnet(ip netip.Addr) string {
	if !ip.Is4() {
		return ""
	}
	b := ip.As4()
	return fmt.Sprintf("%d.%d.%d.0/24", b[0], b[1], b[2])
}

// inferDeviceName implements FR-DEVICE-003's User-Agent-based display name
// inference for automatic device registration.
func inferDeviceName(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "Mobile") && strings.Contains(userAgent, "Safari"):
		return "Mobile Safari on iOS"
	case strings.Contains(userAgent, "Chrome") && strings.Contains(userAgent, "Android"):
		return "Chrome on Android"
	case strings.Contains(userAgent, "Chrome"):
		return "Chrome on " + osFromUserAgent(userAgent)
	case strings.Contains(userAgent, "Firefox"):
		return "Firefox on " + osFromUserAgent(userAgent)
	case strings.Contains(userAgent, "Safari"):
		return "Safari on macOS"
	case strings.Contains(userAgent, "PostmanRuntime"):
		return "Postman API Client"
	default:
		return "Unknown Browser"
	}
}

func osFromUserAgent(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "Windows NT"):
		return "Windows"
	case strings.Contains(userAgent, "Mac OS X"):
		return "macOS"
	case strings.Contains(userAgent, "Linux"):
		return "Linux"
	default:
		return "Unknown"
	}
}
