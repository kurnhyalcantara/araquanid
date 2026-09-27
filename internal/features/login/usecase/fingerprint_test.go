package usecase

import (
	"net/netip"
	"testing"
)

func TestComputeFingerprint(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.42")
	body := DeviceFingerprintInput{
		ScreenResolution: "1920x1080",
		Timezone:         "Asia/Jakarta",
		Platform:         "Win32",
		ColorDepth:       24,
		Language:         "en-US",
	}

	got := computeFingerprint("Mozilla/5.0 (Windows NT 10.0)", "en-US,en;q=0.9", body, ip)
	want := computeFingerprint("MOZILLA/5.0 (Windows NT 10.0)  ", " en-US,en;q=0.9", body, ip)

	if got != want {
		t.Fatalf("computeFingerprint should be case/whitespace-insensitive on header components: %q != %q", got, want)
	}
	if len(got) != 64 {
		t.Fatalf("expected a 64-char lowercase hex sha256 digest, got %d chars: %q", len(got), got)
	}

	// A change in any single canonical component must change the hash.
	other := computeFingerprint("Mozilla/5.0 (Windows NT 10.0)", "en-US,en;q=0.9",
		DeviceFingerprintInput{ScreenResolution: "1280x720", Timezone: body.Timezone, Platform: body.Platform, ColorDepth: body.ColorDepth, Language: body.Language},
		ip)
	if other == got {
		t.Fatal("expected fingerprint to change when screen_resolution changes")
	}
}

func TestIPSubnet(t *testing.T) {
	tests := []struct {
		name string
		ip   netip.Addr
		want string
	}{
		{"ipv4", netip.MustParseAddr("203.0.113.42"), "203.0.113.0/24"},
		{"ipv6 unsupported", netip.MustParseAddr("2001:db8::1"), ""},
		{"invalid", netip.Addr{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipSubnet(tt.ip); got != tt.want {
				t.Errorf("ipSubnet(%v) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestInferDeviceName(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (iPhone) Mobile Safari", "Mobile Safari on iOS"},
		{"Mozilla/5.0 (Linux; Android 14) Chrome/120", "Chrome on Android"},
		{"Mozilla/5.0 (Windows NT 10.0) Chrome/120", "Chrome on Windows"},
		{"Mozilla/5.0 (X11; Linux x86_64) Firefox/120", "Firefox on Linux"},
		{"Mozilla/5.0 (Macintosh; Mac OS X 10_15) Safari/605", "Safari on macOS"},
		{"PostmanRuntime/7.36", "Postman API Client"},
		{"curl/8.0", "Unknown Browser"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := inferDeviceName(tt.ua); got != tt.want {
				t.Errorf("inferDeviceName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}
