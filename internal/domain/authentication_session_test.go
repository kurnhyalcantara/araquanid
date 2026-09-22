package domain

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)

func newTestSession(t *testing.T) *AuthenticationSession {
	t.Helper()
	s, err := NewAuthenticationSession(NewSessionParams{
		ID:          "sess-1",
		Identity:    "identity-1",
		Device:      "dev-1",
		AAL:         AAL2,
		FactorsUsed: []FactorType{FactorTOTP},
		Client:      ClientInfo{IP: netip.MustParseAddr("203.0.113.42"), UserAgent: "ua"},
		Policy:      DefaultSessionPolicy(),
		Now:         t0,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationSession: %v", err)
	}
	return s
}

func TestNewAuthenticationSession(t *testing.T) {
	s := newTestSession(t)

	if s.Status() != SessionStatusActive || !s.IsActive(t0) {
		t.Fatalf("new session must be ACTIVE, got %s", s.Status())
	}
	if got, want := s.AbsoluteExpiresAt(), t0.Add(8*time.Hour); !got.Equal(want) {
		t.Errorf("AbsoluteExpiresAt = %v, want %v", got, want)
	}
	if got, want := s.IdleExpiresAt(), t0.Add(15*time.Minute); !got.Equal(want) {
		t.Errorf("IdleExpiresAt = %v, want %v", got, want)
	}

	ev := s.PullEvents()
	if len(ev) != 1 {
		t.Fatalf("want 1 event, got %d", len(ev))
	}
	if _, ok := ev[0].(SessionCreated); !ok {
		t.Errorf("want SessionCreated, got %T", ev[0])
	}
	if len(s.PullEvents()) != 0 {
		t.Error("PullEvents must clear recorded events")
	}
}

func TestNewAuthenticationSession_Validation(t *testing.T) {
	valid := NewSessionParams{
		ID: "sess-1", Identity: "identity-1", AAL: AAL1,
		Client: ClientInfo{IP: netip.MustParseAddr("10.0.0.1")},
		Policy: DefaultSessionPolicy(), Now: t0,
	}
	tests := []struct {
		name    string
		mutate  func(*NewSessionParams)
		wantErr error
	}{
		{"missing id", func(p *NewSessionParams) { p.ID = "" }, ErrInvalidSession},
		{"missing identity", func(p *NewSessionParams) { p.Identity = "" }, ErrInvalidSession},
		{"unknown aal", func(p *NewSessionParams) { p.AAL = "AAL9" }, ErrInvalidSession},
		{"missing ip", func(p *NewSessionParams) { p.Client.IP = netip.Addr{} }, ErrInvalidSession},
		{"zero time", func(p *NewSessionParams) { p.Now = time.Time{} }, ErrInvalidSession},
		{"idle > absolute", func(p *NewSessionParams) {
			p.Policy = SessionPolicy{IdleTimeout: 9 * time.Hour, AbsoluteLifetime: 8 * time.Hour}
		}, ErrInvalidSessionPolicy},
		{"AAL1 with factors", func(p *NewSessionParams) { p.FactorsUsed = []FactorType{FactorTOTP} }, ErrAALFactorMismatch},
		{"AAL2 without factors", func(p *NewSessionParams) { p.AAL = AAL2 }, ErrAALFactorMismatch},
		{"AAL3 without FIDO2", func(p *NewSessionParams) {
			p.AAL, p.FactorsUsed = AAL3, []FactorType{FactorTOTP}
		}, ErrAALFactorMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid
			tt.mutate(&p)
			if _, err := NewAuthenticationSession(p); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestTouch_ResetsIdleTimer(t *testing.T) {
	s := newTestSession(t)
	now := t0.Add(10 * time.Minute)

	if err := s.Touch(now); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if !s.LastActivityAt().Equal(now) {
		t.Errorf("LastActivityAt = %v, want %v", s.LastActivityAt(), now)
	}
	if !s.IsActive(t0.Add(20 * time.Minute)) {
		t.Error("session must stay active within the reset idle window")
	}

	// Clock skew must never move the idle timer backwards.
	if err := s.Touch(t0.Add(5 * time.Minute)); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if !s.LastActivityAt().Equal(now) {
		t.Error("LastActivityAt moved backwards")
	}
}

func TestExpiry(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(*AuthenticationSession)
		checkAt    time.Time
		wantReason RevokeReason
		wantAt     time.Time
	}{
		{
			name:       "idle",
			prepare:    func(*AuthenticationSession) {},
			checkAt:    t0.Add(20 * time.Minute),
			wantReason: ReasonExpiredIdle,
			wantAt:     t0.Add(15 * time.Minute),
		},
		{
			name: "absolute despite activity",
			prepare: func(s *AuthenticationSession) {
				for m := 10; m < 8*60; m += 10 {
					_ = s.Touch(t0.Add(time.Duration(m) * time.Minute))
				}
			},
			checkAt:    t0.Add(8*time.Hour + time.Minute),
			wantReason: ReasonExpiredAbsolute,
			wantAt:     t0.Add(8 * time.Hour),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSession(t)
			tt.prepare(s)
			s.PullEvents()

			if s.IsActive(tt.checkAt) {
				t.Fatal("IsActive must be false once a timeout elapsed")
			}
			if err := s.Touch(tt.checkAt); !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("Touch err = %v, want ErrSessionExpired", err)
			}
			if s.Status() != SessionStatusExpired || s.RevokeReason() != tt.wantReason {
				t.Errorf("status/reason = %s/%s, want EXPIRED/%s", s.Status(), s.RevokeReason(), tt.wantReason)
			}
			if !s.RevokedAt().Equal(tt.wantAt) {
				t.Errorf("RevokedAt = %v, want exact expiry %v", s.RevokedAt(), tt.wantAt)
			}
			ev := s.PullEvents()
			if len(ev) != 1 {
				t.Fatalf("want 1 event, got %d", len(ev))
			}
			if e, ok := ev[0].(SessionRevoked); !ok || e.Reason != tt.wantReason || e.RevokedBy != "" {
				t.Errorf("unexpected event %#v", ev[0])
			}
		})
	}
}

func TestEnforceExpiry_OnlyOnce(t *testing.T) {
	s := newTestSession(t)
	late := t0.Add(time.Hour)

	if !s.EnforceExpiry(late) {
		t.Fatal("first EnforceExpiry must transition")
	}
	if s.EnforceExpiry(late) {
		t.Error("second EnforceExpiry must be a no-op")
	}
	if s.EnforceExpiry(t0) {
		t.Error("EnforceExpiry on active window must not transition")
	}
}

func TestRevoke(t *testing.T) {
	s := newTestSession(t)
	s.PullEvents()
	now := t0.Add(5 * time.Minute)

	if err := s.Revoke(ReasonUserLogout, "identity-1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if s.Status() != SessionStatusRevoked || s.IsActive(now) {
		t.Fatalf("status = %s, want REVOKED", s.Status())
	}
	ev := s.PullEvents()
	if e, ok := ev[0].(SessionRevoked); !ok || e.Reason != ReasonUserLogout || e.RevokedBy != "identity-1" {
		t.Errorf("unexpected event %#v", ev[0])
	}
	if got := ev[0].EventType(); got != "auth.SessionRevoked" {
		t.Errorf("EventType = %q, want auth.SessionRevoked", got)
	}

	// A revoked session can never be reactivated or revoked again.
	if err := s.Touch(now); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("Touch err = %v, want ErrSessionRevoked", err)
	}
	if err := s.Revoke(ReasonAdminForceLogout, "admin", now); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("Revoke err = %v, want ErrSessionRevoked", err)
	}
	if len(s.PullEvents()) != 0 {
		t.Error("rejected commands must not record events")
	}
}

func TestRevoke_RejectsExpiryReason(t *testing.T) {
	s := newTestSession(t)
	if err := s.Revoke(ReasonExpiredIdle, "identity-1", t0); !errors.Is(err, ErrInvalidRevokeReason) {
		t.Errorf("err = %v, want ErrInvalidRevokeReason", err)
	}
	if s.Status() != SessionStatusActive {
		t.Error("session must remain ACTIVE")
	}
}

func TestRevoke_AfterExpiry(t *testing.T) {
	s := newTestSession(t)
	if err := s.Revoke(ReasonUserLogout, "identity-1", t0.Add(time.Hour)); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("err = %v, want ErrSessionExpired", err)
	}
	if s.Status() != SessionStatusExpired || s.RevokeReason() != ReasonExpiredIdle {
		t.Errorf("status/reason = %s/%s, want EXPIRED/%s", s.Status(), s.RevokeReason(), ReasonExpiredIdle)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	s := newTestSession(t)
	_ = s.Revoke(ReasonPasswordChanged, "identity-1", t0.Add(time.Minute))

	got, err := RehydrateSession(s.Snapshot())
	if err != nil {
		t.Fatalf("RehydrateSession: %v", err)
	}
	if got.Status() != SessionStatusRevoked || !got.RevokedAt().Equal(*s.RevokedAt()) {
		t.Errorf("round trip mismatch: %#v", got.Snapshot())
	}
	if len(got.PullEvents()) != 0 {
		t.Error("rehydration must not record events")
	}
}

func TestRehydrateSession_RejectsInconsistentState(t *testing.T) {
	revokedAt := t0.Add(time.Minute)
	base := newTestSession(t).Snapshot()

	tests := []struct {
		name   string
		mutate func(*SessionSnapshot)
	}{
		{"active with revoked_at", func(s *SessionSnapshot) { s.RevokedAt = &revokedAt }},
		{"revoked without revoked_at", func(s *SessionSnapshot) {
			s.Status, s.RevokeReason = SessionStatusRevoked, ReasonUserLogout
		}},
		{"revoked with expiry reason", func(s *SessionSnapshot) {
			s.Status, s.RevokedAt, s.RevokeReason = SessionStatusRevoked, &revokedAt, ReasonExpiredIdle
		}},
		{"expired with manual reason", func(s *SessionSnapshot) {
			s.Status, s.RevokedAt, s.RevokeReason = SessionStatusExpired, &revokedAt, ReasonUserLogout
		}},
		{"unknown status", func(s *SessionSnapshot) { s.Status = "PAUSED" }},
		{"aal/factor mismatch", func(s *SessionSnapshot) { s.FactorsUsed = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := base
			tt.mutate(&snap)
			if _, err := RehydrateSession(snap); err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}
