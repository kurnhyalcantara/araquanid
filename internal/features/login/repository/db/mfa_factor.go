package db

import (
	"context"
	"fmt"

	"github.com/kurnhyalcantara/araquanid/internal/domain"
)

// ListActiveFactorTypes returns the distinct ACTIVE MFA factor types
// enrolled for identityID (FR-LOGIN-010's available_factors). Unrecognized
// stored values are skipped defensively rather than failing the login.
func (p *Postgres) ListActiveFactorTypes(ctx context.Context, identityID string) ([]domain.FactorType, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT DISTINCT factor_type FROM mfa_factors WHERE identity_id = $1 AND status = 'ACTIVE'`, identityID)
	if err != nil {
		return nil, fmt.Errorf("login/db: list active factor types: %w", err)
	}
	defer rows.Close()

	var factors []domain.FactorType
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("login/db: scan factor type: %w", err)
		}
		if ft, ok := toDomainFactorType(raw); ok {
			factors = append(factors, ft)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("login/db: list active factor types rows: %w", err)
	}
	return factors, nil
}

// HasActiveFactor reports whether identityID has voluntarily enrolled at
// least one ACTIVE MFA factor (BR-003).
func (p *Postgres) HasActiveFactor(ctx context.Context, identityID string) (bool, error) {
	var exists bool
	err := p.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM mfa_factors WHERE identity_id = $1 AND status = 'ACTIVE')`, identityID).
		Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("login/db: has active factor: %w", err)
	}
	return exists, nil
}

func toDomainFactorType(raw string) (domain.FactorType, bool) {
	switch domain.FactorType(raw) {
	case domain.FactorTOTP, domain.FactorSMSOTP, domain.FactorFIDO2, domain.FactorPasskey:
		return domain.FactorType(raw), true
	default:
		return "", false
	}
}
