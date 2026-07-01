// Package domain holds the core business entities and rules. It is pure:
// stdlib and other domain packages only — no transport, infrastructure, or
// framework imports.
package domain

import (
	"errors"
	"time"
)

// ErrNotFound is returned by repositories when an example does not exist.
var ErrNotFound = errors.New("example not found")

// Example is the reference domain entity.
type Example struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Update applies new field values and stamps the update time.
func (e *Example) Update(name, description string, now time.Time) {
	e.Name = name
	e.Description = description
	e.UpdatedAt = now
}
