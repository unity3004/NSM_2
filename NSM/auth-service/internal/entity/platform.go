package entity

import "time"

// PlatformBootstrapStatus mirrors the platform_bootstrap_status Postgres
// enum. See migrations/000020_create_platform_bootstrap_table.up.sql for
// why this is tracked in its own singleton row rather than derived from
// "does any user exist."
type PlatformBootstrapStatus string

const (
	PlatformUninitialized PlatformBootstrapStatus = "uninitialized"
	PlatformInitializing  PlatformBootstrapStatus = "initializing"
	PlatformInitialized   PlatformBootstrapStatus = "initialized"
)

// PlatformBootstrap is the one row in platform_bootstrap.
type PlatformBootstrap struct {
	Status        PlatformBootstrapStatus
	InitializedBy *string
	InitializedAt *time.Time
}
