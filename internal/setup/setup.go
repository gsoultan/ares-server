// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

// Package setup drives Ares's first-run installation: it decides whether setup
// is still needed, validates each step, and performs one atomic commit that
// provisions the datastore configuration, the master encryption key, the
// super-administrator account and the default workspace. Nothing is persisted
// before CommitSetup, and once an install is initialized the commit refuses to
// run again, so the wizard cannot be replayed to hijack a live install.
package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gsoultan/ares-server/internal/auth"
	"github.com/gsoultan/ares-server/internal/engagement"
	"github.com/gsoultan/ares-server/internal/secret"
	"github.com/gsoultan/ares-server/internal/tenant"
)

// Database drivers.
const (
	DriverFile     = "file"     // the built-in embedded datastore (Storm/bbolt)
	DriverPostgres = "postgres" // reserved; not yet a committable backend
)

// Errors.
var (
	ErrAlreadyInitialized = errors.New("setup: this install is already initialized")
	ErrDriverUnavailable  = errors.New("setup: selected database driver is not available yet")
	ErrMissingField       = errors.New("setup: a required field is missing")
	ErrTenantName         = errors.New("setup: default workspace name is required")
)

// Stable machine-readable error codes, returned alongside human messages so the
// UI can branch on a code instead of parsing prose.
const (
	CodeOK             = ""
	CodeAlreadyInit    = "already_initialized"
	CodeDriverUnavail  = "driver_unavailable"
	CodeMissingField   = "missing_field"
	CodeTenantRequired = "tenant_name_required"
	CodeWeakPassword   = "weak_password"
	CodeDBNotWritable  = "db_not_writable"
	CodeInvalidKey     = "invalid_key"
	CodeInternal       = "internal"
)

// CodeFor maps an error returned by TestDatabase or Commit to a stable code.
func CodeFor(err error) string {
	switch {
	case err == nil:
		return CodeOK
	case errors.Is(err, ErrAlreadyInitialized):
		return CodeAlreadyInit
	case errors.Is(err, ErrDriverUnavailable):
		return CodeDriverUnavail
	case errors.Is(err, ErrMissingField):
		return CodeMissingField
	case errors.Is(err, ErrTenantName):
		return CodeTenantRequired
	case errors.Is(err, auth.ErrWeakPassword):
		return CodeWeakPassword
	case errors.Is(err, errKeyInvalid):
		return CodeInvalidKey
	case errors.Is(err, errDBNotWritable):
		return CodeDBNotWritable
	default:
		return CodeInternal
	}
}

// Sentinel wrappers so CodeFor can classify path/key failures without string
// matching.
var (
	errDBNotWritable = errors.New("setup: database path not writable")
	errKeyInvalid    = errors.New("setup: supplied key invalid")
)

// DriverInfo describes a database driver and whether it can be committed now.
type DriverInfo struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Available bool   `json:"available"`
	Note      string `json:"note,omitempty"`
}

// AvailableDrivers reports the datastore drivers the server supports, with the
// built-in file store as the committable default. The running server actually
// chooses its backend at start (via ARES_DB / ARES_PG_URL), not in the wizard,
// so an initialized Service reports the live backend through driversFor; this
// free function is the fallback used only when no setup service is wired.
func AvailableDrivers() []DriverInfo { return driversFor(DriverFile) }

// driversFor builds the driver list for a running server whose active backend is
// `active`. The active backend is the committable one; the other is shown for
// context but cannot be selected, because the datastore is fixed at start.
func driversFor(active string) []DriverInfo {
	if active == "" {
		active = DriverFile
	}
	file := DriverInfo{Name: DriverFile, Label: "Built-in (embedded file)", Available: active == DriverFile}
	pg := DriverInfo{Name: DriverPostgres, Label: "PostgreSQL", Available: active == DriverPostgres}
	switch active {
	case DriverPostgres:
		file.Note = "Not active — the server is running on PostgreSQL."
		pg.Note = "Active backend (chosen at server start)."
	default:
		pg.Note = "Not active — start the server with ARES_PG_URL to run on PostgreSQL."
		file.Note = "Active backend (chosen at server start)."
	}
	return []DriverInfo{file, pg}
}

// Config is the persisted first-run configuration and initialization marker.
type Config struct {
	Initialized   bool      `json:"initialized"`
	InitializedAt time.Time `json:"initializedAt"`
	DBDriver      string    `json:"dbDriver"`
	DBPath        string    `json:"dbPath"`
}

// Store persists the setup config singleton.
type Store interface {
	GetConfig() (Config, bool, error)
	PutConfig(Config) error
}

// State is the current setup status for the UI.
type State struct {
	Needed        bool         `json:"needed"`
	Initialized   bool         `json:"initialized"`
	InitializedAt time.Time    `json:"initializedAt,omitempty"`
	Drivers       []DriverInfo `json:"drivers"`
	// DBPath and KeyFilePath are the locations the running server is actually
	// using, so the wizard can show them read-only (the server has already opened
	// the store and will read the key from here; a different path typed in the
	// wizard does not move them).
	DBPath      string `json:"dbPath"`
	KeyFilePath string `json:"keyFilePath"`
}

// AdminInput is the super-administrator to create.
type AdminInput struct {
	Name     string
	Email    string
	Password string
}

// CommitRequest is the single atomic setup submission.
type CommitRequest struct {
	DBDriver string
	DBPath   string
	// GenerateKey asks the server to generate the master key (returned once).
	// When false, Key must carry a base64 32-byte key the operator supplied.
	GenerateKey bool
	Key         string
	Admin       AdminInput
	TenantName  string
}

// CommitResult reports the outcome. GeneratedKey is the base64 master key, set
// only when the server generated it — shown to the operator exactly once.
type CommitResult struct {
	GeneratedKey  string
	InitializedAt time.Time
	TenantID      string
	AdminUserID   string
}

// Service performs setup over the setup store, the auth service, the engagement
// store (to name the default workspace) and the key file.
type Service struct {
	store   Store
	auth    *auth.Service
	tenants engagement.Store
	dbPath  string
	keyPath string
	// activeDriver is the backend the running server actually opened at start
	// (file or postgres). It is the only committable driver, since the datastore
	// is chosen at boot, not in the wizard. Empty means the file driver.
	activeDriver string
	// onKey is invoked with the master key after a successful commit, so the
	// server can bring the settings store online without a restart.
	onKey func([]byte)
}

// WithActiveDriver records which backend the running server opened at start, so
// the wizard reports and commits against the live datastore. It returns the
// service for chaining and defaults to the file driver when d is empty.
func (s *Service) WithActiveDriver(d string) *Service {
	s.activeDriver = d
	return s
}

// active returns the effective active driver, defaulting to the file backend.
func (s *Service) active() string {
	if s.activeDriver == "" {
		return DriverFile
	}
	return s.activeDriver
}

// NewService builds a setup service. dbPath and keyPath are the locations the
// running server is using (reported read-only to the wizard); keyPath is where
// the sealed master key file is written. onKey (optional) is called with the key
// after a successful commit.
func NewService(store Store, authSvc *auth.Service, tenants engagement.Store, dbPath, keyPath string, onKey func([]byte)) *Service {
	if keyPath == "" {
		keyPath = "ares.key"
	}
	return &Service{store: store, auth: authSvc, tenants: tenants, dbPath: dbPath, keyPath: keyPath, onKey: onKey}
}

// Status reports whether setup is still needed. Setup is needed when the install
// is not yet marked initialized and no account exists, so a fresh deployment is
// gated to the wizard and an initialized one refuses it.
func (s *Service) Status() (State, error) {
	cfg, _, err := s.store.GetConfig()
	if err != nil {
		return State{}, err
	}
	st := State{Initialized: cfg.Initialized, Drivers: driversFor(s.active()), DBPath: s.dbPath, KeyFilePath: s.keyPath}
	if cfg.Initialized {
		st.InitializedAt = cfg.InitializedAt
		st.Needed = false
		return st, nil
	}
	n, err := s.auth.CountUsers()
	if err != nil {
		return State{}, err
	}
	st.Needed = n == 0
	return st, nil
}

// TestDatabase validates a database configuration without committing. For the
// file driver it confirms the target directory exists and is writable; the
// Postgres backend is not yet available.
func (s *Service) TestDatabase(driver, path string) error {
	if driver == "" {
		driver = s.active()
	}
	// The datastore is opened at server start; the wizard can only test the live
	// backend. A different driver is not selectable here.
	if driver != s.active() {
		return ErrDriverUnavailable
	}
	switch driver {
	case DriverFile:
		return testFilePath(path)
	case DriverPostgres:
		// The server already connected to Postgres at start; reaching this service
		// means the pool is live, so the connection is good.
		return nil
	default:
		return fmt.Errorf("setup: unknown driver %q", driver)
	}
}

// testFilePath checks that the datastore file's directory is writable.
func testFilePath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%w: database file path is required", errDBNotWritable)
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: directory not accessible: %w", errDBNotWritable, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %q is not a directory", errDBNotWritable, dir)
	}
	// Probe writability with a temp file we immediately remove.
	f, err := os.CreateTemp(dir, ".ares-write-probe-*")
	if err != nil {
		return fmt.Errorf("%w: %w", errDBNotWritable, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}

// Commit performs the one-shot, atomic-as-possible provisioning. It refuses to
// run on an already-initialized install.
func (s *Service) Commit(req CommitRequest) (CommitResult, error) {
	// Guard: never re-provision an initialized install.
	cfg, _, err := s.store.GetConfig()
	if err != nil {
		return CommitResult{}, err
	}
	if cfg.Initialized {
		return CommitResult{}, ErrAlreadyInitialized
	}
	if n, err := s.auth.CountUsers(); err != nil {
		return CommitResult{}, err
	} else if n > 0 {
		// An account already exists; treat as initialized to prevent takeover.
		return CommitResult{}, ErrAlreadyInitialized
	}

	// Validate every input before persisting anything. The backend is fixed at
	// server start, so the only committable driver is the live one.
	driver := req.DBDriver
	if driver == "" {
		driver = s.active()
	}
	if driver != s.active() {
		return CommitResult{}, ErrDriverUnavailable
	}
	// The file backend needs a writable path; Postgres is already connected, so
	// its DBPath carries the DSN only for the record.
	if driver == DriverFile {
		if err := testFilePath(req.DBPath); err != nil {
			return CommitResult{}, err
		}
	}
	if strings.TrimSpace(req.Admin.Name) == "" || auth.NormalizeEmail(req.Admin.Email) == "" {
		return CommitResult{}, ErrMissingField
	}
	if len(req.Admin.Password) < auth.MinPasswordLen {
		return CommitResult{}, auth.ErrWeakPassword
	}
	if strings.TrimSpace(req.TenantName) == "" {
		return CommitResult{}, ErrTenantName
	}

	// Resolve the master key (generate or accept a supplied one).
	var key []byte
	var generated string
	if req.GenerateKey {
		key, err = secret.NewKey()
		if err != nil {
			return CommitResult{}, err
		}
		generated = secret.EncodeKey(key)
	} else {
		key, err = secret.DecodeKey(req.Key)
		if err != nil {
			return CommitResult{}, fmt.Errorf("%w: %w", errKeyInvalid, err)
		}
	}

	// Persist, in an order that makes re-entry safe: the key file is written
	// exclusively first (it refuses to overwrite, so a second attempt stops
	// here), then the super-admin, the workspace name, and finally the marker.
	if err := secret.SaveKeyFile(s.keyPath, key); err != nil {
		return CommitResult{}, fmt.Errorf("setup: save master key: %w", err)
	}
	admin, err := s.auth.CreateUser(tenant.DefaultID, req.Admin.Email, req.Admin.Name, req.Admin.Password, auth.RoleSuperAdmin)
	if err != nil {
		return CommitResult{}, fmt.Errorf("setup: create super-admin: %w", err)
	}
	if err := s.tenants.SetTenantName(tenant.DefaultID, req.TenantName); err != nil {
		return CommitResult{}, fmt.Errorf("setup: name default workspace: %w", err)
	}
	now := time.Now().UTC()
	if err := s.store.PutConfig(Config{Initialized: true, InitializedAt: now, DBDriver: driver, DBPath: req.DBPath}); err != nil {
		return CommitResult{}, fmt.Errorf("setup: write marker: %w", err)
	}

	// Bring the settings store online with the new key, without a restart.
	if s.onKey != nil {
		s.onKey(key)
	}

	return CommitResult{
		GeneratedKey:  generated,
		InitializedAt: now,
		TenantID:      tenant.DefaultID,
		AdminUserID:   admin.ID,
	}, nil
}

// MemStore is an in-memory setup.Store for tests and ephemeral runs.
type MemStore struct {
	cfg Config
	set bool
}

// NewMemStore builds an empty in-memory setup store.
func NewMemStore() *MemStore { return &MemStore{} }

// GetConfig implements Store.
func (m *MemStore) GetConfig() (Config, bool, error) { return m.cfg, m.set, nil }

// PutConfig implements Store.
func (m *MemStore) PutConfig(c Config) error {
	m.cfg = c
	m.set = true
	return nil
}
