// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	outbox "github.com/Bugs5382/go-outbox"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Steward-GRC/steward-identity/internal/store"
)

var (
	dbsMu sync.Mutex
	dbs   = map[*pgxpool.Pool]*postgres.DB{}
)

// newTestStore returns a Store on a freshly migrated test database.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	return newStoreFor(t, newTestDB(t))
}

// newStoreFor returns a Store on the database newTestDB returned pool for.
func newStoreFor(t *testing.T, pool *pgxpool.Pool) *store.Store {
	t.Helper()
	dbsMu.Lock()
	db := dbs[pool]
	dbsMu.Unlock()
	if db == nil {
		t.Fatal("newStoreFor: pool did not come from newTestDB")
	}
	ob, err := outbox.New(outbox.WithTable(store.AuditTable))
	if err != nil {
		t.Fatalf("outbox: %v", err)
	}
	return store.New(db, ob)
}

// newTestDB returns the pool of a fresh, migrated database for the calling
// test, on DATABASE_TEST_DSN when it is set, otherwise on a throwaway
// testcontainers Postgres.
func newTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("DATABASE_TEST_DSN")
	if base == "" {
		base = sharedContainer(t)
	}
	dsn := newDatabase(t, base)
	ctx := context.Background()
	migrationsDir, err := filepath.Abs("../../migrations")
	if err != nil {
		t.Fatalf("resolve migrations dir: %v", err)
	}
	if err := postgres.Migrate(dsn, migrationsDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("postgres.New: %v", err)
	}
	ob, err := outbox.New(outbox.WithTable(store.AuditTable))
	if err != nil {
		t.Fatalf("outbox: %v", err)
	}
	if err := ob.Migrate(ctx, db); err != nil {
		t.Fatalf("outbox migrate: %v", err)
	}
	t.Cleanup(db.Close)
	dbsMu.Lock()
	dbs[db.Pool()] = db
	dbsMu.Unlock()
	return db.Pool()
}

func newDatabase(t *testing.T, baseDSN string) string {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	defer admin.Close()
	dbName := uniqueDBName()
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %q`, dbName)); err != nil {
		t.Fatalf("create db %s: %v", dbName, err)
	}
	u, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse base dsn: %v", err)
	}
	u.Path = "/" + dbName
	t.Cleanup(func() {
		dropCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dropAdmin, err := pgxpool.New(dropCtx, baseDSN)
		if err != nil {
			return
		}
		defer dropAdmin.Close()
		_, _ = dropAdmin.Exec(dropCtx, fmt.Sprintf(`DROP DATABASE %q WITH (FORCE)`, dbName))
	})
	return u.String()
}

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// sharedContainer starts one throwaway Postgres for the whole test binary;
// each test still gets a database of its own. The testcontainers reaper
// removes it when the binary exits.
func sharedContainer(t *testing.T) string {
	t.Helper()
	containerOnce.Do(func() {
		ctx := context.Background()
		container, err := tcpostgres.Run(ctx, "postgres:16",
			tcpostgres.WithDatabase("identity_test"),
			tcpostgres.WithUsername("test"),
			tcpostgres.WithPassword("test"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(60*time.Second),
			),
		)
		if err != nil {
			containerErr = err
			return
		}
		containerDSN, containerErr = container.ConnectionString(ctx, "sslmode=disable")
	})
	if containerErr != nil {
		t.Fatalf("start postgres container: %v", containerErr)
	}
	return containerDSN
}

func uniqueDBName() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "test_" + hex.EncodeToString(b[:])
}

// auditEvents returns the pending audit events of eventType, oldest first.
func auditEvents(t *testing.T, pool *pgxpool.Pool, eventType string) []store.AuditEvent {
	t.Helper()
	all, err := newStoreFor(t, pool).PendingAuditEvents(context.Background(), 100000)
	if err != nil {
		t.Fatalf("pending audit: %v", err)
	}
	var out []store.AuditEvent
	for _, e := range all {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}
