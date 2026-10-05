// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package readiness_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Bugs5382/go-rabbitmq"
	redis "github.com/Bugs5382/go-redis"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Steward-GRC/steward-identity/internal/readiness"
)

func startPostgres(t *testing.T) (testcontainers.Container, *postgres.DB) {
	t.Helper()
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("identity"), tcpostgres.WithUsername("identity"), tcpostgres.WithPassword("identity"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	dsn, err := c.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := postgres.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(db.Close)
	return c, db
}

func startRabbitMQ(t *testing.T) (testcontainers.Container, *rabbitmq.Conn) {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "rabbitmq:3-alpine", ExposedPorts: []string{"5672/tcp"},
			WaitingFor: wait.ForListeningPort("5672/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = testcontainers.TerminateContainer(c) })
	host, err := c.Host(ctx)
	require.NoError(t, err)
	port, err := c.MappedPort(ctx, "5672/tcp")
	require.NoError(t, err)
	var conn *rabbitmq.Conn
	require.Eventually(t, func() bool {
		conn, err = rabbitmq.Connect(ctx, fmt.Sprintf("amqp://guest:guest@%s:%s/", host, port.Port()))
		return err == nil
	}, 60*time.Second, time.Second, "rabbitmq accepts connections")
	t.Cleanup(func() { _ = conn.Close() })
	return c, conn
}

func stop(t *testing.T, c testcontainers.Container) {
	t.Helper()
	timeout := 5 * time.Second
	require.NoError(t, c.Stop(context.Background(), &timeout))
}

func reportOf(c *health.Checker) health.Report { return c.Report(context.Background()) }

func TestStoppingEachDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Docker")
	}
	pgC, db := startPostgres(t)
	mqC, conn := startRabbitMQ(t)
	mr := miniredis.RunT(t)
	rc, err := redis.Connect(context.Background(), redis.WithAddr(mr.Addr()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = rc.Close() })
	kratos, _ := fakeOry(t, "/admin/health/ready", "/admin/version", "v1.3.1")
	polis, _ := fakeOry(t, "/api/health", "/api/health", "1.52.0")

	c, err := readiness.New(readiness.Deps{
		Postgres: readiness.PostgresDB(db), Broker: conn,
		Cache:          func(ctx context.Context) error { return rc.Redis().Ping(ctx).Err() },
		KratosAdminURL: kratos.URL, PolisURL: polis.URL,
	}, health.WithTTL(time.Millisecond), health.WithTimeout(2*time.Second))
	require.NoError(t, err)
	r := reportOf(c)
	require.True(t, r.Ready)
	require.Equal(t, health.StateOK, r.Status)
	require.Regexp(t, `^16\.\d+$`, dep(t, r, readiness.Postgres).Version)

	degradedOnly := func(t *testing.T, name string) {
		t.Helper()
		require.Eventually(t, func() bool { return dep(t, reportOf(c), name).State == health.StateDegraded }, 30*time.Second, 100*time.Millisecond)
		require.True(t, reportOf(c).Ready, "%s is optional", name)
	}
	t.Run("valkey", func(t *testing.T) {
		mr.Close()
		degradedOnly(t, readiness.Valkey)
	})
	t.Run("kratos", func(t *testing.T) {
		kratos.Close()
		degradedOnly(t, readiness.Kratos)
	})
	t.Run("polis", func(t *testing.T) {
		polis.Close()
		degradedOnly(t, readiness.Polis)
	})
	t.Run("rabbitmq", func(t *testing.T) {
		stop(t, mqC)
		degradedOnly(t, readiness.RabbitMQ)
	})
	t.Run("postgres", func(t *testing.T) {
		stop(t, pgC)
		require.Eventually(t, func() bool { return dep(t, reportOf(c), readiness.Postgres).State == health.StateDown }, 30*time.Second, 100*time.Millisecond)
		require.False(t, reportOf(c).Ready)
	})
}
