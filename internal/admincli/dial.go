// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package admincli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	grpcactor "github.com/Bugs5382/go-grpc-actor"
	gootel "github.com/Bugs5382/go-otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// AdminDialer returns an IdentityAdminService client and its cleanup.
type AdminDialer func(ctx context.Context, opt rootCommandOptions) (identityv1.IdentityAdminServiceClient, func(), error)

// ReadDialer returns an IdentityReadService client and its cleanup.
type ReadDialer func(ctx context.Context, opt rootCommandOptions) (identityv1.IdentityReadServiceClient, func(), error)

const (
	envIdentityGRPCAddr = "IDENTITY_GRPC_ADDR"
	envCertDir          = "IDENTITY_ADMIN_CERT_DIR"
	envCAFile           = "IDENTITY_ADMIN_CA_FILE"
	// envInsecure is for local development only.
	envInsecure = "IDENTITY_INSECURE"

	defaultIdentityAddr = "identity:9090"
	defaultCertDir      = "/var/run/identity-admin-cert"
	certFileName        = "tls.crt"
	keyFileName         = "tls.key"
	caFileName          = "ca.crt"
)

func productionDialAdmin(_ context.Context, opt rootCommandOptions) (identityv1.IdentityAdminServiceClient, func(), error) {
	conn, err := dialIdentity(opt)
	if err != nil {
		return nil, nil, err
	}
	return identityv1.NewIdentityAdminServiceClient(conn), func() { _ = conn.Close() }, nil
}

func productionDialRead(_ context.Context, opt rootCommandOptions) (identityv1.IdentityReadServiceClient, func(), error) {
	conn, err := dialIdentity(opt)
	if err != nil {
		return nil, nil, err
	}
	return identityv1.NewIdentityReadServiceClient(conn), func() { _ = conn.Close() }, nil
}

func dialIdentity(opt rootCommandOptions) (*grpc.ClientConn, error) {
	addr := opt.envLookup(envIdentityGRPCAddr)
	if addr == "" {
		addr = defaultIdentityAddr
	}
	creds, err := transportCredentials(opt)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(creds),
		grpc.WithStatsHandler(gootel.GRPCClientStatsHandler()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return conn, nil
}

func transportCredentials(opt rootCommandOptions) (credentials.TransportCredentials, error) {
	if opt.envLookup(envInsecure) == "1" {
		return insecure.NewCredentials(), nil
	}
	cfg, err := loadTLSConfig(opt)
	if err != nil {
		return nil, fmt.Errorf("load admin mTLS: %w", err)
	}
	return credentials.NewTLS(cfg), nil
}

// loadTLSConfig reads the client certificate, key and CA from the cert
// directory; IDENTITY_ADMIN_CA_FILE moves the CA elsewhere.
func loadTLSConfig(opt rootCommandOptions) (*tls.Config, error) {
	dir := opt.envLookup(envCertDir)
	if dir == "" {
		dir = defaultCertDir
	}
	certFile, keyFile := filepath.Join(dir, certFileName), filepath.Join(dir, keyFileName)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair (%s, %s): %w", certFile, keyFile, err)
	}
	caFile := opt.envLookup(envCAFile)
	if caFile == "" {
		caFile = filepath.Join(dir, caFileName)
	}
	caBytes, err := os.ReadFile(caFile) // #nosec G304 -- the path is operator configuration
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("CA file did not contain a valid PEM certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}
