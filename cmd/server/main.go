// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Command server runs the identity service: users, groups, roles, second
// factors and SSO connections over gRPC. Sign-in is Ory only: Kratos for local
// accounts and sessions, Polis for SAML and OIDC. It calls steward-core for
// merge and the delete checks, and publishes steward-audit's AuditEvent
// through a transactional outbox.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	goemail "github.com/Bugs5382/go-email"
	emailsmtp "github.com/Bugs5382/go-email/smtp"
	grpcactor "github.com/Bugs5382/go-grpc-actor"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	outbox "github.com/Bugs5382/go-outbox"
	outboxrabbitmq "github.com/Bugs5382/go-outbox/rabbitmq"
	postgres "github.com/Bugs5382/go-postgres"
	pgotel "github.com/Bugs5382/go-postgres/otel"
	"github.com/Bugs5382/go-rabbitmq"
	rmqotel "github.com/Bugs5382/go-rabbitmq/otel"
	redis "github.com/Bugs5382/go-redis"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	corev1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/core/v1"
	obligationsv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/obligations/v1"
	workflowv1 "github.com/Steward-GRC/steward-identity/gen/go/thirdparty/workflow/v1"
	"github.com/Steward-GRC/steward-identity/internal/cache"
	"github.com/Steward-GRC/steward-identity/internal/config"
	"github.com/Steward-GRC/steward-identity/internal/email"
	"github.com/Steward-GRC/steward-identity/internal/handlers"
	"github.com/Steward-GRC/steward-identity/internal/merge"
	"github.com/Steward-GRC/steward-identity/internal/readiness"
	"github.com/Steward-GRC/steward-identity/internal/secrets"
	"github.com/Steward-GRC/steward-identity/internal/server"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/userdelete"
	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

const serviceName = "identity"

// auditExchange is the topic exchange steward-audit consumes from.
const auditExchange = "audit"

// jwksRecheck is how long a good key-set check is kept before readiness
// fetches the key set again.
const jwksRecheck = 30 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := log.NewLogger(serviceName)
	if err := run(ctx, logger); err != nil {
		logger.Fatal(err, "identity service stopped")
	}
}

func run(ctx context.Context, logger log.Logger) error {
	bi := buildinfo.Get()
	logger.Info("starting", log.F("version", bi.Version), log.F("commit", bi.Commit), log.F("go_version", bi.GoVersion))
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	zl := log.New(serviceName)

	otelShutdown, err := gootel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		return fmt.Errorf("otel: %w", err)
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn("otel shutdown", log.F("error", err.Error()))
		}
	}()

	if err := pgotel.InstrumentMigrate(ctx, serviceName, func() error {
		return postgres.Migrate(cfg.MigrateDSN, cfg.MigrationsDir)
	}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN, pgotel.WithTracing())
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()
	ob, err := outbox.New(outbox.WithTable(store.AuditTable), outbox.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("outbox: %w", err)
	}
	if err := ob.Migrate(ctx, db); err != nil {
		return fmt.Errorf("outbox migrate: %w", err)
	}
	s := store.New(db, ob)

	conn, err := rabbitmq.Connect(ctx, cfg.RabbitURL, append(rmqotel.Instrument(), rabbitmq.WithLogger(rabbitLogger{logger}))...)
	if err != nil {
		return fmt.Errorf("rabbitmq: %w", err)
	}
	defer func() { _ = conn.Close() }()
	relay := ob.NewRelay(db, outboxrabbitmq.New(conn, auditExchange,
		rabbitmq.WithExchangeDeclare(rabbitmq.ExchangeConfig{Name: auditExchange, Kind: "topic", Durable: true})))
	relayDone := make(chan error, 1)
	go func() { relayDone <- relay.Run(ctx) }()
	jobsPub := publisher{conn.NewPublisher("jobs", rabbitmq.WithExchangeDeclare(rabbitmq.ExchangeConfig{Name: "jobs", Kind: "topic", Durable: true}))}
	ssoEvents := handlers.NewSSOEventEmitter(jobsPub)

	deps := readiness.Deps{Postgres: readiness.PostgresDB(db), Broker: conn, KratosAdminURL: cfg.KratosAdminURL, PolisURL: cfg.Polis.AdminURL}
	if cfg.RedisAddr != "" {
		rc, err := redis.Connect(ctx, redis.WithAddr(cfg.RedisAddr), redis.WithPassword(cfg.RedisPassword),
			redis.WithTimeouts(300*time.Millisecond, 200*time.Millisecond, 200*time.Millisecond))
		if err != nil {
			logger.Warn("redis unreachable: the group cache is off", log.F("error", err.Error()))
			bootErr := err
			deps.Cache = func(context.Context) error { return bootErr }
		} else {
			defer func() { _ = rc.Close() }()
			deps.Cache = func(ctx context.Context) error { return rc.Redis().Ping(ctx).Err() }
			s.WithIdpGroupCache(cache.New(rc, cfg.IdpGroupsCacheTTL))
		}
	}

	mailer := email.New(goemail.New(emailsmtp.NewSMTPTransport(emailsmtp.LoadConfig()), goemail.WithMiddleware(goemail.Validate())), emailsmtp.LoadConfig().From)
	auth := &handlers.AdminAuth{AdminCLIID: cfg.AdminCLIID, Roles: handlers.StoreRoles{Store: s}}
	readH := handlers.NewReadHandler(s).WithSSOEventPublisher(ssoEvents).WithAccountCreatedPublisher(jobsPub).
		WithLastSeenThrottle(cfg.SessionLastSeenThrottle)
	readH.WithOTP(mailer, zl, cfg.Login2FAEnabled, cfg.OTPDevEcho)
	var totpCipher *secrets.Cipher
	if cfg.TotpEncKey != "" {
		if totpCipher, err = secrets.NewFromString(cfg.TotpEncKey); err != nil {
			return fmt.Errorf("TOTP_ENC_KEY: %w", err)
		}
	} else {
		logger.Warn("TOTP_ENC_KEY is not set: the authenticator factor is off")
	}
	readH.WithMFA(totpCipher, mailer, zl, cfg.OTPDevEcho)
	wa, err := webauthn.New(&webauthn.Config{
		RPID: cfg.WebAuthn.RPID, RPDisplayName: cfg.WebAuthn.RPName, RPOrigins: cfg.WebAuthn.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{UserVerification: protocol.UserVerificationRequirement(cfg.WebAuthn.UserVerification)},
	})
	if err != nil {
		return fmt.Errorf("WEBAUTHN_RP_*: %w", err)
	}
	readH.WithWebauthn(wa)

	adminH := handlers.NewAdminHandler(s, auth).WithSSOEventPublisher(ssoEvents).WithAccountCreatedPublisher(jobsPub)
	adminH.WithOTP(mailer, zl, cfg.OTPDevEcho)
	adminH.WithMembershipPublisher(jobsPub)
	adminH.BreakGlassDurationMin = int(cfg.BreakGlassDuration / time.Minute)

	var sessions merge.SessionRevoker
	if cfg.KratosAdminURL != "" {
		k := kratos.New(cfg.KratosAdminURL, kratos.DefaultTimeout, kratos.WithSchemaID(cfg.KratosSchemaID))
		readH.WithSignIn(k)
		adminH.WithSignIn(k).WithCredentialRevoker(k).WithCredentialFinder(userdelete.NewKratosCredentialFinder(k))
		sessions = accountSessions{s: s, k: k}
	} else {
		logger.Warn("KRATOS_ADMIN_URL is not set: local accounts, sessions and deletes are unavailable")
	}

	var core merge.CoreClient
	if cfg.CoreGRPCAddr != "" {
		cc, err := dial(cfg.CoreGRPCAddr, cfg.TLS, cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("dial core: %w", err)
		}
		defer func() { _ = cc.Close() }()
		adminH.WithCategoryRulePurger(userdelete.NewGRPCCategoryRulePurger(corev1.NewCategoryServiceClient(cc))).
			WithOwnedPolicyLister(userdelete.NewGRPCOwnedPolicyLister(corev1.NewPolicyServiceClient(cc))).
			WithCategoryRulePreviewer(userdelete.NewGRPCCategoryRulePreviewer(corev1.NewCategoryServiceClient(cc)))
		core = merge.NewGRPCCore(corev1.NewPolicyServiceClient(cc))
	} else {
		logger.Warn("CORE_GRPC_ADDR is not set: deletes and merges are refused")
	}
	// An unset callee leaves its client nil: the approval check and the merge
	// steps that need it report unavailable, so deletes and merges refuse
	// rather than strand records.
	var workflow merge.WorkflowClient
	if cfg.WorkflowGRPCAddr != "" {
		cc, err := dial(cfg.WorkflowGRPCAddr, cfg.TLS, cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("dial workflow: %w", err)
		}
		defer func() { _ = cc.Close() }()
		adminH.WithApprovalLister(userdelete.NewGRPCApprovalLister(workflowv1.NewWorkflowServiceClient(cc)))
		workflow = merge.NewGRPCWorkflow(workflowv1.NewWorkflowServiceClient(cc))
	} else {
		logger.Warn("WORKFLOW_GRPC_ADDR is not set: deletes and merges are refused")
	}
	var acks merge.AckClient
	if cfg.ObligationsGRPCAddr != "" {
		cc, err := dial(cfg.ObligationsGRPCAddr, cfg.TLS, cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("dial obligations: %w", err)
		}
		defer func() { _ = cc.Close() }()
		acks = merge.NewGRPCAck(obligationsv1.NewAckServiceClient(cc))
	} else {
		logger.Warn("OBLIGATIONS_GRPC_ADDR is not set: merges are refused")
	}
	adminH.WithMerge(merge.New(s, core, acks, workflow, sessions))

	ssoH := handlers.NewSSOAdminHandler(s, polis.New(polis.Config{
		BaseURL: cfg.Polis.AdminURL, APIKey: cfg.Polis.APIKey, Product: cfg.Polis.Product, GatewayBaseURL: cfg.Polis.GatewayBaseURL,
	}), auth).WithSSOEventPublisher(ssoEvents).WithVerifyTXTPrefix(cfg.VerifyTXTPrefix)
	var cs kubernetes.Interface
	if cfg.SPCert.Namespace == "" && cfg.SPCert.PolisSecretNamespace == "" {
		logger.Warn("SP_CERT_NAMESPACE and POLIS_SECRET_NAMESPACE are not set: SAML signing certificates and stored OIDC client secrets are off")
	} else if rc, err := rest.InClusterConfig(); err != nil {
		logger.Warn("no in-cluster config: SAML signing certificates and stored OIDC client secrets are off", log.F("error", err.Error()))
	} else if c, err := kubernetes.NewForConfig(rc); err != nil {
		logger.Warn("kubernetes client: SAML signing certificates and stored OIDC client secrets are off", log.F("error", err.Error()))
	} else {
		cs = c
	}
	if cs != nil && cfg.SPCert.PolisSecretNamespace != "" {
		ssoH = ssoH.WithPolisSecrets(spkeys.NewK8sStore(cs, cfg.SPCert.PolisSecretNamespace, cfg.SPCert.PolisSecretName))
		logger.Info("polis secrets store on", log.F("namespace", cfg.SPCert.PolisSecretNamespace), log.F("secret", cfg.SPCert.PolisSecretName))
	}
	if cs != nil && cfg.SPCert.Namespace == "" {
		logger.Warn("SP_CERT_NAMESPACE is not set: SAML signing certificates are off")
	} else if cs != nil {
		sp := handlers.NewSPCertService(spkeys.NewK8sStore(cs, cfg.SPCert.Namespace, cfg.SPCert.SecretName), s,
			time.Duration(cfg.SPCert.TTLDays)*24*time.Hour, time.Duration(cfg.SPCert.OverlapHours)*time.Hour)
		if err := sp.EnsureInitial(ctx); err != nil {
			logger.Warn("SAML signing certificate not ready", log.F("error", err.Error()))
		}
		ssoH = ssoH.WithSPCert(sp)
	}
	if _, err := ssoH.ClearUnresolvableSecretRefs(ctx); err != nil {
		logger.Warn("sso: secret reference sweep did not finish; it runs again at the next start", log.F("error", err.Error()))
	}
	var callerAuth *server.Auth
	if cfg.WorkloadAuthEnabled {
		v, err := workloadauth.NewVerifier(cfg.WorkloadAuth, logger)
		if err != nil {
			return fmt.Errorf("workload auth: %w", err)
		}
		go v.Run(ctx)
		deps.JWKS = readiness.RecheckEvery(v.Refresh, jwksRecheck, time.Now)
		callerAuth = &server.Auth{Verifier: v, Policy: server.CallerPolicy(), Options: []workloadauth.Option{
			workloadauth.WithDenyHook(server.AuditDenial(s, logger)),
		}}
		logger.Info("service-to-service authentication on",
			log.F("issuer", cfg.WorkloadAuth.Issuer), log.F("audience", cfg.WorkloadAuth.Audience),
			log.F("jwks_override", cfg.WorkloadAuth.JWKSURL != ""), log.F("ca_file", cfg.WorkloadAuth.CAFile != ""),
			log.F("bearer_file", cfg.WorkloadAuth.BearerFile != ""),
			log.F("allowed_serviceaccounts", strings.Join(cfg.WorkloadAuth.AllowedServiceAccounts, ",")))
	} else {
		deps.WorkloadAuthDisabled = true
		go workloadauth.WarnDisabled(ctx, logger, workloadauth.DisabledWarnInterval)
	}

	go every(ctx, cfg.DomainRecheckInterval, func() {
		if checked, revoked, err := ssoH.RecheckVerifiedDomains(ctx); err != nil {
			logger.Warn("sso domain recheck", log.F("error", err.Error()))
		} else if revoked > 0 {
			logger.Info("sso domain recheck revoked domains", log.F("checked", checked), log.F("revoked", revoked))
		}
	})
	go every(ctx, time.Hour, func() {
		if n, err := s.SweepBreakGlass(ctx); err != nil {
			logger.Warn("break-glass sweep", log.F("error", err.Error()))
		} else if n > 0 {
			logger.Info("break-glass sweep", log.F("swept", n))
		}
	})

	checker, err := readiness.New(deps, health.WithTTL(5*time.Second), health.WithTimeout(2*time.Second), health.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("readiness: %w", err)
	}
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", ":"+cfg.GRPCPort)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	probeLis, err := lc.Listen(ctx, "tcp", ":"+cfg.ProbePort)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	logger.Info("serving", log.F("port", cfg.GRPCPort), log.F("probe_port", cfg.ProbePort))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	probesDone := make(chan error, 1)
	go func() {
		probesDone <- server.ServeProbes(ctx, probeLis, checker)
		cancel()
	}()
	opts := server.Options{
		CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile, ClientCAFile: cfg.TLS.ClientCAFile,
		Auth: callerAuth, Checker: checker,
	}
	err = server.Serve(ctx, lis, logger, opts, func(g *grpc.Server) {
		identityv1.RegisterIdentityReadServiceServer(g, readH)
		identityv1.RegisterIdentityAdminServiceServer(g, adminH)
		identityv1.RegisterIdentitySSOAdminServiceServer(g, ssoH)
	})
	cancel()
	return errors.Join(err, <-probesDone, <-relayDone)
}

// dial connects to another Steward service. Every call carries identity's
// projected token (read from tokenFile on every call; none while
// WORKLOAD_AUTH=disabled), the caller and the act-as admin; with TLS
// configured the connection uses the same certificate as a client
// certificate. A token file that can't be read now stops the boot.
func dial(addr string, t config.TLS, tokenFile string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if t.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(t.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file holds no certificate")
		}
		creds = credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13})
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds),
		grpc.WithStatsHandler(gootel.GRPCClientStatsHandler()),
		grpc.WithChainUnaryInterceptor(grpcactor.UnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(grpcactor.StreamClientInterceptor())}
	token, ok, err := workloadauth.DialOptionFromEnv(func(k string) string {
		if k == workloadauth.EnvTokenFile {
			return tokenFile
		}
		return ""
	})
	if err != nil {
		return nil, err
	}
	if ok {
		opts = append(opts, token)
	}
	return grpc.NewClient(addr, opts...)
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// accountSessions revokes an account's Kratos sessions for the merge.
type accountSessions struct {
	s *store.Store
	k *kratos.Client
}

func (a accountSessions) RevokeAccountSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	u, err := a.s.GetUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	id := u.ExternalSubject
	if id == "" {
		if u.Email == "" {
			return 0, nil
		}
		ref, err := a.k.FindIdentity(ctx, u.Email)
		if err != nil || !ref.Found {
			return 0, err
		}
		id = ref.ID
	}
	return a.k.RevokeIdentitySessions(ctx, id)
}

// publisher narrows a go-rabbitmq publisher to the Publish the emitters use.
type publisher struct{ p *rabbitmq.Publisher }

func (p publisher) Publish(ctx context.Context, routingKey string, body []byte) error {
	return p.p.Publish(ctx, routingKey, body)
}

type rabbitLogger struct{ l log.Logger }

func (r rabbitLogger) Debugf(f string, a ...any) { r.l.Debug(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Infof(f string, a ...any)  { r.l.Info(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Warnf(f string, a ...any)  { r.l.Warn(fmt.Sprintf(f, a...)) }
func (r rabbitLogger) Errorf(f string, a ...any) { r.l.Error(nil, fmt.Sprintf(f, a...)) }
