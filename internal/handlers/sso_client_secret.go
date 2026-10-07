// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/Bugs5382/go-log"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Steward-GRC/steward-identity/internal/sso/polis"
	"github.com/Steward-GRC/steward-identity/internal/sso/spkeys"
)

// clientSecretKeyPrefix starts the name of every key identity writes for
// a client secret an admin entered. Keys with this prefix (and the Polis-issued
// ones) are identity's own: a caller can't name them as a secret_ref, and
// identity removes them when they're replaced.
const clientSecretKeyPrefix = "oidc-client-secret-" // #nosec G101 -- a key name prefix

// secretKeyPattern is what Kubernetes accepts as a Secret data key.
var secretKeyPattern = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)

// clientSecret is an OIDC client secret ready for Polis: the key it lives
// under, its value and whether identity wrote that key for this request.
type clientSecret struct {
	ref   string
	value string
	owned bool
}

func isWellFormedSecretKey(k string) bool { return secretKeyPattern.MatchString(k) }

func isOwnedSecretKey(k string) bool {
	return strings.HasPrefix(k, clientSecretKeyPrefix) || strings.HasPrefix(k, polis.PolisClientSecretRef(""))
}

// rejectSecretConfig refuses a config map carrying anything that looks like a
// secret: the config column is plain JSONB.
func rejectSecretConfig(cfg map[string]string) error {
	for k := range cfg {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "secret") || strings.Contains(lk, "password") {
			return status.Error(codes.InvalidArgument, "config takes no secrets: send the OIDC client secret as client_secret")
		}
	}
	return nil
}

// prepareClientSecret checks a request's secret inputs and makes the secret
// ready for Polis. SAML takes neither input; OIDC takes at most one. A
// secret_ref must name a key that already exists
// in the Polis secrets Secret. A client_secret is written there under a new
// key. Everything is checked before the write, and nothing is sent anywhere
// else, so a refusal leaves no trace. Neither value is ever logged or echoed.
func (h *SSOAdminHandler) prepareClientSecret(ctx context.Context, protocol, secretRef, secret string) (clientSecret, error) {
	if protocol != "oidc" {
		if secretRef != "" || secret != "" {
			return clientSecret{}, status.Error(codes.InvalidArgument, "a SAML connection takes no client secret")
		}
		return clientSecret{}, nil
	}
	switch {
	case secretRef != "" && secret != "":
		return clientSecret{}, status.Error(codes.InvalidArgument, "send either secret_ref or client_secret, not both")
	case secretRef == "" && secret == "":
		return clientSecret{}, nil
	}
	if secretRef != "" && (!isWellFormedSecretKey(secretRef) || isOwnedSecretKey(secretRef)) {
		return clientSecret{}, status.Error(codes.InvalidArgument, "secret_ref must be the name of a key created in the Polis secrets Secret")
	}
	if h.polisSecrets == nil {
		return clientSecret{}, status.Error(codes.FailedPrecondition, "the Polis secrets store isn't configured, so a client secret can't be kept")
	}
	lg := logger.Ctx(ctx)
	if secretRef != "" {
		v, err := h.polisSecrets.GetKey(ctx, secretRef)
		if errors.Is(err, spkeys.ErrKeyNotFound) {
			return clientSecret{}, status.Error(codes.InvalidArgument, "secret_ref names no key in the Polis secrets Secret")
		}
		if err != nil {
			lg.Warn("sso: could not read the Polis secrets store", log.F("error", errText(err)))
			return clientSecret{}, status.Error(codes.Unavailable, "the Polis secrets store is unavailable")
		}
		if len(v) == 0 {
			return clientSecret{}, status.Error(codes.InvalidArgument, "secret_ref names an empty key")
		}
		lg.Debug("sso: client secret resolved from a pre-created key")
		return clientSecret{ref: secretRef, value: string(v)}, nil
	}
	ref := clientSecretKeyPrefix + uuid.NewString()
	if err := h.polisSecrets.PutKey(ctx, ref, []byte(secret)); err != nil {
		lg.Warn("sso: could not store the client secret", log.F("error", errText(err)))
		return clientSecret{}, status.Error(codes.Unavailable, "the Polis secrets store is unavailable")
	}
	lg.Debug("sso: client secret stored", log.F("secret_key", ref))
	return clientSecret{ref: ref, value: secret, owned: true}, nil
}

// dropOwnedSecretKey removes a key identity wrote, best-effort; a pre-created
// key is never touched.
func (h *SSOAdminHandler) dropOwnedSecretKey(ctx context.Context, ref string) {
	if ref == "" || h.polisSecrets == nil || !isOwnedSecretKey(ref) {
		return
	}
	if err := h.polisSecrets.DeleteKey(ctx, ref); err != nil {
		lg := logger.Ctx(ctx)
		lg.Warn("sso: could not remove a stored client secret", log.F("secret_key", ref), log.F("error", errText(err)))
	}
}

// ClearUnresolvableSecretRefs empties every secret_ref that isn't a key in
// the Polis secrets Secret, which is what an older row holding the client
// secret itself looks like, and marks the connection as needing its secret
// entered again. Sign-in keeps working: Polis has its own copy. A store error
// stops the sweep without clearing a reference that may be valid. Only the
// count is logged.
func (h *SSOAdminHandler) ClearUnresolvableSecretRefs(ctx context.Context) (int, error) {
	refs, err := h.store.ListIdPConnectionSecretRefs(ctx)
	if err != nil {
		return 0, err
	}
	lg := logger.Ctx(ctx)
	cleared := 0
	for _, r := range refs {
		resolvable := false
		if isWellFormedSecretKey(r.SecretRef) && h.polisSecrets != nil {
			_, gerr := h.polisSecrets.GetKey(ctx, r.SecretRef)
			switch {
			case gerr == nil:
				resolvable = true
			case !errors.Is(gerr, spkeys.ErrKeyNotFound):
				lg.Warn("sso: secret reference sweep stopped: the Polis secrets store is unavailable", log.F("cleared", cleared), log.F("error", errText(gerr)))
				return cleared, gerr
			}
		}
		if resolvable {
			continue
		}
		if err := h.store.ClearIdPConnectionSecretRef(ctx, r.ID); err != nil {
			return cleared, err
		}
		cleared++
	}
	lg.Info("sso: secret reference sweep done", log.F("checked", len(refs)), log.F("cleared", cleared))
	return cleared, nil
}
