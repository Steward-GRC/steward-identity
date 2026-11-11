// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"sort"
	"strings"

	log "github.com/Bugs5382/go-log"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/errcodes"
	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
	"github.com/Steward-GRC/steward-identity/internal/store"
)

// callerSessions reads the calling user's own Kratos sessions. The user is the
// forwarded actor, never a request field, so nobody can read or end another
// person's. An account with no sign-in identity has no sessions.
func (h *ReadHandler) callerSessions(ctx context.Context, unavailable func(error) error) (u store.User, sessions []kratos.Session, err error) {
	sub, ok := callerSubject(ctx)
	if !ok {
		return u, nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	uid, err := parseUUID(sub, "user_id")
	if err != nil {
		return u, nil, err
	}
	if h.signIn == nil {
		return u, nil, errcodes.Error(ctx, unavailable(errNoSignIn))
	}
	if u, err = h.store.GetUser(ctx, uid); err != nil {
		return u, nil, statusFromStoreErr(err)
	}
	identityID, found, err := kratosIdentityID(ctx, h.signIn, u)
	if err != nil {
		return u, nil, errcodes.Error(ctx, unavailable(err))
	}
	if !found {
		return u, nil, nil
	}
	if sessions, err = h.signIn.ListSessions(ctx, identityID); err != nil {
		return u, nil, errcodes.Error(ctx, unavailable(err))
	}
	return u, sessions, nil
}

// ListMySessions lists the calling user's active sessions, newest first, and
// marks the one the request runs on (steward-identity#62).
func (h *ReadHandler) ListMySessions(ctx context.Context, req *identityv1.ListMySessionsRequest) (*identityv1.ListMySessionsResponse, error) {
	lg := logger.Ctx(ctx)
	u, all, err := h.callerSessions(ctx, errcodes.SessionsUnavailable)
	if err != nil {
		lg.Debug("list my sessions: not answered", log.F("error", errText(err)))
		return nil, err
	}
	active := make([]kratos.Session, 0, len(all))
	ids := make([]uuid.UUID, 0, len(all))
	for _, s := range all {
		if !s.Active {
			continue
		}
		active = append(active, s)
		if sid, perr := uuid.Parse(s.ID); perr == nil {
			ids = append(ids, sid)
		}
	}
	sort.SliceStable(active, func(i, j int) bool { return active[i].IssuedAt.After(active[j].IssuedAt) })
	lastSeen, err := h.store.SessionsLastSeen(ctx, ids)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	out := sessionsToProto(u.ID.String(), active, lastSeen)
	if cur := strings.TrimSpace(req.GetCurrentSessionId()); cur != "" {
		for _, s := range out {
			s.Current = strings.EqualFold(s.GetSessionId(), cur)
		}
	}
	lg.Debug("list my sessions: answered", log.F("user_id", u.ID.String()), log.F("sessions", len(out)))
	return &identityv1.ListMySessionsResponse{Sessions: out}, nil
}

// RevokeMySession ends one of the calling user's other sessions. The current
// session is refused (ending it is RevokeMySessions' job), and a session that
// is not the caller's is NotFound, exactly like an unknown one, so a caller
// learns nothing about other people's sessions.
func (h *ReadHandler) RevokeMySession(ctx context.Context, req *identityv1.RevokeMySessionRequest) (*identityv1.RevokeMySessionResponse, error) {
	lg := logger.Ctx(ctx)
	target := strings.TrimSpace(req.GetSessionId())
	current := strings.TrimSpace(req.GetCurrentSessionId())
	if _, ok := callerSubject(ctx); !ok {
		return nil, status.Error(codes.Unauthenticated, "no authenticated user")
	}
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id required")
	}
	if current == "" {
		return nil, status.Error(codes.InvalidArgument, "current_session_id required")
	}
	if strings.EqualFold(target, current) {
		lg.Debug("revoke my session: refused, it is the current session")
		return nil, status.Error(codes.FailedPrecondition, "the current session can't be signed out here; sign out instead")
	}
	u, all, err := h.callerSessions(ctx, errcodes.SessionRevokeUnavailable)
	if err != nil {
		return nil, err
	}
	var mine *kratos.Session
	for i := range all {
		if strings.EqualFold(all[i].ID, target) {
			mine = &all[i]
			break
		}
	}
	if mine == nil {
		lg.Debug("revoke my session: not one of the caller's sessions", log.F("user_id", u.ID.String()))
		return nil, status.Error(codes.NotFound, "session not found")
	}
	if !mine.Active {
		return &identityv1.RevokeMySessionResponse{}, nil
	}
	revoked, err := h.signIn.RevokeSession(ctx, mine.ID)
	if err != nil {
		lg.Error(err, "revoke my session: sign-in service failed", log.F("user_id", u.ID.String()))
		return nil, errcodes.Error(ctx, errcodes.SessionRevokeUnavailable(err))
	}
	if !revoked {
		return &identityv1.RevokeMySessionResponse{}, nil
	}
	if err := h.store.EmitAudit(ctx, store.AuditEvent{
		EventType: "session.revoked", ActorUserID: &u.ID, TargetUserID: &u.ID,
		Payload: map[string]any{"reason": "logout", "revoked": 1, "session_id": mine.ID},
	}); err != nil {
		lg.Warn("revoke my session: audit write failed", log.F("error", errText(err)))
	}
	lg.Info("revoke my session: ended one session", log.F("user_id", u.ID.String()))
	return &identityv1.RevokeMySessionResponse{Revoked: 1}, nil
}
