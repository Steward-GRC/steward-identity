// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Bugs5382/go-log"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
	"github.com/Steward-GRC/steward-identity/internal/store"
	"github.com/Steward-GRC/steward-identity/internal/workloadauth"
)

// Default hard reset windows: a request waits a day for a second root admin,
// and an approval is usable for an hour.
const (
	defaultHardResetRequestTTL  = 24 * time.Hour
	defaultHardResetApprovalTTL = time.Hour
)

// hardResetModules maps each module that can be hard reset to the one service
// that runs the reset and so may redeem an approval.
var hardResetModules = map[string]string{
	"compliance": "reporting",
}

type hardResetConfig struct {
	requestTTL  time.Duration
	approvalTTL time.Duration
	now         func() time.Time
}

func (c hardResetConfig) windows() (time.Duration, time.Duration) {
	req, appr := c.requestTTL, c.approvalTTL
	if req <= 0 {
		req = defaultHardResetRequestTTL
	}
	if appr <= 0 {
		appr = defaultHardResetApprovalTTL
	}
	return req, appr
}

func (c hardResetConfig) clock() time.Time {
	if c.now != nil {
		return c.now().UTC()
	}
	return time.Now().UTC()
}

// WithHardReset sets how long a hard reset request waits for approval, how
// long an approval stays usable, and the clock (nil is the wall clock).
// Returns the handler for chaining.
func (h *AdminHandler) WithHardReset(requestTTL, approvalTTL time.Duration, now func() time.Time) *AdminHandler {
	h.hardReset = hardResetConfig{requestTTL: requestTTL, approvalTTL: approvalTTL, now: now}
	return h
}

// hardResetActor authorizes a root admin's hard reset step: a site-admin
// caller with a platform user id (the admin CLI can't take part, since both
// people must be named), never during act-as. Whether they are root is
// checked with the step, in the same transaction.
func (h *AdminHandler) hardResetActor(ctx context.Context) (uuid.UUID, error) {
	actor, err := h.auth.Authorize(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if err := refuseWhileActingAs(ctx); err != nil {
		return uuid.Nil, err
	}
	id := actorUUIDPtr(actor)
	if id == nil {
		return uuid.Nil, status.Error(codes.PermissionDenied, "a hard reset needs two named root admins, not the admin CLI")
	}
	return *id, nil
}

func hardResetStatus(err error) error {
	switch {
	case errors.Is(err, store.ErrRootRequired):
		return status.Error(codes.PermissionDenied, "only a root admin can take part in a hard reset")
	case errors.Is(err, store.ErrSelfApproval):
		return status.Error(codes.PermissionDenied, "a second root admin must approve: the requester can't")
	case errors.Is(err, store.ErrNotRequester):
		return status.Error(codes.PermissionDenied, "only the requester can cancel a hard reset request")
	case errors.Is(err, store.ErrHardResetState), errors.Is(err, store.ErrConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return statusFromStoreErr(err)
	}
}

// RequestHardReset records a root admin's request to hard reset a module.
func (h *AdminHandler) RequestHardReset(ctx context.Context, req *identityv1.RequestHardResetRequest) (*identityv1.RequestHardResetResponse, error) {
	requester, err := h.hardResetActor(ctx)
	if err != nil {
		return nil, err
	}
	module := strings.ToLower(strings.TrimSpace(req.GetModule()))
	if _, ok := hardResetModules[module]; !ok {
		return nil, status.Error(codes.InvalidArgument, "module must be one that can be hard reset: compliance")
	}
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason required")
	}
	reqTTL, _ := h.hardReset.windows()
	r, err := h.store.CreateHardResetRequest(ctx, module, reason, requester, h.hardReset.clock(), reqTTL)
	if err != nil {
		return nil, hardResetStatus(err)
	}
	lg := logger.Ctx(ctx)
	lg.Info("hard reset requested", log.F("request_id", r.ID.String()), log.F("module", module), log.F("requested_by", requester.String()))
	return &identityv1.RequestHardResetResponse{Request: hardResetToProto(r)}, nil
}

// ApproveHardReset records a second root admin's approval.
func (h *AdminHandler) ApproveHardReset(ctx context.Context, req *identityv1.ApproveHardResetRequest) (*identityv1.ApproveHardResetResponse, error) {
	approver, err := h.hardResetActor(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	_, apprTTL := h.hardReset.windows()
	r, err := h.store.ApproveHardResetRequest(ctx, id, approver, h.hardReset.clock(), apprTTL)
	if err != nil {
		return nil, hardResetStatus(err)
	}
	lg := logger.Ctx(ctx)
	lg.Info("hard reset approved", log.F("request_id", r.ID.String()), log.F("module", r.Module), log.F("approved_by", approver.String()))
	return &identityv1.ApproveHardResetResponse{Request: hardResetToProto(r)}, nil
}

// CancelHardReset withdraws the caller's own pending or approved request.
func (h *AdminHandler) CancelHardReset(ctx context.Context, req *identityv1.CancelHardResetRequest) (*identityv1.CancelHardResetResponse, error) {
	requester, err := h.hardResetActor(ctx)
	if err != nil {
		return nil, err
	}
	id, err := parseUUID(req.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	r, err := h.store.CancelHardResetRequest(ctx, id, requester, h.hardReset.clock())
	if err != nil {
		return nil, hardResetStatus(err)
	}
	lg := logger.Ctx(ctx)
	lg.Info("hard reset cancelled", log.F("request_id", r.ID.String()), log.F("module", r.Module))
	return &identityv1.CancelHardResetResponse{Request: hardResetToProto(r)}, nil
}

// ListHardResetRequests lists the requests for a root admin.
func (h *AdminHandler) ListHardResetRequests(ctx context.Context, req *identityv1.ListHardResetRequestsRequest) (*identityv1.ListHardResetRequestsResponse, error) {
	actor, err := h.hardResetActor(ctx)
	if err != nil {
		return nil, err
	}
	isRoot, err := h.store.IsRootActor(ctx, &actor)
	if err != nil {
		return nil, statusFromStoreErr(err)
	}
	if !isRoot {
		return nil, hardResetStatus(store.ErrRootRequired)
	}
	rs, err := h.store.ListHardResetRequests(ctx, strings.ToLower(strings.TrimSpace(req.GetModule())), h.hardReset.clock())
	if err != nil {
		return nil, hardResetStatus(err)
	}
	out := make([]*identityv1.HardResetRequest, 0, len(rs))
	for _, r := range rs {
		out = append(out, hardResetToProto(r))
	}
	return &identityv1.ListHardResetRequestsResponse{Requests: out}, nil
}

// ConsumeHardReset redeems an approved request once. Only the service that
// owns the module may, calling as itself: the workload-auth grant names it.
func (h *AdminHandler) ConsumeHardReset(ctx context.Context, req *identityv1.ConsumeHardResetRequest) (*identityv1.ConsumeHardResetResponse, error) {
	module := strings.ToLower(strings.TrimSpace(req.GetModule()))
	owner, ok := hardResetModules[module]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "module must be one that can be hard reset: compliance")
	}
	g, ok := workloadauth.GrantFromContext(ctx)
	if !ok || g.Access != workloadauth.Self || g.Caller.Name != owner {
		return nil, status.Error(codes.PermissionDenied, "only the module's own service can redeem a hard reset")
	}
	id, err := parseUUID(req.GetRequestId(), "request_id")
	if err != nil {
		return nil, err
	}
	r, err := h.store.ConsumeHardResetRequest(ctx, id, module, g.Caller.Name, h.hardReset.clock())
	if err != nil {
		lg := logger.Ctx(ctx)
		lg.Warn("hard reset redeem refused", log.F("request_id", id.String()), log.F("module", module), log.F("error", errText(err)))
		return nil, hardResetStatus(err)
	}
	lg := logger.Ctx(ctx)
	lg.Info("hard reset redeemed", log.F("request_id", r.ID.String()), log.F("module", module), log.F("by", g.Caller.Name))
	return &identityv1.ConsumeHardResetResponse{Request: hardResetToProto(r)}, nil
}

func hardResetToProto(r store.HardResetRequest) *identityv1.HardResetRequest {
	ts := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	id := func(u *uuid.UUID) string {
		if u == nil {
			return ""
		}
		return u.String()
	}
	return &identityv1.HardResetRequest{
		Id:                r.ID.String(),
		Module:            r.Module,
		Reason:            r.Reason,
		State:             hardResetStateToProto(r.State),
		RequestedBy:       r.RequestedBy.String(),
		RequestedAt:       r.RequestedAt.UTC().Format(time.RFC3339),
		ExpiresAt:         r.ExpiresAt.UTC().Format(time.RFC3339),
		ApprovedBy:        id(r.ApprovedBy),
		ApprovedAt:        ts(r.ApprovedAt),
		ApprovalExpiresAt: ts(r.ApprovalExpiresAt),
		CancelledAt:       ts(r.CancelledAt),
		ConsumedAt:        ts(r.ConsumedAt),
		ConsumedBy:        r.ConsumedBy,
	}
}

func hardResetStateToProto(s string) identityv1.HardResetState {
	switch s {
	case store.HardResetPending:
		return identityv1.HardResetState_HARD_RESET_STATE_PENDING
	case store.HardResetApproved:
		return identityv1.HardResetState_HARD_RESET_STATE_APPROVED
	case store.HardResetCancelled:
		return identityv1.HardResetState_HARD_RESET_STATE_CANCELLED
	case store.HardResetConsumed:
		return identityv1.HardResetState_HARD_RESET_STATE_CONSUMED
	case store.HardResetExpired:
		return identityv1.HardResetState_HARD_RESET_STATE_EXPIRED
	default:
		return identityv1.HardResetState_HARD_RESET_STATE_UNSPECIFIED
	}
}
