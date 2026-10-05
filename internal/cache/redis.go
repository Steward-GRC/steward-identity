// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package cache is the optional cache for identity's hottest read, a user's
// identity provider groups, on go-redis. A cache that can't be reached reads
// as a miss, so an outage only costs speed.
package cache

import (
	"context"
	"errors"
	"sync"
	"time"

	redis "github.com/Bugs5382/go-redis"
	rediscache "github.com/Bugs5382/go-redis/cache"
)

// Redis caches each user's identity provider group names for one TTL.
type Redis struct {
	c   *rediscache.Cache[[]string]
	ttl time.Duration
	br  breaker
}

// New returns a cache on client with entries kept for ttl.
func New(client *redis.Client, ttl time.Duration) *Redis {
	return &Redis{c: rediscache.New[[]string](client, rediscache.WithPrefix("idpgroups:")), ttl: ttl}
}

// GetIdpGroups returns a user's cached names and whether there were any.
func (r *Redis) GetIdpGroups(ctx context.Context, userID string) ([]string, bool) {
	if !r.br.allow() {
		return nil, false
	}
	names, err := r.c.Get(ctx, userID)
	if errors.Is(err, rediscache.ErrMiss) {
		r.br.record(nil)
		return nil, false
	}
	r.br.record(err)
	return names, err == nil
}

// SetIdpGroups stores a user's names. A failure only counts against the
// breaker.
func (r *Redis) SetIdpGroups(ctx context.Context, userID string, names []string) {
	if r.br.allow() {
		r.br.record(r.c.Set(ctx, userID, names, r.ttl))
	}
}

// DelIdpGroups drops a user's cached names.
func (r *Redis) DelIdpGroups(ctx context.Context, userID string) {
	if r.br.allow() {
		r.br.record(r.c.Delete(ctx, userID))
	}
}

// breaker skips Redis for a few seconds after three failures in a row, so an
// outage doesn't add a timeout to every request.
type breaker struct {
	mu        sync.Mutex
	fails     int
	openUntil time.Time
}

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().After(b.openUntil)
}

func (b *breaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.fails = 0
		b.openUntil = time.Time{}
		return
	}
	b.fails++
	if b.fails >= 3 {
		b.openUntil = time.Now().Add(3 * time.Second)
	}
}
