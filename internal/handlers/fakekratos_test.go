// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/Steward-GRC/steward-identity/internal/sso/kratos"
)

// fakeKratos is an in-memory Kratos admin API. err, when set, fails every
// call.
type fakeKratos struct {
	mu         sync.Mutex
	identities map[string]*fakeIdentity
	sessions   map[string][]kratos.Session
	err        error
	failCreate error
}

type fakeIdentity struct {
	id       string
	account  kratos.Account
	password string
	active   bool
}

func newFakeKratos() *fakeKratos {
	return &fakeKratos{identities: map[string]*fakeIdentity{}, sessions: map[string][]kratos.Session{}}
}

// add seeds an identity and returns its id.
func (f *fakeKratos) add(a kratos.Account, password string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.NewString()
	f.identities[id] = &fakeIdentity{id: id, account: a, password: password, active: true}
	return id
}

// addWithID seeds an identity under a given id, such as a user's external
// subject.
func (f *fakeKratos) addWithID(id string, a kratos.Account) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[id] = &fakeIdentity{id: id, account: a, active: true}
}

func (f *fakeKratos) byEmail(email string) *fakeIdentity {
	for _, i := range f.identities {
		if strings.EqualFold(i.account.Email, email) {
			return i
		}
	}
	return nil
}

func (f *fakeKratos) byUsername(username string) *fakeIdentity {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, i := range f.identities {
		if i.account.Username == username {
			return i
		}
	}
	return nil
}

func (f *fakeKratos) FindIdentity(_ context.Context, email string) (kratos.IdentityRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return kratos.IdentityRef{}, f.err
	}
	if i := f.byEmail(email); i != nil {
		state := "active"
		if !i.active {
			state = "inactive"
		}
		return kratos.IdentityRef{ID: i.id, Found: true, State: state}, nil
	}
	return kratos.IdentityRef{}, nil
}

func (f *fakeKratos) RevokeIdentity(_ context.Context, email string) (kratos.RevokeResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return kratos.RevokeResult{}, f.err
	}
	i := f.byEmail(email)
	if i == nil {
		return kratos.RevokeResult{}, nil
	}
	i.active = false
	delete(f.sessions, i.id)
	removed := i.password != ""
	i.password = ""
	return kratos.RevokeResult{IdentityID: i.id, Found: true, Deactivated: true, SessionsRevoked: true, PasswordRemoved: removed}, nil
}

func (f *fakeKratos) CreateIdentity(_ context.Context, a kratos.Account, password string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.failCreate != nil {
		return "", f.failCreate
	}
	return f.add(a, password), nil
}

func (f *fakeKratos) SetPassword(_ context.Context, identityID, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	i, ok := f.identities[identityID]
	if !ok {
		return errors.New("fake kratos: no such identity")
	}
	i.password = password
	return nil
}

func (f *fakeKratos) UpdateProfile(_ context.Context, identityID, email, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	i, ok := f.identities[identityID]
	if !ok {
		return errors.New("fake kratos: no such identity")
	}
	i.account.Email, i.account.Name = email, name
	return nil
}

func (f *fakeKratos) DeleteIdentity(_ context.Context, identityID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.identities, identityID)
	return nil
}

func (f *fakeKratos) ListSessions(_ context.Context, identityID string) ([]kratos.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]kratos.Session(nil), f.sessions[identityID]...), nil
}

func (f *fakeKratos) RevokeIdentitySessions(_ context.Context, identityID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	n := 0
	for i := range f.sessions[identityID] {
		if f.sessions[identityID][i].Active {
			n++
			f.sessions[identityID][i].Active = false
		}
	}
	return n, nil
}

func (f *fakeKratos) RevokeSession(_ context.Context, sessionID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	for id := range f.sessions {
		for i := range f.sessions[id] {
			if f.sessions[id][i].ID == sessionID && f.sessions[id][i].Active {
				f.sessions[id][i].Active = false
				return true, nil
			}
		}
	}
	return false, nil
}

// addSession seeds a session for identityID.
func (f *fakeKratos) addSession(identityID string, active bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.NewString()
	f.sessions[identityID] = append(f.sessions[identityID], kratos.Session{ID: id, IdentityID: identityID, Active: active, UserAgent: "Example Browser/1.0"})
	return id
}

var (
	kratosForMu sync.Mutex
	kratosByKey = map[any]*fakeKratos{}
)

// kratosFor returns one fake Kratos per key (a test's store), so a test can
// seed sessions on the fake a helper wired.
func kratosFor(key any) *fakeKratos {
	kratosForMu.Lock()
	defer kratosForMu.Unlock()
	if f, ok := kratosByKey[key]; ok {
		return f
	}
	f := newFakeKratos()
	kratosByKey[key] = f
	return f
}
