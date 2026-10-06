// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Steward-GRC/steward-identity/gen/go/steward/identity/v1"
)

// TestGRPCHandlers_EveryRPCImplemented guards every gRPC service
// cmd/server/main.go registers — *AdminHandler, *ReadHandler and
// *SSOAdminHandler — against an RPC left to the embedded
// Unimplemented*Server stub: it compiles (the embed satisfies the interface)
// but answers codes.Unimplemented at runtime, which a
// `var _ Server = (*Handler)(nil)` assertion doesn't catch.
//
// Each handler is built through its public NewXxxHandler constructor, the
// same one main.go calls, rather than a bare struct literal, so the guard
// tracks the real construction path. The constructors take nil dependencies
// here, so an implemented method panics the moment it runs real code; that
// panic is recovered and counts as implemented. New RPCs are covered
// automatically.
func TestGRPCHandlers_EveryRPCImplemented(t *testing.T) {
	// Deferred RPCs, keyed "Service.Method", each with a reason. None today.
	knownDeferred := map[string]string{}

	tests := []struct {
		service     string
		iface       reflect.Type
		srv         reflect.Value
		minExpected int
	}{
		{
			service:     "IdentityAdminService",
			iface:       reflect.TypeFor[identityv1.IdentityAdminServiceServer](),
			srv:         reflect.ValueOf(identityv1.IdentityAdminServiceServer(NewAdminHandler(nil, nil))),
			minExpected: 15,
		},
		{
			service:     "IdentityReadService",
			iface:       reflect.TypeFor[identityv1.IdentityReadServiceServer](),
			srv:         reflect.ValueOf(identityv1.IdentityReadServiceServer(NewReadHandler(nil))),
			minExpected: 15,
		},
		{
			service:     "IdentitySSOAdminService",
			iface:       reflect.TypeFor[identityv1.IdentitySSOAdminServiceServer](),
			srv:         reflect.ValueOf(identityv1.IdentitySSOAdminServiceServer(NewSSOAdminHandler(nil, nil, nil))),
			minExpected: 17,
		},
	}

	ctxT := reflect.TypeFor[context.Context]()

	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			checked := 0
			for m := range tc.iface.Methods() {
				mt := m.Type
				// Only unary RPCs: func(context.Context, *Request) (*Response, error).
				// Skips mustEmbedUnimplemented... and any stream shapes.
				if mt.NumIn() != 2 || mt.NumOut() != 2 || !mt.In(0).Implements(ctxT) || mt.In(1).Kind() != reflect.Pointer {
					continue
				}
				name := m.Name
				checked++
				key := tc.service + "." + name
				if reason, ok := knownDeferred[key]; ok {
					t.Logf("RPC %s intentionally deferred (not implemented): %s", key, reason)
					continue
				}
				t.Run(name, func(t *testing.T) {
					defer func() {
						// A panic means the call reached real handler code (nil dep
						// deref) rather than the dependency-free Unimplemented stub —
						// i.e. the RPC is implemented. That is a pass.
						_ = recover()
					}()
					args := []reflect.Value{
						reflect.ValueOf(context.Background()),
						reflect.New(mt.In(1).Elem()),
					}
					out := tc.srv.MethodByName(name).Call(args)
					if errv := out[1]; !errv.IsNil() {
						if err, ok := errv.Interface().(error); ok && status.Code(err) == codes.Unimplemented {
							t.Errorf("RPC %s is not implemented: it returns codes.Unimplemented (still served by the embedded Unimplemented%sServer stub). Add a real handler method.", key, tc.service)
						}
					}
				})
			}

			// Sanity: ensure the reflection actually exercised the service surface,
			// so a future refactor that hides the methods can't make this test
			// vacuously pass.
			if checked < tc.minExpected {
				t.Fatalf("expected to check the full %s RPC surface, only invoked %d — reflection/filter is wrong", tc.service, checked)
			}
		})
	}
}
