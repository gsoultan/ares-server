// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package connectapi

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"

	"github.com/gsoultan/ares-server/internal/auth"
	aresv1 "github.com/gsoultan/ares-server/internal/gen/ares/v1"
	"github.com/gsoultan/ares-server/internal/setup"
)

// GetSetupStatus reports whether first-run setup is still required, and which
// datastore drivers the server can commit to. It is always available so the app
// can decide at startup whether to show the wizard.
func (h *Handler) GetSetupStatus(ctx context.Context, _ *connect.Request[aresv1.GetSetupStatusRequest]) (*connect.Response[aresv1.SetupStatus], error) {
	if h.setup == nil {
		// No setup service wired (e.g. ephemeral/in-memory run): report done so the
		// app is not stuck on a wizard it cannot complete.
		return connect.NewResponse(&aresv1.SetupStatus{Needed: false, Initialized: true, Drivers: driverProtos(setup.AvailableDrivers())}), nil
	}
	st, err := h.setup.Status()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	out := &aresv1.SetupStatus{
		Needed:      st.Needed,
		Initialized: st.Initialized,
		Drivers:     driverProtos(st.Drivers),
		DbPath:      st.DBPath, // password already redacted by the service
		KeyFilePath: st.KeyFilePath,
	}
	// This RPC is public. Once the install is set up, where its database and key
	// live is nobody's business but a super-admin's.
	if !st.Needed {
		if sess, ok := SessionFromContext(ctx); !ok || sess.Role != auth.RoleSuperAdmin {
			out.DbPath, out.KeyFilePath = "", ""
		}
	}
	if !st.InitializedAt.IsZero() {
		out.InitializedAt = st.InitializedAt.UTC().Format(time.RFC3339)
	}
	return connect.NewResponse(out), nil
}

// TestDatabaseConnection validates a datastore configuration without committing.
func (h *Handler) TestDatabaseConnection(_ context.Context, req *connect.Request[aresv1.TestDatabaseConnectionRequest]) (*connect.Response[aresv1.TestDatabaseConnectionResponse], error) {
	if h.setup == nil {
		return connect.NewResponse(&aresv1.TestDatabaseConnectionResponse{Ok: false, Error: "setup is not available on this instance"}), nil
	}
	err := h.setup.TestDatabase(req.Msg.GetDriver(), req.Msg.GetPath())
	resp := &aresv1.TestDatabaseConnectionResponse{Ok: err == nil}
	if err != nil {
		resp.Error = err.Error() // controlled, credential-free
		resp.ErrorCode = setup.CodeFor(err)
	}
	return connect.NewResponse(resp), nil
}

// CommitSetup performs the one-shot provisioning. Business errors (already
// initialized, unavailable driver, weak password) are returned in the response
// so the UI can show them; only the setup service being absent is an RPC error.
func (h *Handler) CommitSetup(_ context.Context, req *connect.Request[aresv1.CommitSetupRequest]) (*connect.Response[aresv1.CommitSetupResponse], error) {
	if h.setup == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("setup is not available on this instance"))
	}
	m := req.Msg
	res, err := h.setup.Commit(setup.CommitRequest{
		DBDriver:    m.GetDriver(),
		DBPath:      m.GetPath(),
		GenerateKey: m.GetGenerateKey(),
		Key:         m.GetKey(),
		Admin: setup.AdminInput{
			Name:     m.GetAdmin().GetName(),
			Email:    m.GetAdmin().GetEmail(),
			Password: m.GetAdmin().GetPassword(),
		},
		TenantName: m.GetTenantName(),
	})
	if err != nil {
		return connect.NewResponse(&aresv1.CommitSetupResponse{Ok: false, Error: err.Error(), ErrorCode: setup.CodeFor(err)}), nil
	}
	resp := &aresv1.CommitSetupResponse{
		Ok:            true,
		GeneratedKey:  res.GeneratedKey,
		InitializedAt: res.InitializedAt.UTC().Format(time.RFC3339),
		TenantId:      res.TenantID,
		AdminUserId:   res.AdminUserID,
	}
	return connect.NewResponse(resp), nil
}

func driverProtos(ds []setup.DriverInfo) []*aresv1.DriverInfo {
	out := make([]*aresv1.DriverInfo, 0, len(ds))
	for _, d := range ds {
		out = append(out, &aresv1.DriverInfo{Name: d.Name, Label: d.Label, Available: d.Available, Note: d.Note})
	}
	return out
}
