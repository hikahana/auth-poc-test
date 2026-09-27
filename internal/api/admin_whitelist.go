package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/hikahana/auth-poc-test/internal/revocation"
	"github.com/hikahana/auth-poc-test/internal/whitelist"
)

func (s *Server) handleListWhitelist(w http.ResponseWriter, r *http.Request) {
	entries, err := s.Whitelist.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

type addWhitelistRequest struct {
	Email string         `json:"email"`
	Role  whitelist.Role `json:"role"`
}

// handleAddWhitelist registers someone ahead of their first login — mostly
// useful for making a new administrator, since members register themselves
// by signing in.
func (s *Server) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	var req addWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = whitelist.RoleMember
	}
	if !req.Role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}

	entry, err := s.Whitelist.Add(r.Context(), req.Email, req.Role, adminEmail(r))
	if s.writeWhitelistError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

type setRoleRequest struct {
	Role whitelist.Role `json:"role"`
}

func (s *Server) handleSetRole(w http.ResponseWriter, r *http.Request) {
	var req setRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Role.Valid() {
		writeError(w, http.StatusBadRequest, "role must be member or admin")
		return
	}

	entry, err := s.Whitelist.SetRole(r.Context(), r.PathValue("email"), req.Role)
	if s.writeWhitelistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

type revocationResponse struct {
	Email       string              `json:"email"`
	Revocations []revocation.Result `json:"revocations"`
}

// handleDisable keeps the person out from now on and then drops the sessions
// they already hold in each product. The per-product outcome is returned so
// the admin can see (and retry via POST /v1/admin/logins/revoke) anything
// that failed.
func (s *Server) handleDisable(w http.ResponseWriter, r *http.Request) {
	email := whitelist.Normalize(r.PathValue("email"))
	_, err := s.Whitelist.Disable(r.Context(), email, adminEmail(r))
	if s.writeWhitelistError(w, err) {
		return
	}

	results, err := s.revokeSessions(r, email)
	if err != nil {
		s.Logger.Error("disabled but revocation lookup failed", "email", email, "error", err)
		writeError(w, http.StatusInternalServerError, "disabled, but existing sessions could not be revoked; retry with force logout")
		return
	}
	writeJSON(w, http.StatusOK, revocationResponse{Email: email, Revocations: results})
}

func (s *Server) handleEnable(w http.ResponseWriter, r *http.Request) {
	entry, err := s.Whitelist.Enable(r.Context(), r.PathValue("email"))
	if s.writeWhitelistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// jst is used to read the admin's dates: "2026-04-01" means that day in Japan.
var jst = time.FixedZone("JST", 9*60*60)

type bulkDisableRequest struct {
	EntryYearFrom  *int   `json:"entry_year_from"`
	EntryYearTo    *int   `json:"entry_year_to"`
	RegisteredFrom string `json:"registered_from"` // YYYY-MM-DD, inclusive
	RegisteredTo   string `json:"registered_to"`   // YYYY-MM-DD, inclusive
	DryRun         bool   `json:"dry_run"`
}

func (req bulkDisableRequest) criteria() (whitelist.BulkCriteria, error) {
	c := whitelist.BulkCriteria{EntryYearFrom: req.EntryYearFrom, EntryYearTo: req.EntryYearTo}
	if req.RegisteredFrom != "" {
		d, err := time.ParseInLocation("2006-01-02", req.RegisteredFrom, jst)
		if err != nil {
			return c, errors.New("registered_from must be YYYY-MM-DD")
		}
		c.RegisteredFrom = &d
	}
	if req.RegisteredTo != "" {
		d, err := time.ParseInLocation("2006-01-02", req.RegisteredTo, jst)
		if err != nil {
			return c, errors.New("registered_to must be YYYY-MM-DD")
		}
		next := d.AddDate(0, 0, 1)
		c.RegisteredBefore = &next
	}
	if c.Empty() {
		return c, errors.New("specify an entry year range and/or a registration date range")
	}
	return c, nil
}

type bulkDisableResponse struct {
	DryRun  bool                 `json:"dry_run"`
	Matched []whitelist.Entry    `json:"matched"`
	Results []revocationResponse `json:"results,omitempty"`
}

// handleBulkDisable disables every active member matching the conditions
// (administrators are never included) and drops their sessions. With
// dry_run it only lists who would be affected, so the admin can check first.
func (s *Server) handleBulkDisable(w http.ResponseWriter, r *http.Request) {
	var req bulkDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	criteria, err := req.criteria()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	matched, err := s.Whitelist.SelectForBulkDisable(r.Context(), criteria)
	if err != nil {
		s.Logger.Error("bulk selection failed", "error", err)
		writeError(w, http.StatusInternalServerError, "bulk selection failed")
		return
	}
	resp := bulkDisableResponse{DryRun: req.DryRun, Matched: matched}
	if req.DryRun {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	for _, e := range matched {
		if _, err := s.Whitelist.Disable(r.Context(), e.Email, adminEmail(r)); err != nil {
			s.Logger.Error("bulk disable failed", "email", e.Email, "error", err)
			resp.Results = append(resp.Results, revocationResponse{Email: e.Email, Revocations: []revocation.Result{
				{Target: "whitelist", Status: revocation.StatusFailed, Detail: err.Error()},
			}})
			continue
		}
		results, err := s.revokeSessions(r, e.Email)
		if err != nil {
			results = []revocation.Result{{Target: "revocation lookup", Status: revocation.StatusFailed, Detail: err.Error()}}
		}
		resp.Results = append(resp.Results, revocationResponse{Email: e.Email, Revocations: results})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) revokeSessions(r *http.Request, email string) ([]revocation.Result, error) {
	targets, err := s.Clients.RevocationTargets(r.Context(), email)
	if err != nil {
		return nil, err
	}
	results := s.Revoker.Revoke(r.Context(), targets)
	for _, res := range results {
		if res.Status == revocation.StatusFailed {
			s.Logger.Warn("session revocation failed", "email", email, "target", res.Target, "detail", res.Detail)
		}
	}
	return results, nil
}

// writeWhitelistError reports err (if any) and whether it did.
func (s *Server) writeWhitelistError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, whitelist.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such whitelist entry")
	case errors.Is(err, whitelist.ErrNotEligible):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, whitelist.ErrLastAdmin):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.Logger.Error("whitelist update failed", "error", err)
		writeError(w, http.StatusInternalServerError, "whitelist update failed")
	}
	return true
}
