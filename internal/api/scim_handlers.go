package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Busness-app/ky-primitives/scim"
	kysync "github.com/Busness-app/kypassword-server/internal/sync"
	"github.com/Busness-app/kypassword-server/internal/users"
)

func writeSCIM(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}
func scimError(w http.ResponseWriter, status int, kind, detail string) {
	writeSCIM(w, status, map[string]any{"schemas": []string{scim.ErrorSchema}, "status": strconv.Itoa(status), "scimType": kind, "detail": detail})
}

func (s *Server) scimRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		writeSCIM(w, 200, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
			"patch":   map[string]any{"supported": true}, "filter": map[string]any{"supported": true, "maxResults": 100},
			"bulk": map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"sort": map[string]any{"supported": false}, "etag": map[string]any{"supported": false},
			"changePassword":        map[string]any{"supported": false},
			"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Provisioning token", "description": "Dedicated KySignOn provisioning bearer token", "primary": true}},
		})
	})
	for _, pattern := range []string{"GET /scim/v2/Users", "POST /scim/v2/Users", "GET /scim/v2/Users/{id}", "PUT /scim/v2/Users/{id}", "PATCH /scim/v2/Users/{id}", "DELETE /scim/v2/Users/{id}"} {
		mux.HandleFunc(pattern, s.handleSCIMUser)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.scimToken == "" {
			s.recordAnonymousRejection(r, "scim.rejected", clientIP(r), "provisioning is not configured")
			scimError(w, 404, "", "SCIM provisioning is not configured")
			return
		}
		header := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(header, "Bearer ")
		want, got := sha256.Sum256([]byte(s.scimToken)), sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			s.recordAnonymousRejection(r, "scim.rejected", clientIP(r), "provisioning token rejected")
			w.Header().Set("WWW-Authenticate", "Bearer")
			scimError(w, 401, "", "Invalid provisioning token")
			return
		}
		// Serialize with signed webhook mutations so both interfaces see the same directory.
		s.syncMu.Lock()
		defer s.syncMu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

// Local reactivation is an explicit override: an active account must remain visible
// even when a previous directory deletion marker still exists.
func isSCIMDeleted(u users.User) bool { return u.SCIMDeleted && !u.Active }

func scimResource(u users.User) scim.User {
	name := u.SSOUsername
	if name == "" {
		name = u.Username
	}
	out := scim.User{Schemas: []string{scim.UserSchema}, ID: u.ID, ExternalID: u.SSOSub, UserName: name, Active: u.Active,
		Roles: []scim.MultiValue{{Value: string(u.Role), Primary: true}},
		Meta:  &scim.Meta{ResourceType: "User", Created: &u.CreatedAt, LastModified: &u.UpdatedAt, Location: "/scim/v2/Users/" + url.PathEscape(u.ID)},
	}
	if u.SSOEmail != "" {
		out.Emails = []scim.MultiValue{{Value: u.SSOEmail, Primary: true, Type: "work"}}
	}
	return out
}

func readSCIM(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, syncBodyLimit)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(out); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid or oversized SCIM body")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		scimError(w, 400, "invalidSyntax", "Expected one JSON resource")
		return false
	}
	return true
}

func (s *Server) handleSCIMUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if r.Method == "GET" && id == "" {
		s.listSCIMUsers(w, r)
		return
	}
	var existing users.User
	if id != "" {
		var err error
		existing, err = s.users.Get(id)
		if err != nil || isSCIMDeleted(existing) {
			scimError(w, 404, "", "User not found")
			return
		}
	}
	if r.Method == "GET" {
		writeSCIM(w, 200, scimResource(existing))
		return
	}
	if r.Method == "DELETE" {
		if err := s.users.UpdateDirectory(id, existing.Role, false, existing.SSOUsername, existing.SSOEmail, true); err != nil {
			scimError(w, 500, "", "Unable to deactivate user")
			return
		}
		s.revokeDirectorySessions(id)
		s.record(r, "scim.user_deleted", id, "", clientIP(r), "directory account removed; encrypted vault retained")
		writeSCIM(w, 204, nil)
		return
	}
	candidate := scim.User{Active: true}
	if r.Method == "PATCH" {
		candidate = scimResource(existing)
		if !applySCIMPatch(w, r, &candidate) {
			return
		}
	} else if !readSCIM(w, r, &candidate) {
		return
	}
	if !slices.Contains(candidate.Schemas, scim.UserSchema) || strings.TrimSpace(candidate.UserName) == "" || len(candidate.UserName) > 256 {
		scimError(w, 400, "invalidValue", "User schema and userName (up to 256 bytes) are required")
		return
	}
	if id != "" {
		if candidate.ExternalID != "" && candidate.ExternalID != existing.SSOSub {
			scimError(w, 400, "mutability", "externalId cannot change the KySignOn identity")
			return
		}
		candidate.ExternalID = existing.SSOSub
	}
	if len(candidate.Emails) > 1 || len(candidate.Roles) > 1 {
		scimError(w, 400, "invalidValue", "This directory supports one email and one role per user")
		return
	}
	if candidate.ExternalID == "" || len(candidate.ExternalID) > 512 {
		scimError(w, 400, "invalidValue", "externalId must be the KySignOn OIDC subject (up to 512 bytes)")
		return
	}
	// The signed webhook's id is a subject; REST SCIM uses externalId for that identity.
	candidate.ID = candidate.ExternalID
	body, _ := json.Marshal(candidate)
	attrs, err := kysync.ParseSCIMUser(body)
	if err != nil {
		scimError(w, 400, "invalidValue", "Invalid user attributes")
		return
	}

	for _, u := range s.users.List() {
		if u.SSOSub != candidate.ExternalID && !isSCIMDeleted(u) && strings.EqualFold(scimResource(u).UserName, candidate.UserName) {
			scimError(w, 409, "uniqueness", "userName is already in use by another identity")
			return
		}
	}
	status := http.StatusOK
	if r.Method == "POST" {
		found, err := s.users.GetBySSOSub(candidate.ExternalID)
		if err == nil && !isSCIMDeleted(found) {
			scimError(w, 409, "uniqueness", "An account already exists for this externalId")
			return
		}
		if err != nil && !errors.Is(err, users.ErrNotFound) {
			scimError(w, 500, "", "Unable to find user")
			return
		}
		if err == nil {
			existing = found
			id = found.ID
		} else {
			existing, err = s.provisionFromSCIM(attrs)
			if err != nil {
				scimError(w, 500, "", "Unable to provision user")
				return
			}
			id = existing.ID
		}
		status = http.StatusCreated
	}
	if err := s.users.UpdateDirectory(id, scimRole(attrs.Role), attrs.Active, attrs.Username, attrs.Email, false); err != nil {
		scimError(w, 500, "", "Unable to update user")
		return
	}
	if !attrs.Active {
		s.revokeDirectorySessions(id)
	}
	current, err := s.users.Get(id)
	if err != nil {
		scimError(w, 500, "", "Unable to read user")
		return
	}
	resource := scimResource(current)
	if status == http.StatusCreated {
		w.Header().Set("Location", resource.Meta.Location)
	}
	s.record(r, "scim.user_updated", id, "", clientIP(r), "applied SCIM directory resource")
	writeSCIM(w, status, resource)
}

func (s *Server) revokeDirectorySessions(id string) {
	s.devices.CancelUserPairings(id)
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for token, session := range s.sessions {
		if session.UserID == id {
			delete(s.sessions, token)
		}
	}
}

// Equality lookups are deliberately limited to the shared client's supported attributes.
func (s *Server) listSCIMUsers(w http.ResponseWriter, r *http.Request) {
	attribute, value := "", ""
	if filter := r.URL.Query().Get("filter"); filter != "" {
		parts := strings.SplitN(filter, " ", 3)
		if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") ||
			(!strings.EqualFold(parts[0], "externalId") && !strings.EqualFold(parts[0], "userName")) || json.Unmarshal([]byte(parts[2]), &value) != nil {
			scimError(w, 400, "invalidFilter", "Supported filters: externalId eq \"value\" and userName eq \"value\"")
			return
		}
		attribute = strings.ToLower(parts[0])
	}
	start, count := 1, 100
	for name, target := range map[string]*int{"startIndex": &start, "count": &count} {
		if raw := r.URL.Query().Get(name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				scimError(w, 400, "invalidValue", "Invalid pagination")
				return
			}
			*target = parsed
		}
	}
	start = max(start, 1)
	count = min(count, 100)
	matches := []scim.User{}
	for _, u := range s.users.List() {
		if isSCIMDeleted(u) || u.SSOSub == "" {
			continue
		}
		resource := scimResource(u)
		if attribute == "externalid" && resource.ExternalID != value || attribute == "username" && !strings.EqualFold(resource.UserName, value) {
			continue
		}
		matches = append(matches, resource)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
	offset := min(start-1, len(matches))
	end := offset + min(count, len(matches)-offset)
	writeSCIM(w, 200, map[string]any{"schemas": []string{scim.ListResponseSchema}, "totalResults": len(matches), "startIndex": start, "itemsPerPage": end - offset, "Resources": matches[offset:end]})
}

func applySCIMPatch(w http.ResponseWriter, r *http.Request, candidate *scim.User) bool {
	var patch struct {
		Schemas    []string              `json:"schemas"`
		Operations []scim.PatchOperation `json:"Operations"`
	}
	if !readSCIM(w, r, &patch) {
		return false
	}
	if !slices.Contains(patch.Schemas, scim.PatchOpSchema) || len(patch.Operations) == 0 || len(patch.Operations) > 100 {
		scimError(w, 400, "invalidSyntax", "Expected 1 to 100 PatchOp operations")
		return false
	}
	encoded, _ := json.Marshal(candidate)
	fields := map[string]json.RawMessage{}
	_ = json.Unmarshal(encoded, &fields)
	for _, operation := range patch.Operations {
		op := strings.ToLower(operation.Op)
		if op != "replace" && op != "add" && op != "remove" {
			scimError(w, 400, "invalidSyntax", "Unsupported patch operation")
			return false
		}
		values := map[string]any{operation.Path: operation.Value}
		if operation.Path == "" {
			object, ok := operation.Value.(map[string]any)
			if !ok || op == "remove" {
				scimError(w, 400, "invalidValue", "Pathless patch needs an attribute object")
				return false
			}
			values = object
		}
		for path, value := range values {
			key := ""
			switch strings.ToLower(path) {
			case "username":
				key = "userName"
			case "active":
				key = "active"
			case "emails":
				key = "emails"
			case "roles":
				key = "roles"
			case "id", "externalid":
				scimError(w, 400, "mutability", "Identity attributes cannot be patched")
				return false
			default:
				scimError(w, 400, "invalidPath", "Supported paths: userName, active, emails, roles")
				return false
			}
			if op == "remove" {
				if key != "emails" && key != "roles" {
					scimError(w, 400, "mutability", "Only emails and roles can be removed")
					return false
				}
				delete(fields, key)
			} else {
				if value == nil {
					scimError(w, 400, "invalidValue", "Patch value cannot be null")
					return false
				}
				encodedValue, _ := json.Marshal(value)
				if op == "add" && (key == "emails" || key == "roles") {
					var current, incoming []scim.MultiValue
					_ = json.Unmarshal(fields[key], &current)
					if json.Unmarshal(encodedValue, &incoming) != nil {
						scimError(w, 400, "invalidValue", "Multi-valued attributes require an array")
						return false
					}
					for _, item := range incoming {
						if !slices.Contains(current, item) {
							current = append(current, item)
						}
					}
					encodedValue, _ = json.Marshal(current)
				}
				fields[key] = encodedValue
			}
		}
	}
	encoded, _ = json.Marshal(fields)
	var updated scim.User
	if json.Unmarshal(encoded, &updated) != nil {
		scimError(w, 400, "invalidValue", "Invalid attribute value")
		return false
	}
	*candidate = updated
	return true
}

func (s *Server) handleProvisioningStatus(w http.ResponseWriter, r *http.Request, admin users.User) {
	writeJSON(w, 200, map[string]any{"configured": s.scimToken != "", "basePath": "/scim/v2"})
}
