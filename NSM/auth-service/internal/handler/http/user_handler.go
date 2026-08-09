package http

import (
	"net/http"

	"github.com/acme/auth-service/internal/dto"
	"github.com/acme/auth-service/internal/repository"
	"github.com/acme/auth-service/internal/service"
)

type userHandler struct {
	svc *service.UserService
}

func (h *userHandler) create(w http.ResponseWriter, r *http.Request) {
	var req dto.UserCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	orgID := organizationIDFromRequest(r)
	u, err := h.svc.CreateUser(r.Context(), req.ToEntity(orgID), req.Password)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.UserResponseFromEntity(u))
}

// register implements POST /v1/auth/register — self-service signup,
// distinct from create (POST /users, the admin/invite path) even though
// both end up calling into the same UserService. It lives here, not on
// authHandler, because the capability it calls (service.UserService.Register)
// lives on UserService — the route path is a public contract
// ("/auth/register" reads better to a caller than "/users/register" would
// for something that isn't authenticated yet), but nothing requires the
// handler struct that serves a path to match that path's first segment;
// router.go is the only place the two are connected.
func (h *userHandler) register(w http.ResponseWriter, r *http.Request) {
	var req dto.RegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Validate(); err != nil {
		writeValidationError(w, r, err)
		return
	}

	u, err := h.svc.Register(r.Context(), service.RegisterInput{
		OrganizationID: organizationIDFromRequest(r),
		Username:       req.Username,
		Email:          req.Email,
		Password:       req.Password,
		IPAddress:      clientIP(r),
	})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusCreated, dto.RegisterResponse{
		ID:        u.ID,
		Username:  *u.Username,
		Email:     u.Email,
		Status:    string(u.Status),
		CreatedAt: u.CreatedAt,
	})
}

func (h *userHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	u, err := h.svc.GetUser(r.Context(), id)
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	writeJSON(w, r, http.StatusOK, dto.UserResponseFromEntity(u))
}

func (h *userHandler) list(w http.ResponseWriter, r *http.Request) {
	orgID := organizationIDFromRequest(r)
	users, err := h.svc.ListUsers(r.Context(), orgID, repository.UserFilter{Limit: 20})
	if err != nil {
		writeServiceError(w, r, err)
		return
	}
	out := make([]dto.UserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, dto.UserResponseFromEntity(u))
	}
	hasMore := false
	writeJSON(w, r, http.StatusOK, struct {
		Data []dto.UserResponse `json:"data"`
		Page dto.PageMeta       `json:"page"`
	}{Data: out, Page: dto.PageMeta{HasMore: hasMore, Limit: 20}})
}

func (h *userHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("userId")
	if err := h.svc.DeleteUser(r.Context(), id); err != nil {
		writeServiceError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
