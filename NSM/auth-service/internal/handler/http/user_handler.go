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
