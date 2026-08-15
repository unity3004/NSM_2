# syntax=docker/dockerfile:1

# --- build stage -------------------------------------------------------
# A separate build stage means the final image never contains the Go
# toolchain, module cache, or source tree — only the compiled binary. That
# keeps the attack surface (and the image size) down for something that's
# going to hold a JWT signing key in its environment.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Copy just the module files first so `go mod download` is cached across
# builds whenever only application code changes, not dependencies.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# --- runtime stage -------------------------------------------------------
# distroless has no shell, no package manager, no coreutils — nothing an
# attacker who reaches code execution inside the container could use to
# pivot further. It's also why HEALTHCHECK below can't shell out to curl;
# the binary answers its own /healthz instead.
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /out/server /app/server

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/server"]
