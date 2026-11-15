# syntax=docker/dockerfile:1
ARG GOLANG_VERSION="1.27.4"
ARG GOLANG_DIGEST="sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf"

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine@${GOLANG_DIGEST} AS builder
# Release version for startup logs and s5core_build_info.
ARG VERSION=""
ARG TARGETOS
ARG TARGETARCH
WORKDIR /go/src/github.com/mazixs/S5Core
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X github.com/mazixs/S5Core/internal/buildinfo.version=${VERSION}" \
    -o ./S5Core ./cmd/s5core

FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /go/src/github.com/mazixs/S5Core/S5Core /
ENTRYPOINT ["/S5Core"]
