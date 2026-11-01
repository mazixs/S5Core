# syntax=docker/dockerfile:1
ARG GOLANG_VERSION="1.26.9"
ARG GOLANG_DIGEST="sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c"

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

FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /go/src/github.com/mazixs/S5Core/S5Core /
ENTRYPOINT ["/S5Core"]
