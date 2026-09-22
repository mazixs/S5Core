# syntax=docker/dockerfile:1
ARG GOLANG_VERSION="1.26.6"

FROM --platform=$BUILDPLATFORM golang:${GOLANG_VERSION}-alpine AS builder
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

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /go/src/github.com/mazixs/S5Core/S5Core /
ENTRYPOINT ["/S5Core"]
