ARG GOLANG_VERSION="1.26.6"

FROM golang:${GOLANG_VERSION}-alpine AS builder
# Release version for startup logs and s5core_build_info.
ARG VERSION=""
RUN apk --no-cache add tzdata
WORKDIR /go/src/github.com/mazixs/S5Core
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags "-s -X github.com/mazixs/S5Core/internal/buildinfo.version=${VERSION}" \
    -o ./S5Core ./cmd/s5core

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /go/src/github.com/mazixs/S5Core/S5Core /
ENTRYPOINT ["/S5Core"]
