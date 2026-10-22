# syntax=docker/dockerfile:1.7
# =============================================================================
# n8n-custom-service: static Go binary on scratch, non-root (uid/gid 65532).
# Supports multi-service builds via SERVICE_NAME arg:
#   docker build --build-arg SERVICE_NAME=git-sync-service -t <reg>/n8n-custom-service/git-sync-service:<tag> .
#   docker build --build-arg SERVICE_NAME=sharing-service  -t <reg>/n8n-custom-service/sharing-service:<tag> .
# =============================================================================
ARG GO_IMAGE=golang:1.27.2-alpine

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS go-build
ARG TARGETOS=linux
ARG TARGETARCH
ARG SERVICE_NAME=git-sync-service
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -buildid=" -o /out/app ./cmd/${SERVICE_NAME}
# Non-root user without a shell.
RUN echo "app:x:65532:65532:app:/nonexistent:/sbin/nologin" > /out/passwd && \
    echo "app:x:65532:" > /out/group

FROM scratch
ARG SERVICE_NAME=git-sync-service
LABEL org.opencontainers.image.title="${SERVICE_NAME}"
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=go-build /out/passwd /etc/passwd
COPY --from=go-build /out/group /etc/group
COPY --from=go-build /out/app /app
ENV PORT=8080 TZ=Asia/Jakarta
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
