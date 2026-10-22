# syntax=docker/dockerfile:1.7
# =============================================================================
# n8n-git-service: static Go binary on scratch, non-root (uid/gid 65532).
#   docker build -t <registry>/<project>/n8n-git-service:<tag> .
# Base image is a build arg so CI can point it at the internal Harbor mirror:
#   --build-arg GO_IMAGE=<registry>/library/golang:1.27.2-alpine
# No secret is baked in: GITLAB_TOKEN, N8N_API_KEY, SERVICE_API_TOKEN come from
# the Kubernetes Secret at runtime.
# =============================================================================
ARG GO_IMAGE=golang:1.27.2-alpine

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS go-build
ARG TARGETOS=linux
ARG TARGETARCH
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -buildid=" -o /out/app ./cmd/n8n-git-service
# Non-root user without a shell.
RUN echo "app:x:65532:65532:app:/nonexistent:/sbin/nologin" > /out/passwd && \
    echo "app:x:65532:" > /out/group

FROM scratch
LABEL org.opencontainers.image.title="n8n-git-service" \
      org.opencontainers.image.source="https://gitlab.devops.btn.co.id/platform/n8n-git-service"
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
