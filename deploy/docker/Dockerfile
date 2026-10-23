# Build from the repo root: docker build -f deploy/docker/Dockerfile --build-arg VERSION=v1.2.3 \
#   --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ) -t app:v1.2.3 .
# BUILD_TIME is required: job schedules change only for a build at least as new as the one that wrote them.
# No HEALTHCHECK: the image has no shell or curl, so the orchestrator probes /readyz and /livez.
# The build stage runs on the builder's platform and cross-compiles, so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=""
ARG BUILD_TIME=""
ARG TARGETOS
ARG TARGETARCH
RUN test -n "$BUILD_TIME" || { echo "BUILD_TIME is required: --build-arg BUILD_TIME=<build time, RFC 3339 UTC>" >&2; exit 1; }
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -o /out/app \
    -ldflags "-s -w \
    -X github.com/PuckxPuck/keel/internal/kit/buildinfo.version=${VERSION} \
    -X github.com/PuckxPuck/keel/internal/kit/buildinfo.commit=${COMMIT} \
    -X github.com/PuckxPuck/keel/internal/kit/buildinfo.buildTime=${BUILD_TIME}" \
    ./cmd/app

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --from=build /out/app /app
USER nonroot:nonroot
ENV APP_HTTP_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/app"]
CMD ["serve"]
