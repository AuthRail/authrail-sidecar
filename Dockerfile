# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.26-alpine
ARG VERSION=development
ARG REVISION=unknown
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG REVISION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY sidecar ./sidecar
COPY docker/launcher ./docker/launcher
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/authrail-sidecar ./cmd/authrail-sidecar \
 && GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -trimpath -o /out/authrail-container ./docker/launcher \
 && mkdir -p /out/state/authrail \
 && chmod 0700 /out/state/authrail
RUN case "$VERSION:$REVISION" in *[!A-Za-z0-9._:-]*) exit 1 ;; esac \
 && printf '{"version":"%s","revision":"%s","bundleFormat":1,"localProtocolFormat":1,"stateFormat":1}\n' "$VERSION" "$REVISION" > /out/manifest.json

FROM scratch
ARG VERSION=development
ARG REVISION=unknown
LABEL org.opencontainers.image.title="AuthRail Sidecar" \
      org.opencontainers.image.source="https://github.com/AuthRail/authrail-sidecar" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/authrail-sidecar /usr/local/bin/authrail-sidecar
COPY --from=build /out/authrail-container /usr/local/bin/authrail-container
COPY --from=build --chown=10001:10001 /out/state/ /var/lib/
COPY LICENSE /LICENSE
COPY README.md PROTOCOL.md COMPATIBILITY.md RELEASING.md /usr/share/authrail/
COPY docker/README.md /usr/share/authrail/docker/README.md
COPY conformance /usr/share/authrail/conformance
COPY integrations/openshell /usr/share/authrail/integrations/openshell
COPY --from=build /out/manifest.json /usr/share/authrail/manifest.json
USER 10001:10001
ENV AUTHRAIL_STATE_FILE=/var/lib/authrail/state.json
WORKDIR /var/lib/authrail
VOLUME ["/var/lib/authrail"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/authrail-container", "health"]
ENTRYPOINT ["/usr/local/bin/authrail-container"]
