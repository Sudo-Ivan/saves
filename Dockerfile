# SPDX-License-Identifier: 0BSD
FROM docker.io/library/golang:1.27-alpine@sha256:cd410a5c6686417875bc4815688e96ae9769f8562debc545d29fe58e73d174f0 AS builder
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -buildid= -X github.com/Sudo-Ivan/saves/internal/app.Version=${VERSION}" -o /out/savesd ./cmd/savesd && \
    go build -trimpath -ldflags "-s -w -buildid= -X github.com/Sudo-Ivan/saves/internal/app.Version=${VERSION}" -o /out/savesctl ./cmd/savesctl && \
    mkdir -p /data && chown 65532:65532 /data && chmod 0700 /data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d
ARG VERSION=dev
LABEL org.opencontainers.image.title="saves" \
      org.opencontainers.image.description="Saves save-state server" \
      org.opencontainers.image.source="https://github.com/Sudo-Ivan/saves" \
      org.opencontainers.image.licenses="0BSD" \
      org.opencontainers.image.version="${VERSION}"
USER 65532:65532
COPY --from=builder /out/savesd /out/savesctl /usr/local/bin/
COPY --from=builder --chown=65532:65532 /data /data
COPY deploy/docker/config.json /etc/saves/config.json
WORKDIR /data
VOLUME /data
EXPOSE 8080/tcp 8443/tcp 8443/udp
ENTRYPOINT ["savesd"]
CMD ["serve", "-config", "/etc/saves/config.json"]
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD ["/usr/local/bin/savesd", "healthcheck", "-url", "http://127.0.0.1:9090/healthz"]
