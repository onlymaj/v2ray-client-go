# Alternative to `make image` for hosts with Docker/BuildKit. Both build
# stages run on the build host and cross-compile, so no QEMU is needed:
#
#   docker buildx build --platform linux/arm64 -o type=docker,dest=dist/v2ray-client-go-arm64.tar \
#     -t v2ray-client-go:latest .
#
# Build a subset of protocols with --build-arg TAGS="vless reality".
#
# Base images are pinned by the digest of their multi-arch index. To refresh
# one, take the docker-content-digest of the new tag, e.g.:
#
#   tok=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull" | jq -r .token)
#   curl -fsSI -H "Authorization: Bearer $tok" \
#     -H "Accept: application/vnd.oci.image.index.v1+json" \
#     https://registry-1.docker.io/v2/library/node/manifests/22-alpine | grep -i docker-content-digest
#
# (or `docker buildx imagetools inspect node:22-alpine`).

# --- web UI ---
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- Go binary ---
FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
# Same pinned UPX as the Makefile, checked against its sha256 (not apk).
ARG BUILDARCH
ARG UPX_VER=5.2.1
RUN case "$BUILDARCH" in \
      amd64) sum=402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657 ;; \
      arm64) sum=a72d112c5970a904a31da0b9c84f919bc16b9a311787c12245508544a78c7d36 ;; \
      *) echo "no pinned upx for $BUILDARCH" >&2; exit 1 ;; \
    esac \
 && wget -qO /tmp/upx.tar.xz https://github.com/upx/upx/releases/download/v$UPX_VER/upx-$UPX_VER-${BUILDARCH}_linux.tar.xz \
 && echo "$sum  /tmp/upx.tar.xz" | sha256sum -c - \
 && xzcat /tmp/upx.tar.xz | tar -x -C /usr/local/bin --strip-components=1 upx-$UPX_VER-${BUILDARCH}_linux/upx \
 && rm /tmp/upx.tar.xz
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./internal/web/dist
ARG TARGETARCH
ARG TAGS="vless vmess reality ws grpc"
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
      go build -trimpath -ldflags="-s -w -buildid=" -tags "$TAGS" \
      -o /out/v2ray-client-go ./cmd/v2ray-client-go \
 && upx -q --best --lzma /out/v2ray-client-go \
 && mkdir -p /out/data /out/tmp && chmod 1777 /out/tmp

# --- runtime ---
FROM scratch
COPY --from=build /out/ /
ENV GOMEMLIMIT=32MiB CONFIG_DIR=/data
VOLUME /data
ENTRYPOINT ["/v2ray-client-go"]
