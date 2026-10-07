# Alternative to `make image` for hosts with Docker/BuildKit. Both build
# stages run on the build host and cross-compile, so no QEMU is needed:
#
#   docker buildx build --platform linux/arm64 -o type=docker,dest=dist/v2ray-client-go-arm64.tar \
#     -t v2ray-client-go:latest .
#
# Build a subset of protocols with --build-arg TAGS="vless reality".

# --- web UI ---
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- Go binary ---
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
RUN apk add --no-cache upx
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
