# v2ray-client-go. Docker-free build: pinned tools are downloaded into
# .tools/ and checked against their published sha256.

TAGS     ?= vless vmess reality ws grpc
IMAGE    := v2ray-client-go
TAR      := dist/$(IMAGE)-arm64.tar
BIN      := dist/v2ray-client-go
MAX_SIZE := 8388608   # 8 MiB

UPX_VER  := 5.2.1
UPX_SHA  := 402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657
XRAY_VER := 26.3.27
XRAY_SHA := 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
UPX      := .tools/upx
XRAY     := .tools/xray

GOBUILD := CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -buildid="

.PHONY: build build-ui embed-ui test interop image size probe probe-image clean

build: $(UPX) embed-ui
	@mkdir -p dist
	$(GOBUILD) -tags "$(TAGS)" -o $(BIN).raw ./cmd/v2ray-client-go
	rm -f $(BIN) && $(UPX) -q --best --lzma -o $(BIN) $(BIN).raw >/dev/null
	@ls -l $(BIN).raw $(BIN) | awk '{print $$5, $$9}'

build-ui:
	cd web && npm ci --no-audit --no-fund && npm run size

# Copy the built UI into the embed directory. Only the .gz files are kept;
# internal/web decompresses on the fly for clients without gzip support.
embed-ui:
	@if [ -d web/dist ]; then \
	  find internal/web/dist -mindepth 1 ! -name .gitkeep -delete; \
	  cd web/dist && find . -name '*.gz' -exec sh -c 'mkdir -p "../../internal/web/dist/$$(dirname "$$1")" && cp "$$1" "../../internal/web/dist/$$1"' _ {} \; ; \
	  echo "embedded UI: $$(du -sb ../../internal/web/dist | cut -f1) bytes"; \
	else echo "web/dist missing: run make build-ui (embedding placeholder)"; fi

test:
	go vet -tags "$(TAGS)" ./...
	go test -tags "$(TAGS)" ./...

interop: $(XRAY)
	XRAY_BIN=$(abspath $(XRAY)) go test -tags "$(TAGS) interop" -count=1 ./test/interop/...

image: build
	go run ./tools/mkimage -out $(TAR) -tag $(IMAGE):latest -arch arm64 \
	  -file $(BIN):/v2ray-client-go:0755 -dir /data -dir /tmp \
	  -entrypoint /v2ray-client-go -env GOMEMLIMIT=32MiB -env CONFIG_DIR=/data

size: image
	scripts/size-check.sh $(TAR) $(MAX_SIZE)

probe: $(UPX)
	@mkdir -p dist
	$(GOBUILD) -o dist/probe.raw ./probe
	rm -f dist/probe && $(UPX) -q --best --lzma -o dist/probe dist/probe.raw >/dev/null
	@ls -l dist/probe.raw dist/probe | awk '{print $$5, $$9}'

probe-image: probe
	go run ./tools/mkimage -out dist/v2ray-probe-arm64.tar -tag v2ray-probe:latest -arch arm64 \
	  -file dist/probe:/probe:0755 -entrypoint /probe

$(UPX):
	@mkdir -p .tools
	curl -fsSL -o .tools/upx.tar.xz https://github.com/upx/upx/releases/download/v$(UPX_VER)/upx-$(UPX_VER)-amd64_linux.tar.xz
	echo "$(UPX_SHA)  .tools/upx.tar.xz" | sha256sum -c -
	tar -xJf .tools/upx.tar.xz -C .tools --strip-components=1 upx-$(UPX_VER)-amd64_linux/upx
	rm .tools/upx.tar.xz

$(XRAY):
	@mkdir -p .tools
	curl -fsSL -o .tools/xray.zip https://github.com/XTLS/Xray-core/releases/download/v$(XRAY_VER)/Xray-linux-64.zip
	echo "$(XRAY_SHA)  .tools/xray.zip" | sha256sum -c -
	cd .tools && python3 -c 'import zipfile; z=zipfile.ZipFile("xray.zip"); z.extract("xray"); import os; os.chmod("xray",0o755)'
	rm .tools/xray.zip

clean:
	rm -rf dist
