GO ?= go
CLANG ?= clang
CC ?= cc
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || true)
BPF_IMAGE ?= clatch-bpf-builder
BPF_OBJECT := internal/guard/gateway_bpfel.o
BPF_HEADERS ?= /usr/include/$(shell $(CC) -dumpmachine)
BINARIES := dist/clatch-linux-amd64 dist/clatch-linux-arm64
MACOS_BINARY := dist/clatch-darwin-$(shell $(GO) env GOARCH)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all bpf bpf-container macos test clean
all: $(BINARIES)

macos: $(MACOS_BINARY)
$(MACOS_BINARY): $(shell find cmd internal -name '*.go') go.mod go.sum
	mkdir -p dist
	CGO_ENABLED=0 GOOS=darwin $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $@ ./cmd/clatch

bpf: $(BPF_OBJECT)
$(BPF_OBJECT): bpf/guard.bpf.c bpf/guard.h
	$(CLANG) -O2 -g -Wall -Werror -target bpfel -I$(BPF_HEADERS) -c $< -o $@

bpf-container:
	docker build -f Dockerfile.build -t $(BPF_IMAGE) .
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$$(pwd):/src" -w /src $(BPF_IMAGE) \
		sh -ec 'clang -O2 -g -Wall -Werror -target bpfel -I/usr/include/$$(cc -dumpmachine) -c bpf/guard.bpf.c -o $(BPF_OBJECT)'

dist/clatch-linux-%: $(BPF_OBJECT) $(shell find cmd internal -name '*.go') go.mod go.sum
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=$* $(GO) build -tags embedded_bpf -trimpath -ldflags='$(LDFLAGS)' -o $@ ./cmd/clatch

test:
	$(GO) test ./...

clean:
	$(RM) $(BINARIES) $(MACOS_BINARY) $(BPF_OBJECT)
