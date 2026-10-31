.PHONY: all build build_release release upx clean install test lint vet coverage ci vuln

DESTDIR = ~/.local
PREFIX = $(DESTDIR)/bin

GO_SOURCES = $(shell find . -name \*.go) go.sum go.mod

MAIN_BIN_DIR = cmd/bx
MAIN_BIN_FILE = bx
MAIN_BIN = $(MAIN_BIN_DIR)/$(MAIN_BIN_FILE)

VERSION = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LINT_VERSION = v2.15.0
VULN_VERSION = v1.9.0

GOOS =
GOARCH =
GOLDFLAGS += -X main.Version=$(VERSION)
GOFLAGS += -trimpath -buildvcs=false -ldflags "$(GOLDFLAGS)"
CGO_ENABLED = 1

all: build

build: $(MAIN_BIN)

$(MAIN_BIN): $(GO_SOURCES)
	cd $(MAIN_BIN_DIR); GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS)

build_release: GOLDFLAGS += -s -w
build_release: GOFLAGS += -trimpath -mod=readonly
build_release: build

upx:
	upx -qq --best $(MAIN_BIN)

release: build_release upx

clean:
	rm -f $(MAIN_BIN)*
	go clean

test:
	go test -cover -coverprofile .coverage ./...

coverage: test
	go tool cover -html .coverage

vet:
	go vet ./...

lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION) run ./...

install: release
	mkdir -p $(PREFIX)
	cp $(MAIN_BIN) $(PREFIX)

install_unpacked: build_release
	mkdir -p $(PREFIX)
	cp $(MAIN_BIN) $(PREFIX)

update_dependencies:
	go get -u ./...
	go mod tidy

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(VULN_VERSION) ./...

ci: clean vet test lint vuln build
