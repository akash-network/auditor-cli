BINARY := auditor-cli
GO ?= go

.PHONY: build
build:
	GOWORK=off $(GO) build -o ./.cache/bin/$(BINARY) ./cmd/auditor-cli

.PHONY: install
install:
	GOWORK=off $(GO) install ./cmd/auditor-cli

.PHONY: test
test:
	GOWORK=off $(GO) test ./...

.PHONY: vet
vet:
	GOWORK=off $(GO) vet ./...

.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --clean --skip=publish
