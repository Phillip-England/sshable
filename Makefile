GO ?= go
INSTALL ?= install

GO_BIN := $(shell $(GO) env GOBIN)
GO_PATH := $(shell $(GO) env GOPATH)
BINDIR ?= $(if $(GO_BIN),$(GO_BIN),$(firstword $(subst :, ,$(GO_PATH)))/bin)

.PHONY: build install test serve

build:
	$(GO) build -o sshable .

install: build
	$(INSTALL) -d "$(BINDIR)"
	$(INSTALL) -m 755 sshable "$(BINDIR)/sshable"
	@printf 'Installed %s\n' "$(BINDIR)/sshable"

test:
	$(GO) test ./...

serve:
	$(GO) run . serve
