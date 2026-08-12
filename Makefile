OS      := $(shell uname -s | tr A-Z a-z)
ifeq ($(OS), darwin)
    EXT :=
else ifeq ($(OS), linux)
    EXT :=
else
    EXT := .exe
endif

BINARY  := netscanner$(EXT)
DASH    := dashboard$(EXT)
ENRICH  := enrich$(EXT)
LDFLAGS := -s -w
GO      ?= go

.PHONY: all build dashboard enrich run run-panel deploy test vet fmt tidy clean

all: build dashboard enrich

build:
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/scanner

dashboard:
	$(GO) build -ldflags="$(LDFLAGS)" -o $(DASH) ./cmd/dashboard

enrich:
	$(GO) build -ldflags="$(LDFLAGS)" -o $(ENRICH) ./cmd/enrich

run:
	$(GO) run ./cmd/scanner --cidr 127.0.0.1/32 --ports 80,443 --workers 16 --timeout 1000

run-panel:
	$(GO) run ./cmd/dashboard -file casa.jsonl

deploy:
	@if [ -f deploy.sh ]; then ./deploy.sh; else .\deploy.ps1; fi

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BINARY) $(DASH) $(ENRICH)
	rm -rf tools
