BINARY  := netscanner.exe
LDFLAGS := -s -w
GO      ?= go

.PHONY: all build dashboard enrich run test vet fmt tidy clean

all: build dashboard enrich

build:
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/scanner

dashboard:
	$(GO) build -ldflags="$(LDFLAGS)" -o dashboard.exe ./cmd/dashboard

enrich:
	$(GO) build -ldflags="$(LDFLAGS)" -o enrich.exe ./cmd/enrich

run:
	$(GO) run ./cmd/scanner --cidr 127.0.0.1/32 --ports 80,443 --workers 16 --timeout 1000

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

tidy:
	$(GO) mod tidy

clean:
	rm -f $(BINARY) dashboard.exe enrich.exe
	rm -rf tools
