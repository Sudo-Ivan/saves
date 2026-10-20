FUZZTIME ?= 20s
PKGS := ./...
BIN := bin

.PHONY: build test race vet lint fuzz bench cover vuln check docs sandbox-check docker clean

build:
	go build -o $(BIN)/savesd ./cmd/savesd
	go build -o $(BIN)/savesctl ./cmd/savesctl

test:
	go test -count=1 $(PKGS)

race:
	go test -race -count=1 $(PKGS)

vet:
	go vet $(PKGS)

lint:
	@if command -v staticcheck >/dev/null 2>&1; then staticcheck $(PKGS); else echo "staticcheck not installed, skipping"; fi
	@if command -v gosec >/dev/null 2>&1; then gosec -quiet -tests=false $(PKGS); else echo "gosec not installed, skipping"; fi

# Discover fuzz targets per package and run each for FUZZTIME.
fuzz:
	@for pkg in $$(go list $(PKGS)); do \
		dir=$$(go list -f '{{.Dir}}' $$pkg); \
		for t in $$(cd $$dir && go test -list '^Fuzz' . 2>/dev/null | grep '^Fuzz'); do \
			echo "== $$t ($$pkg) $(FUZZTIME)"; \
			(cd $$dir && go test -run='^$$' -fuzz="^$$t\$$" -fuzztime=$(FUZZTIME) .) || exit 1; \
		done; \
	done

bench:
	go test -run='^$$' -bench=. -benchmem $(PKGS)

cover:
	go test -count=1 -coverprofile=coverage.out $(PKGS)
	go tool cover -func=coverage.out | tail -1

vuln:
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck $(PKGS); else echo "govulncheck not installed, skipping"; fi

check: vet lint race

docs:
	go run ./internal/config/gendoc > docs/config.md

sandbox-check: build
	./$(BIN)/savesd sandbox-check

CONTAINER ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo docker)

docker:
	$(CONTAINER) build -t saves .

clean:
	rm -rf $(BIN) coverage.out coverage.html
