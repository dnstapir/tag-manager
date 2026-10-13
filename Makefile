VERSION:=$(shell cat ./VERSION)
COMMIT:=$(shell git describe --dirty=+WiP --always 2> /dev/null || echo "no-vcs")
OUT:=$(CURDIR)/out

.PHONY: all build outdir test coverage fmt vet clean ko checkfmt

all: build

build: outdir
	go build -v -ldflags "-X main.commit=$(COMMIT)" -o $(OUT)/ ./cmd/...

outdir:
	-mkdir -p $(OUT)

test:
	go test ./...

coverage: outdir
	go test -coverprofile=$(OUT)/coverage.out ./...
	go tool cover -html="$(OUT)/coverage.out" -o $(OUT)/coverage.html

fmt:
	go fmt ./...

checkfmt:
	@files=$$(gofmt -l ./); \
	if [ -n "$$files" ]; then \
		printf '%s\n' "$$files"; \
		exit 1; \
	fi

vet:
	go vet ./...

clean:
	-rm -rf $(OUT)

ko:
	ko build -L -B ./cmd/tag-manager
