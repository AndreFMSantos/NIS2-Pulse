.PHONY: all test lint build check-sources clean

all: test lint build

test:
	go test -v -race ./...

lint:
	golangci-lint run

# Confirms that every RFC quote cited by the report catalog exists in the RFC text.
# Reads the RFCs from rfc-editor.org, or from $(NIS2_RFC_DIR) (files rfcNNNN.txt) when set.
check-sources:
	NIS2_CHECK_SOURCES=1 go test -count=1 -run TestRFCQuotesExist -v ./internal/catalog

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$$(git describe --tags --always --dirty 2>/dev/null || echo dev)" -o bin/nis2-pulse ./cmd/nis2-pulse

clean:
	rm -rf bin/
