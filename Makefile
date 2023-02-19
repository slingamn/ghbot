.PHONY: build gofmt

# disable linking against native libc / libpthread by default;
# this can be overridden by passing CGO_ENABLED=1 to make
export CGO_ENABLED ?= 0

build:
	go vet ghbot.go
	go build ghbot.go

gofmt:
	gofmt -s -w ghbot.go
