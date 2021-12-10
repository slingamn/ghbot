.PHONY: build gofmt

build:
	go vet ghbot.go
	go build ghbot.go

gofmt:
	gofmt -s -w ghbot.go
