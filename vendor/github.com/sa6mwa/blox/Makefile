.PHONY: dependencies test build clean upgrade

all: dependencies test build

go.mod:
	go mod init github.com/sa6mwa/blox
	go mod tidy

dependencies: go.mod
	go get -v -d ./...

test: go.mod
	go test -cover ./...

build: go.mod demo

demo:
	go build -o demo ./example

clean:
	rm -f demo

upgrade: go.mod
	go get -u
