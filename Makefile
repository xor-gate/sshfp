export CGO_ENABLED=0
export GOPATH?=$(shell go env GOPATH)
export DESTDIR?=$(GOPATH)/bin
export GOBIN?=$(DESTDIR)

all: build
ci: env test

install:
	go get ./...

env:
	go env
	echo "---"

dep:
	go get -u ./

build:
	go build
	go install github.com/xor-gate/sshfp/cmd/sshfp

test:
	go test -v $(shell go list ./... | grep -v '^vendor\/')

lint:
	gometalinter --config .gometalinter.conf

clean:
	#rm -Rf $(TMPDIR)/debpkg*

fmt:
	gofmt -s -w .
