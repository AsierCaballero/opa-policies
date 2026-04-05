BINARY=opa-policies
POLICIES=./policies/...

build:
	go build -o $(BINARY) .

test:
	go test ./...
	opa test $(POLICIES)

lint:
	golangci-lint run ./...
	opa fmt -d $(POLICIES)

validate-examples: build
	./$(BINARY) validate examples/k8s/bad-pod.yaml
	./$(BINARY) validate examples/docker/bad.Dockerfile
	./$(BINARY) validate examples/github/bad-workflow.yaml

.PHONY: build test lint validate-examples
