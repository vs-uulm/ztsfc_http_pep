GO_BUILD_TARGET=./cmd/ztsfc_http_pep/main.go
DOCKER_BUILD_TARGET=vs-uulm/ztsfc_http_pep:latest

.PHONY: main
main: go docker

.PHONY: go
go:
	go mod tidy
	go build -v $(GO_BUILD_TARGET)

.PHONY: docker
docker:
	sudo docker image rm -f $(DOCKER_BUILD_TARGET) || true
	sudo docker build -t $(DOCKER_BUILD_TARGET) .
