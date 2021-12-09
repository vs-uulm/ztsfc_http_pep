.DEFAULT_GOAL := build

.PHONY: build
build:
	go mod tidy
	go build -v ./cmd/ztsfc_http_pep

.PHONY: image
image:
	docker build -t vs-uulm/ztsfc_http_pep:1.0 .
