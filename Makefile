.PHONY: build
build:
	go mod tidy
	go build -v ./cmd/ztsfc_http_pep

.DEFAULT_GOAL := build
