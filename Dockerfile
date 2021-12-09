#build stage
FROM golang:alpine AS builder
RUN apk add --no-cache git
WORKDIR /go/src/app
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./go.mod ./go.mod
COPY ./go.sum ./go.sum
RUN go get -d -v ./...
RUN go build -v ./internal/...
RUN go build -v ./cmd/ztsfc_http_pep/...

#final stage
FROM alpine:latest
# RUN apk --no-cache add ca-certificates
COPY --from=builder /go/src/app/ztsfc_http_pep /ztsfc_http_pep
RUN mkdir -p /configs
ENTRYPOINT ["/ztsfc_http_pep", "-c", "/configs/conf.yaml"]
LABEL Name=ztsfc_http_pep Version=1.0.1
EXPOSE 443
