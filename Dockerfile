FROM golang:latest

WORKDIR /app

COPY go.mod .
COPY go.sum .

ENV GO111MODULE=on
ENV CGO_ENABLED=1
#see which DNS resolver is being used
#ENV GODEBUG=netdns=go+2

RUN apt update
RUN apt install net-tools
RUN go mod download

COPY . ./

RUN go build -o /app/host-resolver

CMD go test -v ./...
