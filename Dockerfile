FROM golang:1.17-alpine
# TODO: Investigate why Alpine 1.18 is broken :|

WORKDIR /app

COPY go.mod .
COPY go.sum .

ENV GO111MODULE=on
# need CGO disabled since container has no cgo installed
ENV CGO_ENABLED=0
#see which DNS resolver is being used
#ENV GODEBUG=netdns=go+2

RUN go mod download

COPY . ./

RUN go build -o /host-resolver
CMD /host-resolver run -a 127.0.0.1 -t 54 -u 53 -c "host.rd.internal=111.111.111.111,host2.rd.internal=222.222.222.222" & go test -v ./...
