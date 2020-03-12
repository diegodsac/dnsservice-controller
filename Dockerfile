#0.5.1
FROM atf.intranet.bb.com.br:5001/bb-infra/aic/aic-go-alpine3.9:1.0.0 as builder

ENV DEP_VERSION=v0.5.1 \
    GOPATH=/go \
    CGO_ENABLED=0 \
    GOOS=linux 

WORKDIR /usr/local/go/src/

COPY vendor/ .

COPY . dnsservice-controller/

WORKDIR /usr/local/go/src/dnsservice-controller/

RUN go build *.go

FROM atf.intranet.bb.com.br:5001/bb/lnx/lnx-alpine:3.9.6 as go

ENV DEP_VERSION=v0.5.1 \
    GOPATH=/go \
    CGO_ENABLED=0 \
    GOOS=linux \
    NAMESPACE=dnsservice \
    NAME=dnsbb

COPY --from=builder /usr/local/go/src/dnsservice-controller/controller /bin/dnsservice-controller

CMD ["/bin/dnsservice-controller"]  

