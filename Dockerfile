FROM docker.io/library/golang:1.25-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 go build -o /bin/gateway         ./cmd/gateway/
RUN CGO_ENABLED=0 go build -o /bin/mockidentity     ./cmd/mockidentity/
RUN CGO_ENABLED=0 go build -o /bin/mockbackend      ./cmd/mockbackend/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/gateway        /bin/gateway
COPY --from=builder /bin/mockidentity   /bin/mockidentity
COPY --from=builder /bin/mockbackend    /bin/mockbackend
