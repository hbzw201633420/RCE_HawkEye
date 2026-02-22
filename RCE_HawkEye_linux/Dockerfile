FROM golang:1.21-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o rce-hawkeye ./cmd/rce-hawkeye

FROM alpine:latest

LABEL maintainer="hbzw"
LABEL description="RCE HawkEye - RCE Vulnerability Scanner"
LABEL version="1.1.2"

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/rce-hawkeye /app/rce-hawkeye
COPY configs /app/configs
COPY data /app/data

RUN mkdir -p /app/reports /app/data/history && \
    chmod +x /app/rce-hawkeye

EXPOSE 8080

ENV TZ=Asia/Shanghai

ENTRYPOINT ["/app/rce-hawkeye"]
CMD ["web", "-p", "8080"]
