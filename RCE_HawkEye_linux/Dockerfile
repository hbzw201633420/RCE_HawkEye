FROM alpine:latest

LABEL maintainer="hbzw"
LABEL description="RCE HawkEye - RCE Vulnerability Scanner"
LABEL version="1.1.1"

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY rce-hawkeye /app/rce-hawkeye
COPY configs /app/configs
COPY data /app/data

RUN mkdir -p /app/reports /app/data/history && \
    chmod +x /app/rce-hawkeye

EXPOSE 8080

ENV TZ=Asia/Shanghai

ENTRYPOINT ["/app/rce-hawkeye"]
CMD ["web", "-p", "8080"]
