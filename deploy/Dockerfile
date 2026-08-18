# 多開CF代理 — 多構建階段 Dockerfile
# TARGETARCH 由 docker buildx 自動注入（amd64/arm64）；本地單架構構建時兜底 amd64
FROM golang:1.26-alpine AS build
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/multi-cf-proxy .

FROM alpine:3.20
LABEL org.opencontainers.image.title="multi-cf-proxy" \
      org.opencontainers.image.description="多開CF代理：多條 Cloudflare WARP 隧道聚合，SOCKS5/HTTP 帳密分流出口，Web 管理" \
      org.opencontainers.image.source="https://github.com/s12ryt/multi-cf-proxy" \
      org.opencontainers.image.licenses="MIT"
RUN adduser -D -H mcp
COPY --from=build /out/multi-cf-proxy /usr/local/bin/multi-cf-proxy
USER mcp
VOLUME /config
EXPOSE 1080 8080 8081
ENTRYPOINT ["multi-cf-proxy", "-config", "/config/config.json"]
