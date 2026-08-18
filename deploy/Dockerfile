# 多開CF代理 — 多構建階段 Dockerfile
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/multi-cf-proxy .

FROM alpine:3.20
RUN adduser -D -H mcp
COPY --from=build /out/multi-cf-proxy /usr/local/bin/multi-cf-proxy
USER mcp
VOLUME /config
EXPOSE 1080 8080 8081
ENTRYPOINT ["multi-cf-proxy", "-config", "/config/config.json"]
