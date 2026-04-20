# ---- Stage 1: Go builder ----
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/shadow-ingestion .

# ---- Stage 2: runtime ----
FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /out/shadow-ingestion ./shadow-ingestion
COPY config.yaml ./config.yaml
EXPOSE 8080 9090
CMD ["./shadow-ingestion"]
