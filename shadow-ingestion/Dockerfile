# Build stage
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN go build -o shadow-ingestion main.go

# Run stage
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/shadow-ingestion .
COPY config.yaml ./config.yaml
EXPOSE 8080 9090
CMD ["./shadow-ingestion"]
