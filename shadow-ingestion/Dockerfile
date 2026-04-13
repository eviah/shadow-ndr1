FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY shadow-ingestion ./shadow-ingestion
COPY config.yaml ./config.yaml
EXPOSE 8080 9090
CMD ["./shadow-ingestion"]
