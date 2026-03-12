# Build stage
FROM ghcr.io/graalvm/graalvm-community:25 AS builder

WORKDIR /app

# Copy gradle files
COPY gradle gradle
COPY gradlew gradlew
COPY build.gradle.kts settings.gradle.kts ./

# Download dependencies
RUN ./gradlew dependencies --no-daemon

# Copy source
COPY src src

# Build native image
RUN ./gradlew nativeCompile --no-daemon

# Runtime stage
FROM gcr.io/distroless/base-nossl-debian12

WORKDIR /app

# Copy native executable
COPY --from=builder /app/build/native/nativeCompile/authorization-service .

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/authorization-service", "--health-check"] || exit 1

# Run
ENTRYPOINT ["/app/authorization-service"]
