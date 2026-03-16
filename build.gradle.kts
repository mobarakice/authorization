import org.springframework.boot.gradle.tasks.bundling.BootBuildImage

plugins {
    java
    id("org.springframework.boot") version "4.0.0"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.graalvm.buildtools.native") version "0.10.4"
    id("com.google.protobuf") version "0.9.4"
}

group = "com.pss"
version = "1.0.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
    maven { url = uri("https://repo.spring.io/milestone") }
}

val grpcVersion = "1.69.0"
val protobufVersion = "4.29.3"
val caffeineVersion = "3.1.8"

dependencies {
    // Spring Boot Starters
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    
    // gRPC
    implementation("io.grpc:grpc-netty-shaded:$grpcVersion")
    implementation("io.grpc:grpc-protobuf:$grpcVersion")
    implementation("io.grpc:grpc-stub:$grpcVersion")
    implementation("io.grpc:grpc-services:$grpcVersion")
    implementation("net.devh:grpc-spring-boot-starter:3.1.0.RELEASE")
    
    // javax.annotation for gRPC generated code (required for Java 9+)
    implementation("javax.annotation:javax.annotation-api:1.3.2")
    
    // Cache - Caffeine L1
    implementation("com.github.ben-manes.caffeine:caffeine:$caffeineVersion")
    
    // Database
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")
    
    // Redis serialization with MessagePack
    implementation("org.msgpack:msgpack-core:0.9.8")
    implementation("org.msgpack:jackson-dataformat-msgpack:0.9.8")
    
    // Protobuf
    implementation("com.google.protobuf:protobuf-java:$protobufVersion")
    
    // Kafka for event sync
    implementation("org.springframework.kafka:spring-kafka")
    
    // Utilities
    implementation("org.mapstruct:mapstruct:1.6.3")
    annotationProcessor("org.mapstruct:mapstruct-processor:1.6.3")
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok-mapstruct-binding:0.2.0")
    
    // API Documentation - Swagger/OpenAPI (2.8.3 for Spring Boot 4.0 compatibility)
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.3")
    
    // Observability
    implementation("io.micrometer:micrometer-registry-prometheus")
    implementation("io.micrometer:micrometer-tracing-bridge-otel")
    
    // Testing
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(platform("org.testcontainers:testcontainers-bom:1.20.4"))
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.testcontainers:kafka")
    testImplementation("com.redis:testcontainers-redis:2.2.2")
    testAnnotationProcessor("org.projectlombok:lombok")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// Protobuf configuration
protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:$protobufVersion"
    }
    plugins {
        create("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:$grpcVersion"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.plugins {
                create("grpc")
            }
        }
    }
}

// GraalVM Native Image configuration
graalvmNative {
    binaries {
        named("main") {
            imageName.set("authorization-service")
            mainClass.set("com.pss.authorization.AuthorizationApplication")
            buildArgs.addAll(
                "--enable-preview",
                "-H:+ReportExceptionStackTraces",
                "--initialize-at-build-time=org.slf4j",
                "--initialize-at-run-time=io.netty"
            )
        }
    }
    toolchainDetection.set(false)
}

tasks.named<BootBuildImage>("bootBuildImage") {
    builder.set("paketobuildpacks/builder-jammy-buildpackless-tiny")
    buildpacks.set(listOf("paketobuildpacks/java-native-image"))
    environment.set(mapOf(
        "BP_NATIVE_IMAGE" to "true",
        "BP_JVM_VERSION" to "25"
    ))
}

tasks.withType<Test> {
    useJUnitPlatform()
}

// Source sets for generated protobuf
sourceSets {
    main {
        java {
            srcDirs("build/generated/source/proto/main/java")
            srcDirs("build/generated/source/proto/main/grpc")
        }
    }
}

// Disable AOT processing (incompatible with SpringDoc + Protobuf in Spring Boot 4.0)
tasks.named("processAot") {
    enabled = false
}
tasks.named("processTestAot") {
    enabled = false
}

// Configure bootJar to not require AOT
tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    dependsOn("compileJava", "processResources")
}
