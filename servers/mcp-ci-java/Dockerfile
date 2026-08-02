# Meridian CI - Build Assistant (MCP)  ·  LAB-ONLY, INSECURE BY DESIGN
#
# Multi-stage build. The build stage resolves Maven dependencies (needs egress to Maven Central at
# BUILD time on the VM). The runtime image runs on labnet (internal: true, NO egress) and publishes
# NO ports - see ../../docker-compose.yml and ../../SECURITY.md. EXPOSE is metadata only.
#
# The image pins the VULNERABLE MCP Java SDK 1.0.0 (CVE-2026-34237) BY DEFAULT; do not change that for
# the anchor service. The MCP_SDK_VERSION build-arg exists ONLY so the mitigation can be demonstrated
# side by side: building with --build-arg MCP_SDK_VERSION=1.0.1 produces the patched "Fixed" server used
# by the vulnerable-vs-fixed comparison in docs/CVE-2026-34237-report.md. Same source, one dependency
# bump - which is exactly the one-line remediation.

# ---- build ---------------------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
# Which MCP Java SDK release to link. Default = the affected 1.0.0 (the anchor). Override to 1.0.1 /
# 1.1.1 / 0.18.3 to build the patched server for the mitigation comparison.
ARG MCP_SDK_VERSION=1.0.0
# Prime the dependency cache off the POM first so source edits don't re-resolve every build.
COPY pom.xml .
RUN mvn -B -q -DskipTests -Dmcp.sdk.version=${MCP_SDK_VERSION} dependency:go-offline || true
COPY src ./src
RUN mvn -B -q -DskipTests -Dmcp.sdk.version=${MCP_SDK_VERSION} clean package

# ---- runtime -------------------------------------------------------------------------------------
FROM eclipse-temurin:17-jre
WORKDIR /app
# A non-root service account, as any production image would use.
RUN groupadd -g 10001 appsvc \
 && useradd -u 10001 -g 10001 -M -d /app -s /usr/sbin/nologin appsvc
COPY --from=build /src/target/build-assistant-mcp.jar /app/build-assistant-mcp.jar
# Own the shared telemetry dir BEFORE dropping privileges. A named volume mounted here inherits the
# image directory's ownership when it is first created, so without this the volume lands root-owned and
# every LAB_LOG_FILE append from appsvc fails silently: the server still logs to stdout, so the attack
# looks fine while the screencast's telemetry pane sits empty.
RUN mkdir -p /var/log/lab && chown appsvc:appsvc /var/log/lab
USER appsvc
EXPOSE 8080
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0"
ENTRYPOINT ["sh","-c","exec java $JAVA_OPTS -jar /app/build-assistant-mcp.jar"]
