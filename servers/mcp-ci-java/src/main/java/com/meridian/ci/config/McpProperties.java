package com.meridian.ci.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * MCP transport + server-identity configuration ({@code mcp.*}).
 *
 * <p>The HTTP/SSE transport exposes two endpoints: an SSE stream ({@code sseEndpoint}, opened with GET)
 * and a message channel ({@code messageEndpoint}, POSTed to). On connect, the server writes an
 * {@code endpoint} SSE event whose data is {@code <messageEndpoint>?sessionId=<uuid>} - that is where the
 * session identifier is disclosed to the client.
 */
@ConfigurationProperties(prefix = "mcp")
public record McpProperties(
        String serverName,
        String serverVersion,
        String protocolVersion,
        String sseEndpoint,
        String messageEndpoint) {
}
