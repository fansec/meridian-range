package com.meridian.ci.config;

import com.meridian.ci.mcp.CiToolCatalog;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the MCP server on top of the official SDK's HTTP/SSE transport.
 *
 * <p>The vulnerability reproduced by this lab lives entirely inside
 * {@link HttpServletSseServerTransportProvider} (mcp-core 1.0.0): the transport unconditionally sets
 * {@code Access-Control-Allow-Origin: *} and discloses the session id on the SSE {@code endpoint} event
 * (CVE-2026-34237, CWE-942). This application does not add or remove any CORS handling - it simply uses
 * the transport as shipped, which is exactly how an affected deployment behaves.
 */
@Configuration
public class McpServerConfig {

    /** Adapt Spring Boot's Jackson {@link ObjectMapper} to the SDK's JSON abstraction. */
    @Bean
    public McpJsonMapper mcpJsonMapper(ObjectMapper objectMapper) {
        return new JacksonMcpJsonMapper(objectMapper);
    }

    /** The affected HTTP/SSE transport provider (also a {@code jakarta} servlet). */
    @Bean
    public HttpServletSseServerTransportProvider mcpTransportProvider(McpJsonMapper mapper, McpProperties props) {
        return HttpServletSseServerTransportProvider.builder()
                .jsonMapper(mapper)
                .baseUrl("")
                .sseEndpoint(props.sseEndpoint())
                .messageEndpoint(props.messageEndpoint())
                .build();
    }

    /** The MCP server bound to the transport, advertising the build-assistant tools. */
    @Bean(destroyMethod = "close")
    public McpSyncServer mcpSyncServer(HttpServletSseServerTransportProvider provider,
                                       McpProperties props,
                                       CiToolCatalog catalog) {
        McpSyncServer server = McpServer.sync(provider)
                .serverInfo(props.serverName(), props.serverVersion())
                .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
                .build();
        catalog.specifications().forEach(server::addTool);
        return server;
    }

    /**
     * Register the transport servlet for both the SSE stream and the message channel. Async must be
     * enabled for the long-lived SSE connection.
     */
    @Bean
    public ServletRegistrationBean<HttpServletSseServerTransportProvider> mcpTransportServlet(
            HttpServletSseServerTransportProvider provider, McpProperties props) {
        ServletRegistrationBean<HttpServletSseServerTransportProvider> registration =
                new ServletRegistrationBean<>(provider, props.sseEndpoint(), props.messageEndpoint());
        registration.setName("mcpHttpSseTransport");
        registration.setAsyncSupported(true);
        registration.setLoadOnStartup(1);
        return registration;
    }
}
