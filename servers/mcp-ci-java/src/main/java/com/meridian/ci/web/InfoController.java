package com.meridian.ci.web;

import com.meridian.ci.config.McpProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Lightweight service-identity endpoint. Health and build metadata are served by Spring Boot Actuator
 * at {@code /actuator/health} and {@code /actuator/info}; {@code /version} is a convenience view the
 * platform team's tooling scrapes.
 */
@RestController
public class InfoController {

    private final McpProperties mcp;

    public InfoController(McpProperties mcp) {
        this.mcp = mcp;
    }

    @GetMapping("/version")
    public Map<String, Object> version() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("service", mcp.serverName());
        body.put("version", mcp.serverVersion());
        body.put("protocol", "mcp/" + mcp.protocolVersion());
        body.put("transport", "http+sse");
        body.put("sseEndpoint", mcp.sseEndpoint());
        body.put("messageEndpoint", mcp.messageEndpoint());
        return body;
    }
}
