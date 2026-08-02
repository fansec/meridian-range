package com.meridian.ci.observability;

import com.meridian.ci.config.BuildAssistantProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Emits one structured (ECS) access record per HTTP request to the {@code mcp.access} logger, which the
 * node's log collector ships to the SIEM.
 *
 * <p><b>Detection-engineering note.</b> This filter records only RAW request facts: method, path, status,
 * the {@code Origin} and {@code Host} headers, user agent, source address, and the {@code sessionId} query
 * parameter. It deliberately does NOT compute any verdict (no "cross_origin", no "foreign_host"). Deriving
 * whether a request is a cross-origin session hijack is the SOC's job, done in an ingest pipeline, because
 * in the real world the SOC does not control this (vulnerable) application and cannot trust it to
 * self-incriminate. See modules/01-cors-session-hijack/detection/elastic.md.
 */
@Component
@Order(1)
public class AccessLogFilter extends OncePerRequestFilter {

    private static final Logger ACCESS = LoggerFactory.getLogger("mcp.access");

    private final BuildAssistantProperties props;

    public AccessLogFilter(BuildAssistantProperties props) {
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } finally {
            record(request, response);
        }
    }

    private void record(HttpServletRequest req, HttpServletResponse res) {
        String path = req.getRequestURI();
        if (path != null && path.startsWith("/actuator")) {
            return; // operational probes are not part of the application access dataset
        }
        String origin = req.getHeader("Origin");
        String host = req.getHeader("Host");
        String sessionId = req.getParameter("sessionId");

        put("event.dataset", "mcp.access");
        put("event.category", "web");
        put("http.request.method", req.getMethod());
        put("url.path", path);
        put("url.query", req.getQueryString());
        put("http.response.status_code", Integer.toString(res.getStatus()));
        put("http.request.headers.origin", origin);
        put("http.request.headers.host", host);
        put("user_agent.original", req.getHeader("User-Agent"));
        put("source.ip", req.getRemoteAddr());
        put("mcp.session.id", sessionId);
        try {
            ACCESS.info("{} {} -> {}", req.getMethod(), path, res.getStatus());
        } finally {
            MDC.clear();
        }
        mirror(req, res, origin, host, sessionId);
    }

    private static void put(String key, String value) {
        if (value != null) {
            MDC.put(key, value);
        }
    }

    /**
     * Optional compact mirror to a shared file for the screencast / live-tail rig. Best-effort; a write
     * error never disrupts request handling. Off unless {@code buildassistant.access-log-file} is set.
     */
    private void mirror(HttpServletRequest req, HttpServletResponse res, String origin, String host, String sessionId) {
        String file = props.accessLogFile();
        if (file == null || file.isBlank()) {
            return;
        }
        String line = "{\"evt\":\"mcp.access\",\"method\":\"%s\",\"path\":\"%s\",\"status\":%d,\"origin\":%s,\"host\":%s,\"session_id\":%s}%n"
                .formatted(req.getMethod(), req.getRequestURI(), res.getStatus(), q(origin), q(host), q(sessionId));
        try {
            Files.writeString(Path.of(file), line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // best-effort only
        }
    }

    private static String q(String value) {
        return value == null ? "null" : "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
