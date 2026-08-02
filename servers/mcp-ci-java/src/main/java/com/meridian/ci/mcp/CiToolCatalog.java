package com.meridian.ci.mcp;

import com.meridian.ci.service.BuildService;
import com.meridian.ci.service.CommandExecutor;
import io.modelcontextprotocol.json.McpJsonMapper;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * The build assistant's MCP tool surface. Every tool is a legitimate day-job CI operation:
 *
 * <ul>
 *   <li>{@code list_builds}      - enumerate recent pipeline runs</li>
 *   <li>{@code get_build_log}    - tail a run's console log</li>
 *   <li>{@code trigger_pipeline} - queue a registered pipeline</li>
 *   <li>{@code run_command}      - run an ad-hoc build step (shell) in the workspace  &lt;- the capability</li>
 * </ul>
 *
 * <p>{@code run_command} is not a "hacking tool" - ad-hoc shell is what a CI/dev assistant is for. The
 * lab's finding is not that it exists, but who can reach it from where once the transport leaks the
 * session cross-origin (CVE-2026-34237). Benign canaries only.
 */
@Component
public class CiToolCatalog {

    private static final Logger log = LoggerFactory.getLogger(CiToolCatalog.class);

    private final BuildService builds;
    private final CommandExecutor executor;
    private final McpJsonMapper json;

    public CiToolCatalog(BuildService builds, CommandExecutor executor, McpJsonMapper json) {
        this.builds = builds;
        this.executor = executor;
        this.json = json;
    }

    public List<SyncToolSpecification> specifications() {
        return List.of(listBuilds(), getBuildLog(), triggerPipeline(), runCommand());
    }

    private SyncToolSpecification listBuilds() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name("list_builds")
                .description("List recent CI pipeline runs (id, pipeline, branch, status, who, commit).")
                .inputSchema(json, "{\"type\":\"object\",\"properties\":{}}")
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, req) -> text(builds.renderRecentRuns()))
                .build();
    }

    private SyncToolSpecification getBuildLog() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name("get_build_log")
                .description("Tail the console log for a build id.")
                .inputSchema(json, """
                        {"type":"object",
                         "properties":{
                           "build_id":{"type":"integer","description":"CI build id, e.g. 4209"},
                           "tail":{"type":"integer","description":"return only the last N lines"}},
                         "required":["build_id"]}""")
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, req) -> {
                    Integer id = intArg(req, "build_id");
                    Integer tail = intArg(req, "tail");
                    if (id == null) {
                        return error("build_id is required");
                    }
                    return text(builds.renderLog(id, tail));
                })
                .build();
    }

    private SyncToolSpecification triggerPipeline() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name("trigger_pipeline")
                .description("Queue a registered CI pipeline by name.")
                .inputSchema(json, """
                        {"type":"object",
                         "properties":{
                           "name":{"type":"string","description":"registered pipeline, e.g. backend-ci"},
                           "ref":{"type":"string","description":"git ref to build (default main)"}},
                         "required":["name"]}""")
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, req) -> {
                    String name = strArg(req, "name");
                    String ref = strArg(req, "ref");
                    if (name == null || name.isBlank()) {
                        return error("name is required");
                    }
                    if (!builds.pipelineExists(name)) {
                        return error("unknown pipeline: " + name);
                    }
                    int id = builds.queue(name, ref);
                    return text("queued build #%d - pipeline %s @ %s".formatted(id, name, ref == null ? "main" : ref));
                })
                .build();
    }

    private SyncToolSpecification runCommand() {
        McpSchema.Tool tool = McpSchema.Tool.builder()
                .name("run_command")
                .description("Run an ad-hoc build step (shell command) in the CI workspace.")
                .inputSchema(json, """
                        {"type":"object",
                         "properties":{
                           "cmd":{"type":"string","description":"shell command to run in the build workspace"}},
                         "required":["cmd"]}""")
                .build();
        return SyncToolSpecification.builder()
                .tool(tool)
                .callHandler((exchange, req) -> {
                    String cmd = strArg(req, "cmd");
                    if (cmd == null || cmd.isBlank()) {
                        return error("cmd is required");
                    }
                    log.info("run_command: executing ad-hoc build step in the workspace");
                    return text(executor.run(cmd));
                })
                .build();
    }

    // ---- helpers -----------------------------------------------------------------------------------

    private static CallToolResult text(String body) {
        return CallToolResult.builder().addTextContent(body).build();
    }

    private static CallToolResult error(String body) {
        return CallToolResult.builder().addTextContent(body).isError(true).build();
    }

    private static Map<String, Object> args(CallToolRequest req) {
        Map<String, Object> a = req.arguments();
        return a == null ? Map.of() : a;
    }

    private static String strArg(CallToolRequest req, String key) {
        Object v = args(req).get(key);
        return v == null ? null : v.toString();
    }

    private static Integer intArg(CallToolRequest req, String key) {
        Object v = args(req).get(key);
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(v.toString().trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
