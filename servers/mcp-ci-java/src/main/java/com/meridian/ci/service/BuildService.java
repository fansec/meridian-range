package com.meridian.ci.service;

import com.meridian.ci.domain.Build;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The CI system's read/query surface: recent pipeline runs, their console logs, and the registered
 * pipelines a run can be queued against. This is the day-job data a build assistant answers questions
 * from. All data is fabricated and benign; nothing here touches a real repository or host.
 */
@Service
public class BuildService {

    private final List<Build> builds = new CopyOnWriteArrayList<>(List.of(
            new Build(4207, "backend-ci", "main", "passed", "alice", "a1c9f02", 214),
            new Build(4208, "web-deploy", "release/3.4", "passed", "bob", "7d3e558", 331),
            new Build(4209, "nightly-e2e", "main", "failed", "ci-bot", "b90aa11", 902),
            new Build(4210, "backend-ci", "feat/quotas", "running", "carol", "5f1d7ac", 0)));

    /** Registered pipelines: name -> the workspace build command a runner would execute. */
    private final Map<String, String> pipelines = Map.of(
            "backend-ci", "make -C /srv/build test",
            "web-deploy", "sh /srv/build/deploy.sh web",
            "nightly-e2e", "sh /srv/build/e2e.sh --full");

    private final Map<Integer, String> logs = Map.of(
            4209, String.join("\n",
                    "> nightly-e2e  main@b90aa11  (runner mrdn-ci-3)",
                    "  provision test env         (18s)  ok",
                    "  migrate db                 (4s)   ok",
                    "  e2e: checkout -> pay flow   FAILED (timeout after 30000ms)",
                    "  Error: expected order.status=paid, got=pending",
                    "  42 passed, 1 failing - artifacts/e2e-4209.xml"));

    private final AtomicInteger nextId = new AtomicInteger(4210);

    public String renderRecentRuns() {
        StringBuilder sb = new StringBuilder();
        for (Build b : builds) {
            sb.append(b.toRow()).append('\n');
        }
        return sb.toString().stripTrailing();
    }

    public String renderLog(int buildId, Integer tail) {
        String full = logs.get(buildId);
        if (full == null) {
            return "no log retained for build #" + buildId;
        }
        if (tail == null || tail <= 0) {
            return full;
        }
        String[] lines = full.split("\n");
        int from = Math.max(0, lines.length - tail);
        return String.join("\n", List.of(lines).subList(from, lines.length));
    }

    public boolean pipelineExists(String name) {
        return pipelines.containsKey(name);
    }

    public Map<String, String> registeredPipelines() {
        return new LinkedHashMap<>(pipelines);
    }

    /** Queue a registered pipeline (models an enqueue; a runner would execute the command). */
    public int queue(String name, String ref) {
        int id = nextId.incrementAndGet();
        builds.add(new Build(id, name, ref == null ? "main" : ref, "running", "copilot", "queued", 0));
        return id;
    }
}
