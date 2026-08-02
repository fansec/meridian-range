package com.meridian.ci.domain;

/** A single CI pipeline run. Fabricated lab data - no real repositories, hosts, or people. */
public record Build(
        int id,
        String pipeline,
        String branch,
        String status,   // passed | failed | running
        String who,
        String commit,
        int durationSeconds) {

    public String toRow() {
        return "#%d  %-11s %-13s %-7s %s (%s)".formatted(id, pipeline, branch, status, who, commit);
    }
}
