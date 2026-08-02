package com.meridian.ci.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Build-assistant runtime configuration ({@code buildassistant.*}).
 *
 * @param workspace             directory the ad-hoc build step (run_command) executes in
 * @param commandTimeoutSeconds hard timeout applied to any ad-hoc build step
 * @param accessLogFile         optional path; when set, one compact access line is mirrored there for the
 *                              screencast / live-tail rig (best-effort). Empty in normal operation.
 */
@ConfigurationProperties(prefix = "buildassistant")
public record BuildAssistantProperties(
        String workspace,
        int commandTimeoutSeconds,
        String accessLogFile) {
}
