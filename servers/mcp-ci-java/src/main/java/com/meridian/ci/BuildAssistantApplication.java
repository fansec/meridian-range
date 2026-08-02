package com.meridian.ci;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Meridian CI - Build Assistant (MCP).
 *
 * <p>A platform-engineering service that lets a developer's coding agent drive the internal CI system
 * over the Model Context Protocol: list pipeline runs, tail build logs, queue pipelines, and run ad-hoc
 * build steps in the workspace. It is a normal Spring Boot application - dependency injection, actuator
 * health, structured logging, environment configuration - built on the official MCP Java SDK.
 *
 * <p><b>Lab note.</b> This build pins the MCP Java SDK release affected by CVE-2026-34237 and is run only
 * on the isolated lab VM. Nothing here is a hand-written vulnerability: the insecure behaviour originates
 * in the SDK transport. See {@code docs/CVE-2026-34237-report.md}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class BuildAssistantApplication {

    public static void main(String[] args) {
        SpringApplication.run(BuildAssistantApplication.class, args);
    }
}
