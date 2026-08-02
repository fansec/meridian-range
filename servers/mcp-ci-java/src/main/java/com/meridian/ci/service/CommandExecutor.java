package com.meridian.ci.service;

import com.meridian.ci.config.BuildAssistantProperties;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Runs an ad-hoc build step in the CI workspace - the same primitive every CI runner exposes
 * ({@code make}, {@code sh deploy.sh}, ...). It shells out with a hard timeout and captures combined
 * output.
 *
 * <p>The tool is intentionally ungated: the point of the lab is who can <em>reach</em> this capability
 * from where, not that it exists. In the lab, the only commands ever sent are benign canaries
 * ({@code id; hostname; echo LAB_CANARY_$$}) - see SECURITY.md.
 */
@Service
public class CommandExecutor {

    private final BuildAssistantProperties props;

    public CommandExecutor(BuildAssistantProperties props) {
        this.props = props;
    }

    public String run(String command) {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command).redirectErrorStream(true);
        File ws = new File(props.workspace());
        if (ws.isDirectory()) {
            pb.directory(ws);
        }
        Process process;
        try {
            process = pb.start();
        } catch (IOException e) {
            return "build step failed to start: " + e.getMessage();
        }
        try {
            boolean finished = process.waitFor(props.commandTimeoutSeconds(), TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                return "[build step exceeded " + props.commandTimeoutSeconds() + "s and was terminated]";
            }
            byte[] out = process.getInputStream().readAllBytes();
            return new String(out, StandardCharsets.UTF_8).stripTrailing();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            return "[build step interrupted]";
        } catch (IOException e) {
            return "[failed to read build step output: " + e.getMessage() + "]";
        }
    }
}
