# Why I Built a Defensive MCP Attack Range

I built Meridian Range because I wanted a better answer to a common security question: when an MCP or AI-agent vulnerability is published, what will it actually look like in an environment a defender operates?

A CVE, a proof of concept, and a list of remediation steps are useful. They do not automatically tell me which requests to log, what sequence of events matters, or how to write a detection that will survive contact with a real SIEM. I wanted a small, repeatable way to connect those pieces.

Meridian Range is my defensive research range for MCP and AI-agent attacks. Each module starts with an already-published insecure default, reproduces it in an isolated lab, records the observable telemetry, and ships a detection alongside the reproduction. The outcome I care about is not a clever exploit. It is a defender being able to say, "I know what this looks like, and I know how to find it."

## The loop I wanted to make routine

The project follows one simple loop:

```text
reproduce -> observe -> detect -> verify
```

I first make the vulnerable behavior happen using a harmless proof-of-execution canary. I then identify the telemetry that a security team can realistically collect, turn it into a detection rule with test cases, and verify the complete loop on an isolated VM.

That order matters to me. It is easy to write a rule around an application field that only exists because a demonstration app declares itself compromised. It is much harder, and much more useful, to base the rule on web, process, or network telemetry that a SOC can actually own. The range deliberately treats that distinction as a design constraint.

## What the first modules taught me

The first module covers a CORS session-hijacking issue in the MCP Java SDK. A server can look local and private to its operator while a browser still makes it reachable from an attacker-controlled page. In the affected transport, permissive CORS and session information exposed on an event stream combine to let that page replay a session and reach a capability-bearing tool.

The second module explores DNS rebinding in the MCP TypeScript SDK. Fixing the first issue by checking `Origin` is important, but it does not solve a page that becomes same-origin with its target after DNS changes. The attack path is different, and so is the detection signal. In this case, the most useful question is whether the server accepted a request for a foreign `Host`, followed by a sensitive tool invocation.

Both modules are intentionally narrow. I do not need a catalogue of every possible attack to learn something useful. I need an evidence-backed example that demonstrates how one control fails, how a mitigation changes the outcome, and how a detection can distinguish the two.

## Containment is part of the experiment

I made containment a property of the range rather than a footnote in its documentation. The default deployment is a Docker network with no egress and no published ports. The command-line tool refuses to deploy or run a scenario unless it is positively identified as the dedicated lab VM. It also permits only one module at a time.

The only commands issued through the demonstration tools are benign canaries such as `id`, `hostname`, and an explicit lab marker. I do not use real credentials, personal data, destructive actions, or targets outside the environment I control.

Some attack models require a browser or attacker infrastructure on another host. For those cases, I keep the capability-bearing MCP server and scenario runner on the isolated VM. The other host is limited to static attacker content, a collection endpoint, and, when needed, a browser. The split is intentional: a realistic trust boundary should not quietly become a path for moving command execution somewhere less controlled.

## Reproduction is not the finish line

The part I find most valuable is the detection work. A successful reproduction is only the evidence that I chose the right behavior to study. It is not the deliverable.

Each module includes a machine-readable detection rule, positive and negative test cases, and guidance for translating the rule into Elastic. The rules are evaluated offline, and the project can export them as Sigma or Elastic packs. I also keep the rules disabled by default so importing a research artifact cannot accidentally create noisy detections in an unrelated environment.

This has changed how I think about demonstrations. Instead of asking whether a clip proves that an attack can work, I ask whether it proves that the attack produces a signal worth operationalizing. A good module makes both answers clear.

## Why publish the range

I am publishing the structure and the detections because security research is more useful when people can inspect the assumptions, rerun the checks, and adapt the telemetry to their own systems. The goal is not to encourage deployment of vulnerable servers. The goal is to help defenders test the controls around systems they own.

There is also a practical reason to keep the work manifest-driven. A module owns its scenario, environment, evidence, detection, and write-up in one directory. That makes it easier for me to review a new contribution as a complete defensive story instead of a disconnected exploit and an unrelated rule.

## What comes next

I plan to add modules only when they can complete the same loop: a published issue, a contained reproduction, useful telemetry, and a tested detection. I am especially interested in the places where AI-agent systems cross trust boundaries: tool descriptions, browser-based flows, external upstreams, and authorization assumptions that are easy to miss in normal development.

The measure of progress is not the number of attacks in the catalog. It is whether each new module leaves defenders with a concrete question to ask of their telemetry and a practical way to answer it.

If you work with MCP servers or AI agents, I hope the range gives you a starting point for that work: reproduce carefully, observe honestly, and ship the detection with the demonstration.
