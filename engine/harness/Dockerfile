# harness - LAB-ONLY MCP client / scenario runner. labnet-internal; ephemeral (run --rm).
#
# The build context is the REPO ROOT and the image MIRRORS THE REPO LAYOUT (/app/engine/harness +
# /app/modules). That is deliberate: a scenario imports the SDK as `../../engine/harness/src/...`, and
# mirroring means that one relative path is correct both on the authoring host (where `range
# typecheck` reads it) and inside the container (where it actually runs). A flattened image layout
# would need two different import paths for the same file.
#
# Runs via tsx (transpile-only), the runner's original execution model; `range typecheck` is a
# separate, non-blocking check.
FROM node:20-alpine
WORKDIR /app/engine/harness

# tsconfig.json extends the shared base, so the base has to be in the image too.
COPY config/tsconfig.base.json /app/config/tsconfig.base.json
COPY engine/harness/package.json engine/harness/package-lock.json engine/harness/tsconfig.json ./
RUN npm ci
COPY engine/harness/src ./src

# Baked so the image also works without the bind mount. At run time compose mounts the host's
# modules/ over this path, which is what lets the harness write evidence back to the repo.
COPY modules /app/modules

ENTRYPOINT ["npx", "tsx", "src/index.ts"]
