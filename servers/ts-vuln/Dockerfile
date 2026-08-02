# ts-vuln - LAB-ONLY intentionally-vulnerable MCP server.
# No ports are published in any sealed compose file; this EXPOSE is metadata only (labnet-internal).
#
# Built from the REPO ROOT context (like the harness image) so the shared TypeScript settings in
# config/tsconfig.base.json are reachable. Keeping one build-context convention across every image
# means a project's tsconfig can extend the shared base instead of being a third copy of it.
FROM node:20-alpine
WORKDIR /app/servers/ts-vuln
COPY config/tsconfig.base.json /app/config/tsconfig.base.json
COPY servers/ts-vuln/package.json servers/ts-vuln/package-lock.json servers/ts-vuln/tsconfig.json ./
RUN npm ci
COPY servers/ts-vuln/src ./src
RUN npm run build
EXPOSE 8080
CMD ["node", "dist/index.js"]
