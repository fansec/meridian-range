# LAB-ONLY server for module 03. The sealed compose file publishes no host ports.
FROM node:20-alpine
WORKDIR /app/servers/mcp-cross-client-ts

ARG MCP_SDK_VERSION=1.25.3

COPY config/tsconfig.base.json /app/config/tsconfig.base.json
COPY servers/mcp-cross-client-ts/package.json servers/mcp-cross-client-ts/package-lock.json servers/mcp-cross-client-ts/tsconfig.json ./
RUN npm ci && npm install --no-save --ignore-scripts --package-lock=false "@modelcontextprotocol/sdk@${MCP_SDK_VERSION}"
COPY servers/mcp-cross-client-ts/src ./src
RUN npm run build

EXPOSE 8080
CMD ["node", "dist/index.js"]
