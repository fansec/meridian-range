# attacker-collector - LAB-ONLY exfil sink. Benign: it stores and prints what it is sent, nothing more.
# labnet-internal in the sealed tier; published only by an opt-in deploy/ fragment.
#
# Built from the REPO ROOT context, matching the harness and ts-vuln images, so it can extend the
# shared TypeScript settings in config/tsconfig.base.json.
FROM node:20-alpine
WORKDIR /app/engine/attacker/collector
COPY config/tsconfig.base.json /app/config/tsconfig.base.json
COPY engine/attacker/collector/package.json engine/attacker/collector/package-lock.json engine/attacker/collector/tsconfig.json ./
RUN npm ci
COPY engine/attacker/collector/src ./src
RUN npm run build
EXPOSE 9000
CMD ["node", "dist/index.js"]
