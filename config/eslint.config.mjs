// Flat ESLint config for the Meridian Range TypeScript (engine, modules, servers).
// Lives under config/ to keep the repo root readable; invoked as
//   npx eslint --config config/eslint.config.mjs .
// which `./range lint` does for you.
// Deliberately light: this is intentionally-vulnerable lab code, so the rules catch real mistakes
// (unused vars, unsafe comparisons) without fighting the deliberate patterns the lab needs, such as
// `any` on loosely-typed JSON-RPC payloads and `execSync` in the by-design-vulnerable server.
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // `ops/` is a separate private repo checked out inside this one (see .gitignore). It is not part
    // of this project and is absent from a fresh clone, so linting it would only ever fail locally.
    // ESLint's flat config does not read .gitignore, so the exclusion has to be stated here.
    ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "ops/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        fetch: "readonly",
        Buffer: "readonly",
      },
    },
    rules: {
      "@typescript-eslint/no-explicit-any": "off", // loosely-typed JSON-RPC payloads by design
      "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "no-empty": ["warn", { allowEmptyCatch: true }], // best-effort recon/exfil swallow errors on purpose
    },
  },
);
