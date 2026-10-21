# dsh-rea-toolkit

**One-line value:** after installing, your DeepSeek Harness agent gains the full [REA (Reverse Engineer Anything)](https://github.com/morluto/rea) toolset — evidence-backed static analysis of JavaScript/Electron applications, browser extensions, ASAR archives, .NET assemblies, native binaries, SQLite databases, WASM, EVM bytecode, and more — as native `mcp__rea__*` tools.

[![Listed on dsh-plugin.org](https://dsh-plugin.org/badges/listed.svg)](https://dsh-plugin.org/plugins/akash-digitavision/my-rea-toolkit)

## What it does

This bundle packages the **REA v6.7.0 runtime** (`dist/`, verified Windows native artifact, skills, and the exact dependency lockfile) together with a DeepSeek Harness **configuration-only MCP bundle** that registers REA's stdio MCP server through `@deepseek-ai/dsh-mcp-client`. REA analyzes targets **locally**; results include per-conclusion evidence and limitations.

Typical agent prompts after install:

- *"Analyze the extracted extension at `D:/apps/legacy-ext` and list its modules, IPC channels and gateway endpoints with evidence."*
- *"Inspect this Electron app's ASAR and explain how the renderer talks to the main process."*

## Install

```sh
dsh plugin --profile web add github:akash-digitavision/my-rea-toolkit
```

Then, inside the installed bundle directory, run the bootstrap **once** and restart DeepSeek Harness:

```sh
install-tools.bat      # Windows
./install-tools.sh     # Linux / macOS
node install-tools.mjs # directly
```

The bootstrap: discovers a suitable Node.js (22.19+/24.11+/26+), verifies the bundled REA runtime, installs REA's exact production dependencies from the shipped lockfile, persists `DSH_REA_HOME` / `DSH_REA_NODE` at user scope, and runs REA's own `mcp doctor`.

**Resolution contract** (see `cordis.patch.yml`):

| Environment | Behavior |
| --- | --- |
| `DSH_REA_NODE` + `DSH_REA_HOME` set | Absolute node + bundled, validated REA runtime (works with no system Node on PATH) |
| `DSH_REA_HOME` only | `node` from PATH + bundled runtime |
| Neither set | `npx -y rea-agents@6.7.0 mcp` fetches the official runtime from npm |

Without any setup the bundle still installs safely — you simply get no REA tools until the bootstrap runs (or npm/npx is available).

## Compatibility

- DeepSeek Harness (DSH) with `@deepseek-ai/dsh-mcp-client` (shipped profile package).
- Windows 10+ x64 (uses the bundled verified `rea-windows-x64.node` Node-API addon; loader checks version/ABI/architecture/SHA-256 at load), Linux x64, macOS (Apple silicon: JS analysis lanes; native binary lanes per REA docs).
- Node.js 22.19+/24.11+/26+ (auto-discovered by the bootstrap; the bundled DeepSeek Harness runtime qualifies).

## Permissions & external services

- **Local-only analysis:** REA reads the target files/directories you point it at and writes nothing outside its own analysis sessions. It does not upload targets anywhere.
- **Network:** only optional — npm registry (first bootstrap / npx fallback) and analysis targets that the agent explicitly asks to inspect over the network (e.g., a website URL via the browser lane).
- **Execution scope:** static analysis lanes do not run the analyzed application. Runtime capture lanes (browser observation, process capture, frida) run only when an agent workflow explicitly invokes them, with the harness user's permissions.
- **Ambient secrets** (`*TOKEN*`, `*KEY*`, …) are scrubbed from the MCP child environment by the Harness MCP client.

## License

- Wrapper (bundle, scripts, manifest): **MIT** — see [LICENSE](LICENSE).
- Bundled REA runtime: **MIT** — see [runtime/rea/LICENSE](runtime/rea/LICENSE), [runtime/rea/THIRD_PARTY_NOTICES.md](runtime/rea/THIRD_PARTY_NOTICES.md) and [runtime/rea/DISCLAIMER.md](runtime/rea/DISCLAIMER.md). REA is for lawful analysis of software you own or are authorized to examine.

## Category

Development & Operations (secondary: Tools & Capabilities).

## Notes

- REA upstream: <https://github.com/morluto/rea> (not affiliated with this bundle).
- Native deep-analysis engines (Hopper / Ghidra / IDA) are bring-your-own and optional; JavaScript/extension analysis needs none of them.
- The `index.js` `apply(ctx)` export is an inert plugin-spec compliance shim; the bundle is configuration-only.
