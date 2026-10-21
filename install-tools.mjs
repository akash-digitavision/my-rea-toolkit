#!/usr/bin/env node
/**
 * dsh-rea-toolkit bootstrap / doctor.
 *
 * One-time setup for a cloned copy of this bundle inside a DeepSeek Harness
 * workspace:
 *   1. Discovers a usable Node.js runtime (>= 22.19 / 24.11 / 26 per REA).
 *   2. Verifies the bundled REA runtime layout (dist, MCP entry, native addon).
 *   3. Materializes REA's exact production dependencies from the shipped
 *      package-lock.json (`npm ci --omit=dev`) when npm is available.
 *   4. Persists DSH_REA_HOME and DSH_REA_NODE at user scope so the
 *      cordis.patch.yml `!!js` expressions resolve without editing the patch.
 *   5. Runs REA's own `mcp doctor` check when possible.
 *
 * Usage: node install-tools.mjs [--skip-deps] [--doctor-only]
 */
import { spawnSync } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir, platform, userInfo } from "node:os";

const BUNDLE_ROOT = dirname(fileURLToPath(import.meta.url));
const REA_HOME = join(BUNDLE_ROOT, "runtime", "rea");
const IS_WINDOWS = platform() === "win32";
const problems = [];
const steps = [];

const note = (msg) => steps.push(msg) && console.log(`  [ok] ${msg}`);
const warn = (msg) => problems.push(msg) && console.error(`  [!]  ${msg}`);
const canRead = (p) => {
  try { accessSync(p, constants.R_OK); return true; } catch { return false; }
};

/* ---- 1. Node discovery ------------------------------------------------- */

function nodeSatisfies(execPath) {
  const probe = spawnSync(execPath, ["-p", "process.versions.node"], { encoding: "utf8" });
  if (probe.status !== 0) return null;
  const v = (probe.stdout || "").trim().split(".").map(Number);
  if (v.length < 2) return null;
  const [maj, min] = v;
  const ok = (maj === 22 && min >= 19) || (maj === 24 && min >= 11) || maj >= 26;
  return ok ? (probe.stdout || "").trim() : null;
}

function discoverNode() {
  const candidates = [];
  if (process.env.DSH_REA_NODE) candidates.push(process.env.DSH_REA_NODE);
  candidates.push(process.execPath); // currently running node, if invoked via node
  if (IS_WINDOWS) {
    const dshRuntime = join(
      process.env.USERPROFILE || homedir(),
      ".dsh", "dsh-runtimes", "dsh-primary-runtime", "dependencies", "node", "bin", "node.exe",
    );
    candidates.push(dshRuntime, "node");
  } else {
    candidates.push("node");
  }
  for (const c of candidates) {
    // A candidate with a path separator must exist on disk; a bare command is
    // resolved from PATH by the probe itself. Persist absolute paths as-is and
    // bare commands as-is (resolving "node" to a cwd-joined path would break
    // DSH_REA_NODE for other processes).
    const isPath = c.includes("\\") || c.includes("/");
    if (isPath && !canRead(c)) continue;
    const version = nodeSatisfies(c);
    if (version) return { path: c, version };
  }
  return null;
}

/* ---- 2. Runtime layout verification ------------------------------------ */

function verifyRuntimeLayout() {
  const required = [
    "scripts/rea.mjs",
    "package.json",
    "package-lock.json",
    "dist/mcp/main.js",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
  ];
  const missing = required.filter((rel) => !existsSync(join(REA_HOME, rel)));
  if (missing.length > 0) {
    warn(`bundled REA runtime is incomplete; missing: ${missing.join(", ")}`);
    return false;
  }
  let version = "unknown";
  try { version = JSON.parse(readFileSync(join(REA_HOME, "package.json"), "utf8")).version; } catch {}
  note(`REA runtime layout verified (rea-agents v${version}) at ${REA_HOME}`);
  if (IS_WINDOWS) {
    const manifest = join(REA_HOME, "native", "windows", "build", "manifest.json");
    const addon = join(REA_HOME, "native", "windows", "build", "rea-windows-x64.node");
    if (existsSync(manifest) && existsSync(addon)) {
      note("Windows native controls artifact present (loader verifies digest at load time)");
    } else {
      warn("Windows native artifact missing; Windows provider-backed workflows will report unavailable (JS analysis unaffected)");
    }
  }
  return true;
}

/* ---- 3. Production dependency provisioning ------------------------------ */

function materializeDependencies(nodePath, skip) {
  const nm = join(REA_HOME, "node_modules");
  if (existsSync(join(nm, ".package-lock.json"))) {
    note("REA production dependencies already materialized");
    return true;
  }
  if (skip) { warn("dependency provisioning skipped by flag"); return false; }
  const npmCli = join(dirname(nodePath), IS_WINDOWS ? "node_modules\\npm\\bin\\npm-cli.js" : "node_modules/npm/bin/npm-cli.js");
  const useDirect = canRead(npmCli);
  const cmd = useDirect ? nodePath : "npm";
  const baseArgs = useDirect ? [npmCli, "ci", "--omit=dev", "--no-audit", "--no-fund"] : ["ci", "--omit=dev", "--no-audit", "--no-fund"];
  console.log("  ..  installing REA production dependencies (npm ci --omit=dev); this can take a few minutes");
  // npm lifecycle scripts (e.g. the repo's prepare hook) spawn `node` through
  // cmd.exe; make sure the resolved node's directory is on the child PATH.
  const childEnv = {
    ...process.env,
    PATH: `${dirname(nodePath)}${delimiter}${process.env.PATH || ""}`,
  };
  const r = spawnSync(cmd, baseArgs, { cwd: REA_HOME, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: childEnv });
  if (r.status !== 0) {
    warn(`npm ci failed (exit ${r.status}). Re-run with network access, or run it manually in runtime/rea. stderr tail: ${(r.stderr || "").split("\n").slice(-3).join(" | ")}`);
    return false;
  }
  note("REA production dependencies installed from the shipped lockfile");
  return true;
}

/* ---- 4. Environment persistence ----------------------------------------- */

function persistEnvironment(nodePath) {
  const pairs = [["DSH_REA_HOME", REA_HOME], ["DSH_REA_NODE", nodePath]];
  if (IS_WINDOWS) {
    for (const [k, v] of pairs) {
      const r = spawnSync("setx", [k, v], { encoding: "utf8" });
      if (r.status === 0) note(`persisted ${k}=${v} (user scope; effective for processes started after this shell)`);
      else warn(`setx ${k} failed (exit ${r.status}); set it manually`);
    }
  } else {
    const profile = join(homedir(), ".profile");
    const block = `\n# dsh-rea-toolkit\nexport DSH_REA_HOME="${REA_HOME}"\nexport DSH_REA_NODE="${nodePath}"\n`;
    try {
      const existing = existsSync(profile) ? readFileSync(profile, "utf8") : "";
      if (!existing.includes("dsh-rea-toolkit")) {
        spawnSync("sh", ["-c", `printf '%s\\n' '${block.replace(/'/g, "")}' >> '${profile}'`]);
      }
      note(`appended DSH_REA_HOME / DSH_REA_NODE exports to ${profile}`);
    } catch {
      warn(`could not update ${profile}; export DSH_REA_HOME=${REA_HOME} and DSH_REA_NODE=${nodePath} manually`);
    }
  }
  console.log("  [i]  restart DeepSeek Harness so the host process inherits the new environment");
}

/* ---- 5. REA mcp doctor --------------------------------------------------- */

function runDoctor(nodePath) {
  console.log("  ..  running REA 'mcp doctor'");
  const r = spawnSync(nodePath, [join(REA_HOME, "scripts", "rea.mjs"), "mcp", "doctor"], {
    encoding: "utf8", timeout: 120000,
  });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  if (r.status === 0) { note("REA mcp doctor passed"); return true; }
  warn(`mcp doctor exit ${r.status}: ${out.split("\n").slice(-6).join(" | ").slice(0, 500)}`);
  return false;
}

/* ---- main ---------------------------------------------------------------- */

const args = process.argv.slice(2);
const skipDeps = args.includes("--skip-deps");
const doctorOnly = args.includes("--doctor-only");

console.log(`dsh-rea-toolkit bootstrap (bundle: ${BUNDLE_ROOT})`);
console.log(`platform: ${platform()} ${process.arch}, user: ${(() => { try { return userInfo().username; } catch { return "?"; } })()}`);

const node = discoverNode();
if (!node) {
  warn("no Node.js >= 22.19/24.11/26 found; install Node.js or point DSH_REA_NODE at a suitable binary, then re-run");
} else {
  note(`Node.js ${node.version} at ${node.path}`);
}

if (!doctorOnly) {
  verifyRuntimeLayout();
  if (node) {
    materializeDependencies(node.path, skipDeps);
    persistEnvironment(node.path);
    runDoctor(node.path);
  }
} else if (node) {
  runDoctor(node.path);
}

console.log("");
if (problems.length === 0) {
  console.log("RESULT: OK — bundle is provisioned. Restart DeepSeek Harness to activate the REA MCP tools (mcp__rea__*).");
  process.exit(0);
} else {
  console.log(`RESULT: COMPLETED WITH ${problems.length} WARNING(S) — see [!] lines above. REA static analysis needs the warnings resolved; the bundle otherwise installs safely.`);
  process.exit(0); // warnings are non-fatal by design; report documents them
}
