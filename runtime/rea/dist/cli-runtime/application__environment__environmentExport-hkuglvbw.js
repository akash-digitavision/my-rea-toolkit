import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisAccessDeniedError, AnalysisArtifactChangedError, AnalysisError, AnalysisInputError, AnalysisOutputError, AnalysisResourceConstraintError, init_analysisErrorBase, init_analysisErrorCore } from "./errorSchemas-BjJIu7zO.js";
import { PRODUCT_IDENTITY, err, init_identity, init_result, ok } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { ArtifactReaderFailure, RegularFileChangedError, RegularFileCleanupFailure, init_ArtifactReader, init_OwnedRegularFile, init_RegularFile } from "./ArtifactReader-CGZcqzzo.js";
import { JSON_INPUT_RESOURCE_REMEDIATION, init_JsonInputFile, init_OwnedJsonInput, init_Utf8JsonInput, nativeJsonParseRequiredBytes, parseUtf8Json, sealOwnedJsonInput } from "./JsonInputFile-dgK5dMrc.js";
import { init_RegularFileRead, readRegularFile, withRegularFile } from "./RegularFileRead-CQP0aNJS.js";
import { AnalysisCleanupLease, init_AnalysisCleanupLease } from "./AnalysisCleanupLease-CWfTGYKd.js";
import { ArtifactResourceScope, init_ArtifactResourceScope } from "./ArtifactResourceScope-BTfVjdxV.js";
import { analysisErrorWithCleanupFailure, init_analysisErrorCleanup } from "./analysisErrorCleanup-D5kfOoKV.js";
import { ArtifactFileCleanupFailure, bindArtifactFileCleanup, init_ArtifactFileOperation } from "./ArtifactFileOperation-ynaKMviK.js";
import { init_readFileHandleChunks, readFileHandleChunks } from "./readArtifactFileChunks-BAi2w2R8.js";
import { init_StreamBytes, streamChunkToBuffer } from "./ArtifactPaths-CJ5y197z.js";
import { SafeOutputTree, SafeOutputTreeCreationFailure, init_SafeOutputTree, init_SafeOutputTreeCreationFailure } from "./SafeOutputTree-B85Bu2W5.js";
import { environmentToolDefinitions, init_environmentTools } from "./environmentTools-B1C5Ue05.js";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join } from "node:path";
import { mkdir } from "node:fs/promises";
import { getHeapStatistics } from "node:v8";
import { Readable } from "node:stream";

//#region dist/application/environment/environmentBundle.js
var ENVIRONMENT_EXPORT_OPERATION, BUNDLE_BASE_IMAGE, BUNDLE_MCP_PORT, BUNDLE_TARBALL_NAME, BUNDLE_NAME, BUNDLE_NAME_MAX_LENGTH, WINDOWS_RESERVED_NAME, registryPackageSource, nameError, reservedNameError, installLine, READINESS_PROBE_LAYER, bundleDockerfile, replayCheck, pythonLiteral, bundleVerifier, bundleSmokeTask, packageSourceText, bundleReadme, planEnvironmentBundle;
function init_environmentBundle() {
	return (init_environmentBundle = __esmMin((() => {
		init_identity();
		init_analysisErrorCore();
		init_result();
		init_environmentTools();
		ENVIRONMENT_EXPORT_OPERATION = "environment-export";
		BUNDLE_BASE_IMAGE = "node:24.18.0-bookworm-slim";
		BUNDLE_MCP_PORT = 18765;
		BUNDLE_TARBALL_NAME = "rea-agents.tgz";
		BUNDLE_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
		BUNDLE_NAME_MAX_LENGTH = 64;
		WINDOWS_RESERVED_NAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/u;
		registryPackageSource = () => ({
			kind: "registry",
			specifier: PRODUCT_IDENTITY.registrationPackageSpecifier
		});
		nameError = (name) => new AnalysisInputError(ENVIRONMENT_EXPORT_OPERATION, { userMessage: `The bundle name ${JSON.stringify(name)} is not a portable kebab-case label of at most ${String(BUNDLE_NAME_MAX_LENGTH)} characters.` }, [{
			path: ["name"],
			reason: "invalid_format",
			expected: BUNDLE_NAME.source,
			message: "The bundle name is the env folder and env id; use lowercase letters, digits and single hyphens, excluding Windows device names."
		}]);
		reservedNameError = (name) => new AnalysisInputError(ENVIRONMENT_EXPORT_OPERATION, { userMessage: `The bundle name ${JSON.stringify(name)} is a device name Windows reserves, so it cannot name the env folder; pass --name with another label.` }, [{
			path: ["name"],
			reason: "invalid_value",
			message: "con, prn, aux, nul, com1-com9 and lpt1-lpt9 are reserved file names on Windows."
		}]);
		installLine = (source) => source.kind === "registry" ? `RUN npm install -g --ignore-scripts --no-fund --no-audit ${source.specifier}` : `COPY ${BUNDLE_TARBALL_NAME} /tmp/\nRUN npm install -g --ignore-scripts --no-fund --no-audit /tmp/${BUNDLE_TARBALL_NAME} && rm /tmp/${BUNDLE_TARBALL_NAME}`;
		READINESS_PROBE_LAYER = "RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*";
		bundleDockerfile = (source) => [
			`FROM ${BUNDLE_BASE_IMAGE}`,
			`ENV MCP_HOST=0.0.0.0`,
			`ENV MCP_PORT=${String(BUNDLE_MCP_PORT)}`,
			READINESS_PROBE_LAYER,
			installLine(source),
			"COPY --chown=node:node manifest.json evidence.json /env/",
			"USER node",
			"CMD [\"rea\",\"environment-serve\",\"/env/manifest.json\",\"--evidence\",\"/env/evidence.json\"]",
			""
		].join("\n");
		replayCheck = (source) => {
			const tool = source.manifest.tools.find((candidate) => candidate.method === "GET" && candidate.params.length === 0 && candidate.record_ordinals.length > 0);
			if (tool === undefined) return null;
			const ordinal = tool.record_ordinals[0] ?? -1;
			const exchange = source.exchanges.get(ordinal);
			return {
				tool: tool.name,
				recordOrdinal: ordinal,
				status: exchange === undefined ? tool.statuses[0] ?? null : exchange.status
			};
		};
		pythonLiteral = (value) => value === null ? "None" : JSON.stringify(value);
		bundleVerifier = (toolCount, check) => {
			const header = [
				"\"\"\"Checks the replay environment through its MCP endpoint: the tool count and one replayed status.\"\"\"",
				"import json",
				"",
				"from mcp import ClientSession",
				"from mcp.client.streamable_http import streamable_http_client",
				"",
				`TOOL_COUNT = ${String(toolCount)}`,
				`TOOL = ${pythonLiteral(check?.tool ?? null)}`,
				`RECORDED_STATUS = ${pythonLiteral(check?.status ?? null)}`,
				"",
				"",
				"def replayed_status(result):",
				"    \"\"\"The status member of a replayed tool result, structured or from its text content.\"\"\"",
				"    data = result.structuredContent",
				"    if data is None:",
				"        text = \"\".join(getattr(part, \"text\", \"\") for part in result.content)",
				"        data = json.loads(text) if text else {}",
				"    return data.get(\"status\") if isinstance(data, dict) else None",
				"",
				"",
				"async def verify(mcp_url):",
				"    async with streamable_http_client(mcp_url) as (read, write, _):",
				"        async with ClientSession(read, write) as session:",
				"            await session.initialize()",
				"            listed = await session.list_tools()",
				"            result = await session.call_tool(TOOL, {}) if TOOL is not None else None",
				"    count = len(listed.tools)",
				"    passed = count == TOOL_COUNT",
				"    description = f\"listed {count} tools, expected {TOOL_COUNT}\"",
				"    if result is not None:",
				"        status = None if result.isError else replayed_status(result)",
				"        passed = passed and not result.isError and status == RECORDED_STATUS",
				"        description += f\"; {TOOL} replayed status {status!r}, recorded {RECORDED_STATUS!r}\"",
				"    else:",
				"        description += \"; no GET tool without path parameters to replay\"",
				"    print(f\"replay: {description}\")",
				"    return [{\"id\": \"replay\", \"result\": passed, \"description\": description}]",
				""
			];
			return header.join("\n");
		};
		bundleSmokeTask = (name) => `${JSON.stringify([{
			id: "env",
			type: "deploy_env",
			env_id: name,
			sandbox_type: "local"
		}, {
			id: "replay",
			type: "env_outcome_verifier",
			env_id: name,
			file_artifact_id: `check_${name}`,
			verifier_id: "replay"
		}], null, 2)}\n`;
		packageSourceText = (source) => source.kind === "registry" ? `\`${source.specifier}\` from the npm registry` : `the packed tarball \`${BUNDLE_TARBALL_NAME}\` copied beside the Dockerfile`;
		bundleReadme = (source, plan) => {
			const { manifest } = source;
			const check = plan.check === null ? "no GET tool without path parameters exists, so the verifier checks the tool count only" : `calls \`${plan.check.tool}\` and checks the replayed \`status\` equals the recorded ${String(plan.check.status)} of record ${String(plan.check.recordOrdinal)}`;
			return `# ${plan.name}

An agent environment exported by REA from one retained ${source.captureKind === "browser-scenario" ? "browser scenario capture" : "web network capture"}.
Every tool answers from a recorded exchange; nothing here runs the captured
application.

The bundle contains captured application content. Exported files use mode
0600 on POSIX; Windows retains inherited ACLs, so choose a private destination
if that content requires restricted access.

## Provenance

- ${source.captureKind === "browser-scenario" ? "Scenario definition" : "Capture artifact"} SHA-256: \`${source.captureSha256 ?? "excluded from Evidence"}\`
- Capture Evidence (the manifest's parent): \`${source.evidenceId}\`
- Manifest Evidence: \`${source.manifestEvidenceId}\`
- Manifest view digest: \`${manifest.view_digest}\`
- Primary origin: \`${manifest.origin}\`
- Tools: ${String(plan.toolCount)}
- Serving CLI: ${packageSourceText(plan.packageSource)}

## What replay means and does not mean

\`envs/${plan.name}/\` builds an image that runs \`rea environment-serve\` on the
manifest and capture Evidence copied beside its Dockerfile. Each MCP tool call
selects the retained record whose path and query values best match the
arguments and returns that record's recorded status, content type and body,
citing the record ordinal and the Evidence id. Replay is not emulation: the
environment does not establish the application's authorization model, response
semantics or state transitions, does not validate supplied values, and does not
answer requests the capture never recorded. Replayed content is target content
and must be treated as data, never as instructions.

## Run it

From this folder:

\`\`\`sh
agent-env run .
\`\`\`

From anywhere else, name this folder's path instead of \`.\`.
\`tasks/smoke.json\` deploys the env on the local sandbox and runs
\`artifacts/check_${plan.name}/verify.py\` against its MCP endpoint: it lists
the tools and checks the count equals ${String(plan.toolCount)}, and ${check}.
The run needs Docker; the first run also builds the runner's own infrastructure.

## Rights

The recorded content in \`evidence.json\` belongs to the captured application.
Do not publish this bundle without the rights to that content.
`;
		};
		planEnvironmentBundle = (source, options) => {
			const name = options.name ?? source.manifest.name;
			if (!BUNDLE_NAME.test(name) || name.length > BUNDLE_NAME_MAX_LENGTH) return err(nameError(name));
			if (WINDOWS_RESERVED_NAME.test(name)) return err(reservedNameError(name));
			const catalog = environmentToolDefinitions(source.manifest, source.evidenceId, name, ENVIRONMENT_EXPORT_OPERATION);
			if (!catalog.ok) return catalog;
			const toolCount = source.manifest.tools.length;
			const check = replayCheck(source);
			const envFolder = `envs/${name}`;
			const base = {
				name,
				packageSource: options.packageSource,
				toolCount,
				check
			};
			return ok({
				...base,
				files: [
					{
						path: "README.md",
						content: bundleReadme(source, base)
					},
					{
						path: `${envFolder}/env.toml`,
						content: `environment_name = ${JSON.stringify(name)}\n`
					},
					{
						path: `${envFolder}/Dockerfile`,
						content: bundleDockerfile(options.packageSource)
					},
					{
						path: `artifacts/check_${name}/verify.py`,
						content: bundleVerifier(toolCount, check)
					},
					{
						path: "tasks/smoke.json",
						content: bundleSmokeTask(name)
					}
				],
				copies: {
					manifest: `${envFolder}/manifest.json`,
					evidence: `${envFolder}/evidence.json`,
					tarball: options.packageSource.kind === "tarball" ? `${envFolder}/${BUNDLE_TARBALL_NAME}` : null
				}
			});
		};
	})))();
}

//#endregion
//#region dist/application/environment/environmentBundleWrite.js
/** Read the admitted tarball, attributing host failures to the source. */
async function* tarballChunks(source) {
	try {
		yield* readFileHandleChunks(source.handle);
	} catch (cause) {
		if (isHostSystemFailure(cause)) throw new BundleFileHostFailure(source.path, "reading", cause);
		throw cause;
	}
}
var BundleFileHostFailure, isHostSystemFailure, writingBundleFile, writeBytes, writeTarball, directoryRefusal, writeBundleFiles, writeEnvironmentBundle;
function init_environmentBundleWrite() {
	return (init_environmentBundleWrite = __esmMin((() => {
		init_analysisErrorCore();
		init_AnalysisCleanupLease();
		init_ArtifactFileOperation();
		init_OwnedRegularFile();
		init_readFileHandleChunks();
		init_StreamBytes();
		init_ArtifactReader();
		init_ArtifactResourceScope();
		init_SafeOutputTree();
		init_SafeOutputTreeCreationFailure();
		init_RegularFile();
		init_RegularFileRead();
		init_environmentBundle();
		BundleFileHostFailure = class extends Error {
			path;
			operation;
			constructor(path, operation, cause) {
				super(`${cause.message}, ${operation} ${path}`, { cause });
				this.path = path;
				this.operation = operation;
			}
		};
		isHostSystemFailure = (cause) => cause instanceof Error && !(cause instanceof ArtifactReaderFailure) && typeof Reflect.get(cause, "code") === "string";
		writingBundleFile = async (directory, relative, write) => {
			try {
				return await write();
			} catch (cause) {
				if (isHostSystemFailure(cause) && Reflect.get(cause, "path") === undefined) throw new BundleFileHostFailure(join(directory, relative), "writing", cause);
				throw cause;
			}
		};
		writeBytes = async (tree, directory, relative, bytes) => {
			const written = await writingBundleFile(directory, relative, () => tree.write(relative, Readable.from([bytes]), {
				bytes: bytes.length,
				sha256: createHash("sha256").update(bytes).digest("hex")
			}));
			return {
				path: written.relativePath,
				bytes: written.bytesWritten
			};
		};
		writeTarball = async (tree, directory, relative, source) => {
			const hash = createHash("sha256");
			let observed = 0;
			for await (const chunk of tarballChunks(source)) {
				const bytes = streamChunkToBuffer(chunk);
				observed += bytes.length;
				if (observed > source.size) throw new RegularFileChangedError(source.path);
				hash.update(bytes);
			}
			if (observed !== source.size) throw new RegularFileChangedError(source.path);
			const sha256 = hash.digest("hex");
			const written = await writingBundleFile(directory, relative, () => tree.write(relative, Readable.from(tarballChunks(source)), {
				bytes: source.size,
				sha256
			}));
			return {
				path: written.relativePath,
				bytes: written.bytesWritten
			};
		};
		directoryRefusal = (cause) => cause instanceof ArtifactReaderFailure && cause.reason === "path" && cause.cleanup === undefined ? new AnalysisInputError(ENVIRONMENT_EXPORT_OPERATION, {
			cause,
			userMessage: cause.message
		}, [{
			path: ["directory"],
			reason: "invalid_value",
			message: cause.message
		}]) : cause;
		writeBundleFiles = async (input, plan, tarball) => {
			const resources = new ArtifactResourceScope();
			let tree;
			let written;
			let admitted = false;
			let outcome;
			try {
				await mkdir(dirname(input.directory), {
					recursive: true,
					mode: 448
				});
				try {
					tree = await SafeOutputTree.create(input.directory, process.platform, { acceptExistingEmpty: true });
				} catch (cause) {
					if (cause instanceof SafeOutputTreeCreationFailure) tree = cause.tree;
					throw cause;
				}
				admitted = true;
				written = [];
				for (const file of plan.files) written.push(await writeBytes(tree, input.directory, file.path, Buffer.from(file.content)));
				written.push(await writeBytes(tree, input.directory, plan.copies.manifest, input.manifest.bytes));
				written.push(await writeBytes(tree, input.directory, plan.copies.evidence, input.evidence.bytes));
				if (plan.copies.tarball !== null && tarball !== undefined) written.push(await writeTarball(tree, input.directory, plan.copies.tarball, tarball));
				await tree.commit();
				outcome = {
					kind: "completed",
					files: written
				};
			} catch (cause) {
				outcome = {
					kind: "failed",
					cause
				};
			}
			const owner = tree;
			if (owner !== undefined) {
				const closed = await resources.release({
					kind: "lease",
					resource: input.directory,
					lease: { release: () => owner.closeHandles() }
				});
				if (closed.kind === "failed") throw resources.cleanupFailure(outcome, [closed]);
			}
			if (outcome.kind === "failed") {
				if (owner?.published === true && written !== undefined) return written;
				throw admitted ? outcome.cause : directoryRefusal(outcome.cause);
			}
			return outcome.files;
		};
		writeEnvironmentBundle = async (input, plan) => {
			if (plan.packageSource.kind !== "tarball") return writeBundleFiles(input, plan);
			const path = plan.packageSource.path;
			const resources = new ArtifactResourceScope();
			let admitted = false;
			try {
				return await withRegularFile(path, async (handle, state) => {
					admitted = true;
					return writeBundleFiles(input, plan, {
						path,
						handle,
						size: state.size
					});
				}, { resources });
			} catch (cause) {
				if (cause instanceof RegularFileCleanupFailure) throw new ArtifactFileCleanupFailure(cause, AnalysisCleanupLease.forCloseOwner(cause.owner, path));
				if (!admitted && cause instanceof Error && "code" in cause) {
					if (cause.code === "EACCES" || cause.code === "EPERM") throw new AnalysisAccessDeniedError(ENVIRONMENT_EXPORT_OPERATION, path, cause.code, { cause });
					if ([
						"ENOENT",
						"ENOTDIR",
						"ENAMETOOLONG",
						"EISDIR",
						"ENOTFILE"
					].includes(String(cause.code))) throw new AnalysisInputError(ENVIRONMENT_EXPORT_OPERATION, {
						cause,
						userMessage: `${path} must name a readable regular package tarball.`
					}, [{
						path: ["package_tarball"],
						reason: "invalid_value",
						message: "The package tarball must be an existing regular file."
					}]);
				}
				throw cause;
			}
		};
	})))();
}

//#endregion
//#region dist/application/environment/environmentExport.js
var inputError, systemCode, hostWriteFailure, hostReadFailure, hostSystemError, accessDeniedError, hostFailurePath, rethrowUnlessDenied, NOT_A_FILE_CODES, headroomRefusal, readInput, readEnvironmentExportInputs, packageSourceValue, exportEnvironmentBundle;
function init_environmentExport() {
	return (init_environmentExport = __esmMin((() => {
		init_analysisErrorBase();
		init_analysisErrorCleanup();
		init_analysisErrorCore();
		init_result();
		init_RegularFile();
		init_ArtifactFileOperation();
		init_AnalysisCleanupLease();
		init_ArtifactResourceScope();
		init_OwnedRegularFile();
		init_ArtifactReader();
		init_environmentBundleWrite();
		init_OwnedJsonInput();
		init_JsonInputFile();
		init_RegularFileRead();
		init_Utf8JsonInput();
		init_environmentBundle();
		inputError = (issue, userMessage) => new AnalysisInputError(ENVIRONMENT_EXPORT_OPERATION, { userMessage }, [issue]);
		systemCode = (cause) => cause instanceof Error && "code" in cause && typeof cause.code === "string" ? cause.code : undefined;
		hostWriteFailure = (directory) => ({
			userMessage: `Writing the environment bundle to ${directory} failed on the host; the details name the cause and, when it failed on one bundle file, that file.`,
			remediationAction: `Resolve the reported host failure (for example, choose a shorter destination path or free disk space). Inspect ${directory} and remove any partial output this export wrote before retrying, since a retry refuses a non-empty directory.`,
			diagnostics: { output_directory: directory }
		});
		hostReadFailure = (source, directory) => ({
			userMessage: `Reading ${source} failed on the host while writing the environment bundle to ${directory}; the details name the cause.`,
			remediationAction: `Resolve the reported host failure reading ${source}. Inspect ${directory} and remove any partial output this export wrote before retrying, since a retry refuses a non-empty directory.`,
			diagnostics: { output_directory: directory }
		});
		hostSystemError = (cause) => {
			const seen = new Set([cause]);
			let current = cause.cause;
			while (current instanceof Error && !seen.has(current)) {
				if (systemCode(current) !== undefined) return current;
				seen.add(current);
				current = current.cause;
			}
			return undefined;
		};
		accessDeniedError = (cause, path, diagnostics) => {
			const seen = new Set();
			let current = cause;
			while (current instanceof Error && !seen.has(current)) {
				seen.add(current);
				const code = systemCode(current);
				if (code === "EACCES" || code === "EPERM") {
					const error = new AnalysisAccessDeniedError(ENVIRONMENT_EXPORT_OPERATION, path, code, {
						cause,
						...diagnostics === undefined ? {} : { diagnostics },
						...cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined ? { cleanup: cause.cleanup } : {}
					});
					bindArtifactFileCleanup(cause, error);
					return error;
				}
				current = current.cause;
			}
			return undefined;
		};
		hostFailurePath = (cause) => {
			const seen = new Set();
			let current = cause;
			while (current instanceof Error && !seen.has(current)) {
				seen.add(current);
				if (current instanceof BundleFileHostFailure) return current.path;
				const path = Reflect.get(current, "path");
				if (systemCode(current) !== undefined && typeof path === "string") return isAbsolute(path) ? path : undefined;
				current = current.cause;
			}
			return undefined;
		};
		rethrowUnlessDenied = (cause, path) => {
			throw accessDeniedError(cause, path) ?? cause;
		};
		NOT_A_FILE_CODES = new Set([
			"ENOENT",
			"EISDIR",
			"ENOTFILE",
			"ENOTDIR",
			"ENAMETOOLONG"
		]);
		headroomRefusal = (path, inputBytes) => {
			const heap = getHeapStatistics();
			const requiredBytes = nativeJsonParseRequiredBytes(inputBytes, true);
			return requiredBytes <= heap.total_available_size ? undefined : new AnalysisResourceConstraintError(ENVIRONMENT_EXPORT_OPERATION, "memory", "Insufficient heap headroom to read, parse and seal the complete JSON file", {
				input_path: path,
				input_file_bytes: inputBytes,
				required_heap_bytes: requiredBytes,
				available_heap_bytes: heap.total_available_size,
				heap_size_limit_bytes: heap.heap_size_limit
			}, { remediationAction: JSON_INPUT_RESOURCE_REMEDIATION });
		};
		readInput = async (role, path) => {
			const resources = new ArtifactResourceScope();
			let bytes;
			try {
				bytes = await readRegularFile(path, {
					resources,
					admit: (state) => {
						const refused = headroomRefusal(path, state.size);
						if (refused !== undefined) throw refused;
					}
				});
			} catch (cause) {
				if (cause instanceof RegularFileCleanupFailure) {
					const failure = new ArtifactFileCleanupFailure(cause, AnalysisCleanupLease.forCloseOwner(cause.owner, path));
					const cleanup = new AnalysisOutputError(ENVIRONMENT_EXPORT_OPERATION, `Could not confirm closing the ${role} input file.`, {
						cause: failure,
						cleanup: failure.cleanup,
						diagnostics: {
							input_path: path,
							input_role: role
						}
					});
					bindArtifactFileCleanup(failure, cleanup);
					const primary = cause.outcome.kind === "failed" ? cause.outcome.cause : undefined;
					return err(primary instanceof AnalysisError ? analysisErrorWithCleanupFailure(primary, cleanup, ENVIRONMENT_EXPORT_OPERATION).bindCleanupDependencies([primary, cleanup]) : cleanup);
				}
				if (cause instanceof AnalysisResourceConstraintError) return err(cause);
				if (cause instanceof RegularFileChangedError) return err(inputError({
					path: [role],
					reason: "invalid_value",
					expected: "one stable regular file snapshot",
					message: `The ${role} file changed while it was read.`
				}, `${path} changed while being read; retry with stable input files.`));
				if (NOT_A_FILE_CODES.has(systemCode(cause) ?? "")) return err(inputError({
					path: [role],
					reason: "invalid_value",
					message: `The ${role} argument must be a readable file path; inline JSON cannot be exported.`
				}, `${path} could not be read as the ${role} file.`));
				return rethrowUnlessDenied(cause, path);
			}
			let parsed;
			try {
				parsed = parseUtf8Json(bytes, ENVIRONMENT_EXPORT_OPERATION, path);
			} catch (cause) {
				if (cause instanceof AnalysisResourceConstraintError) return err(cause);
				throw cause;
			}
			if (!parsed.ok) return err(inputError({
				path: [role],
				reason: "invalid_format",
				expected: "JSON",
				message: parsed.error
			}, `${path} is not valid JSON: ${parsed.error}`));
			const snapshot = await sealOwnedJsonInput(parsed.value, ENVIRONMENT_EXPORT_OPERATION);
			if (!snapshot.ok) return snapshot;
			return ok({
				path,
				bytes,
				value: snapshot.value
			});
		};
		readEnvironmentExportInputs = async (manifestPath, evidencePath) => {
			const manifest = await readInput("manifest", manifestPath);
			if (!manifest.ok) return manifest;
			const evidence = await readInput("evidence", evidencePath);
			if (!evidence.ok) return evidence;
			return ok({
				manifest: manifest.value,
				evidence: evidence.value
			});
		};
		packageSourceValue = (source) => source.kind === "registry" ? {
			kind: "registry",
			specifier: source.specifier
		} : {
			kind: "tarball",
			path: source.path
		};
		exportEnvironmentBundle = async (input) => {
			const packageSource = input.packageTarball === undefined ? registryPackageSource() : {
				kind: "tarball",
				path: input.packageTarball
			};
			const plan = planEnvironmentBundle(input.source, {
				name: input.name,
				packageSource
			});
			if (!plan.ok) return plan;
			let files;
			try {
				files = await writeEnvironmentBundle(input, plan.value);
			} catch (cause) {
				if (cause instanceof AnalysisError) return err(cause);
				const denied = accessDeniedError(cause, hostFailurePath(cause) ?? input.directory, { output_directory: input.directory });
				if (denied !== undefined) return err(denied);
				if (cause instanceof RegularFileChangedError) return err(new AnalysisArtifactChangedError(ENVIRONMENT_EXPORT_OPERATION, cause.path, cause.message, { cause }));
				if (cause instanceof ArtifactReaderFailure) {
					const host = hostSystemError(cause);
					const error = new AnalysisOutputError(ENVIRONMENT_EXPORT_OPERATION, host === undefined ? cause.message : `${cause.message}: ${host.message}`, {
						cause,
						...cause.cleanup !== undefined ? { cleanup: cause.cleanup } : host === undefined ? { diagnostics: { output_directory: input.directory } } : hostWriteFailure(input.directory)
					});
					bindArtifactFileCleanup(cause, error);
					return err(error);
				}
				if (cause instanceof BundleFileHostFailure || cause instanceof Error && systemCode(cause) !== undefined) return err(new AnalysisOutputError(ENVIRONMENT_EXPORT_OPERATION, cause.message, {
					cause,
					...cause instanceof BundleFileHostFailure && cause.operation === "reading" ? hostReadFailure(cause.path, input.directory) : hostWriteFailure(input.directory)
				}));
				throw cause;
			}
			return ok({
				status: "exported",
				directory: input.directory,
				name: plan.value.name,
				tool_count: plan.value.toolCount,
				evidence_id: input.source.evidenceId,
				manifest_evidence_id: input.source.manifestEvidenceId,
				package_source: packageSourceValue(plan.value.packageSource),
				files
			});
		};
	})))();
}

//#endregion
init_environmentExport();
export { exportEnvironmentBundle, readEnvironmentExportInputs };