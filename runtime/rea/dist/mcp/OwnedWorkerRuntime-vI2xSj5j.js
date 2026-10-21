import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { r as init_ProcessOwnership, t as cleanupOwnedProcessGroup } from "./ProcessOwnership-BucaMvrX.js";
import { v as ArtifactReaderFailure, x as init_ArtifactReader } from "./OwnedRegularFile--jcCKh4T.js";
import { n as init_PrivateRuntimeRoot, t as PrivateRuntimeRoot } from "./PrivateRuntimeRoot-B3rem_t1.js";
import { n as init_ProviderProcess, r as spawnOwnedProviderProcess, t as ProviderProcessSupervisor } from "./ProviderProcess-DipGfrDv.js";
import { f as BrowserObservationError, p as init_browserObservationError } from "./analysisErrorProjection-DPMozIkD.js";
import { a as assertArtifactReadActive, l as withArtifactFileHandle, s as init_ArtifactFileOperation } from "./ArtifactFileOperation-B41PVRrO.js";
import { c as init_browserObservation, m as sanitizeBrowserUrl } from "./webContentArtifact-DEw68fYw.js";
import { a as init_CdpCaptureValues, c as recordValue, i as delayWithCancellation, n as allowedSanitizedUrl, o as isHttpUrl, r as cdpStringValue } from "./CdpCaptureValues-BQ0nvKmV.js";
import { o as init_CdpCaptureDocuments, s as mainFrameUrl } from "./CdpCaptureDocuments-D2wPwCMw.js";
import { constants } from "node:fs";
import { z } from "zod";
import { lstat, open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { satisfies } from "semver";

//#region dist/artifacts/readStableArtifact.js
var FILE_SYSTEM, afterValidation, readStableArtifact;
function init_readStableArtifact() {
	return (init_readStableArtifact = __esmMin((() => {
		init_ArtifactReader();
		init_ArtifactFileOperation();
		FILE_SYSTEM = {
			lstat: (path) => lstat(path, { bigint: true }),
			open
		};
		afterValidation = async (path, stage, read) => {
			try {
				return await read();
			} catch (cause) {
				if (cause instanceof Error && "code" in cause && [
					"ENOENT",
					"ENOTDIR",
					"ELOOP"
				].includes(String(cause.code))) throw new ArtifactReaderFailure("integrity", `Artifact changed ${stage}: ${path}`, { cause });
				throw cause;
			}
		};
		readStableArtifact = async (path, maximumBytes, signal, fileSystem = FILE_SYSTEM, resourceScope) => {
			assertArtifactReadActive(signal);
			const before = await fileSystem.lstat(path);
			if (!before.isFile() || before.isSymbolicLink()) throw new ArtifactReaderFailure("path", `Expected a regular file without a symlink: ${path}`);
			if (before.size > BigInt(maximumBytes)) throw new ArtifactReaderFailure("limit", `Selected artifact exceeds ${String(maximumBytes)} bytes: ${path}`, { boundary: "file-size" });
			const file = await afterValidation(path, "before open", () => fileSystem.open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK));
			return withArtifactFileHandle(path, file, resourceScope, signal, async (file) => {
				const initial = await file.stat({ bigint: true });
				if (!initial.isFile() || initial.dev !== before.dev || initial.ino !== before.ino) throw new ArtifactReaderFailure("integrity", `Artifact changed before open: ${path}`);
				const chunks = [];
				let count = 0;
				for await (const chunk of file.createReadStream({
					autoClose: false,
					highWaterMark: 65536
				})) {
					assertArtifactReadActive(signal);
					const value = chunk;
					if (!Buffer.isBuffer(value)) throw new ArtifactReaderFailure("format", `Artifact stream did not return bytes: ${path}`);
					const bytes = value;
					count += bytes.length;
					if (count > maximumBytes) throw new ArtifactReaderFailure("limit", `Selected artifact grew beyond its byte limit: ${path}`, { boundary: "file-size" });
					chunks.push(bytes);
				}
				const after = await file.stat({ bigint: true });
				const current = await afterValidation(path, "during read", () => fileSystem.lstat(path));
				if ([after, current].some((stat) => !stat.isFile() || stat.dev !== initial.dev || stat.ino !== initial.ino || stat.size !== initial.size || stat.mtimeNs !== initial.mtimeNs || stat.ctimeNs !== initial.ctimeNs) || BigInt(count) !== initial.size) throw new ArtifactReaderFailure("integrity", `Artifact changed during read: ${path}`);
				assertArtifactReadActive(signal);
				const bytes = Buffer.concat(chunks, count);
				return {
					bytes,
					sha256: createHash("sha256").update(bytes).digest("hex")
				};
			});
		};
	})))();
}

//#endregion
//#region dist/domain/runtimeVersion.js
var SUPPORTED_NODE_VERSION_RANGE, SUPPORTED_NODE_VERSION_PROSE, supportsNodeVersion, javaScriptRuntime;
function init_runtimeVersion() {
	return (init_runtimeVersion = __esmMin((() => {
		SUPPORTED_NODE_VERSION_RANGE = "^22.19.0 || ^24.11.0 || >=26.0.0";
		SUPPORTED_NODE_VERSION_PROSE = "Node.js 22.x (>=22.19), 24.x (>=24.11), or 26+";
		supportsNodeVersion = (version) => satisfies(version, SUPPORTED_NODE_VERSION_RANGE);
		javaScriptRuntime = (versions) => versions.bun === undefined ? {
			id: "node",
			version: versions.node
		} : {
			id: "bun",
			version: versions.bun,
			nodeCompatibilityVersion: versions.node
		};
	})))();
}

//#endregion
//#region dist/process/JavaScriptWorkerMemoryLimit.js
var MIB, BUN_WORKER_RUNTIME_RESERVE_BYTES, javaScriptWorkerMemoryLimitBytes;
function init_JavaScriptWorkerMemoryLimit() {
	return (init_JavaScriptWorkerMemoryLimit = __esmMin((() => {
		init_runtimeVersion();
		MIB = 1024 * 1024;
		BUN_WORKER_RUNTIME_RESERVE_BYTES = 512 * MIB;
		javaScriptWorkerMemoryLimitBytes = (heapBudgetMiB, host = process) => host.platform === "win32" && javaScriptRuntime(host.versions).id === "bun" ? heapBudgetMiB * MIB + BUN_WORKER_RUNTIME_RESERVE_BYTES : null;
	})))();
}

//#endregion
//#region dist/browser/CdpAuthorizedTarget.js
var authorizeCdpTarget;
function init_CdpAuthorizedTarget() {
	return (init_CdpAuthorizedTarget = __esmMin((() => {
		init_browserObservation();
		init_browserObservationError();
		authorizeCdpTarget = (discovery, input, operation) => {
			const target = discovery.targets.find((candidate) => candidate.id === input.target_id);
			if (target === undefined) throw new BrowserObservationError(operation, "target_not_found", { detail: `Target ${input.target_id} was not found at the selected endpoint.` });
			const origin = sanitizeBrowserUrl(target.url).origin;
			if (target.type !== "page" || origin === null || input.allowed_origins.length > 0 && !input.allowed_origins.includes(origin)) throw new BrowserObservationError(operation, "target_not_allowed", { detail: `Target ${input.target_id} must be an HTTP(S) page in the selected origin scope.` });
			return {
				target,
				allowedOrigins: new Set(input.allowed_origins.length > 0 ? input.allowed_origins : [origin])
			};
		};
	})))();
}

//#endregion
//#region dist/browser/CdpAuthorizedMainFrame.js
var authorizedMainFrame;
function init_CdpAuthorizedMainFrame() {
	return (init_CdpAuthorizedMainFrame = __esmMin((() => {
		init_browserObservationError();
		init_CdpCaptureDocuments();
		init_CdpCaptureValues();
		authorizedMainFrame = async ({ connection, sessionId, signal, allowedOrigins, operation }) => {
			for (let attempt = 0; attempt < 80; attempt += 1) {
				const result = await connection.send("Page.getFrameTree", {}, sessionId, signal);
				const url = mainFrameUrl(result);
				if (allowedSanitizedUrl(url, allowedOrigins) !== undefined) return result;
				if (isHttpUrl(url)) throw new BrowserObservationError(operation, "target_not_allowed");
				await delayWithCancellation(25, operation, signal);
			}
			throw new BrowserObservationError(operation, "target_not_allowed");
		};
	})))();
}

//#endregion
//#region dist/browser/CdpTargetEvents.js
var cdpTargetEventMatches;
function init_CdpTargetEvents() {
	return (init_CdpTargetEvents = __esmMin((() => {
		init_CdpCaptureValues();
		cdpTargetEventMatches = (event, sessionId) => {
			if (event.method !== "Target.detachedFromTarget") return event.sessionId === sessionId;
			return sessionId !== undefined && cdpStringValue(recordValue(event.params)?.sessionId) === sessionId;
		};
	})))();
}

//#endregion
//#region dist/domain/sourceMapEnvelope.js
var sourceMapMappingsSchema, sourceMapJsonText, isRecord, classifySourceMapSection, classifySourceMapSections, isVersion3Map, materializeSectionPath, compareSectionPaths, inspectSourceMapEnvelope;
function init_sourceMapEnvelope() {
	return (init_sourceMapEnvelope = __esmMin((() => {
		sourceMapMappingsSchema = z.string();
		sourceMapJsonText = (text) => {
			const withoutBom = text.replace(/^\uFEFF/u, "");
			if (!withoutBom.startsWith(")]}'")) return withoutBom;
			const newline = withoutBom.search(/[\r\n]/u);
			return newline === -1 ? "" : withoutBom.slice(newline);
		};
		isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
		classifySourceMapSection = (section) => {
			if (!isRecord(section)) return {
				kind: "invalid",
				reason: "Indexed source-map section must be an object."
			};
			if (Object.prototype.hasOwnProperty.call(section, "url")) return typeof section.url === "string" ? {
				kind: "external",
				url: section.url
			} : {
				kind: "invalid",
				reason: "External source-map section URL must be a string."
			};
			if (!isRecord(section.map)) return {
				kind: "invalid",
				reason: "Indexed source-map section requires an embedded map or external URL."
			};
			return {
				kind: "embedded",
				map: section.map
			};
		};
		classifySourceMapSections = (map) => {
			if (!isRecord(map)) return {
				kind: "invalid",
				reason: "Source map must be an object."
			};
			if (!Object.prototype.hasOwnProperty.call(map, "sections")) return { kind: "regular" };
			return Array.isArray(map.sections) ? {
				kind: "indexed",
				sections: map.sections
			} : {
				kind: "invalid",
				reason: "Indexed source-map sections must be an array."
			};
		};
		isVersion3Map = (value) => isRecord(value) && value.version === 3;
		materializeSectionPath = (path) => {
			const result = [];
			for (let current = path; current !== null; current = current.parent) result.push(current.index);
			return result.reverse();
		};
		compareSectionPaths = (left, right) => {
			for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
				const leftIndex = left[index] ?? 0;
				const rightIndex = right[index] ?? 0;
				if (leftIndex !== rightIndex) return leftIndex - rightIndex;
			}
			return left.length - right.length;
		};
		inspectSourceMapEnvelope = (root) => {
			if (!isVersion3Map(root)) return {
				status: "invalid",
				reason: "Source map is not a version 3 map."
			};
			const leaves = [];
			const externalSections = [];
			const invalidSections = [];
			const pending = [{
				map: root,
				path: null
			}];
			while (pending.length > 0) {
				const current = pending.pop();
				if (current === undefined) break;
				const map = current.map;
				const sectionList = classifySourceMapSections(map);
				if (sectionList.kind === "invalid") {
					invalidSections.push({
						path: current.path,
						reason: sectionList.reason
					});
					continue;
				}
				if (sectionList.kind === "indexed") {
					const children = [];
					for (let index = 0; index < sectionList.sections.length; index += 1) {
						const section = sectionList.sections[index];
						const path = {
							parent: current.path,
							index
						};
						const classification = classifySourceMapSection(section);
						if (classification.kind === "external") externalSections.push({
							path,
							url: classification.url
						});
						else if (classification.kind === "invalid") invalidSections.push({
							path,
							reason: classification.reason
						});
						else if (!isVersion3Map(classification.map)) invalidSections.push({
							path,
							reason: "Indexed source-map section map is not a version 3 map."
						});
						else children.push({
							map: classification.map,
							path
						});
					}
					for (let index = children.length - 1; index >= 0; index -= 1) {
						const child = children[index];
						if (child !== undefined) pending.push(child);
					}
				} else leaves.push({
					section_path: materializeSectionPath(current.path),
					map
				});
			}
			const external = externalSections.map(({ path, url }) => ({
				section_path: materializeSectionPath(path),
				url
			})).sort((left, right) => compareSectionPaths(left.section_path, right.section_path));
			const invalid = invalidSections.map(({ path, reason }) => ({
				section_path: materializeSectionPath(path),
				reason
			})).sort((left, right) => compareSectionPaths(left.section_path, right.section_path));
			const status = invalid.length > 0 ? "malformed" : external.length > 0 ? "unsupported" : "included";
			return {
				status,
				leaves,
				external_sections: external,
				invalid_sections: invalid
			};
		};
	})))();
}

//#endregion
//#region dist/process/OwnedWorkerRuntime.js
var _a, OwnedWorkerRuntimeCleanupError, OwnedWorkerRuntimeCleanupEpoch, OwnedWorkerRuntime, releasedCleanupOwner, message;
function init_OwnedWorkerRuntime() {
	return (init_OwnedWorkerRuntime = __esmMin((() => {
		init_PrivateRuntimeRoot();
		init_ProviderProcess();
		init_ProcessOwnership();
		;
		OwnedWorkerRuntimeCleanupError = class extends Error {
			cleanupResources;
			processId;
			#cleanupEpoch;
			constructor(cleanupResources, processId, message, cleanupEpoch, options) {
				super(message, options);
				this.cleanupResources = cleanupResources;
				this.processId = processId;
				this.name = "OwnedWorkerRuntimeCleanupError";
				this.#cleanupEpoch = cleanupEpoch;
			}
			bindCleanupFailure(error) {
				if (this.#cleanupEpoch === undefined) {
					error.bindCleanupResourceOwner(releasedCleanupOwner);
					error.resolveCleanup();
					return;
				}
				this.#cleanupEpoch.bind(error);
			}
		};
		OwnedWorkerRuntimeCleanupEpoch = class {
			rootPath;
			#released = false;
			#runId;
			#failures = [];
			constructor(rootPath) {
				this.rootPath = rootPath;
			}
			get cleanupResources() {
				return this.#released ? [] : [...this.#runId === undefined ? [] : [this.#runId], this.rootPath];
			}
			setRunId(runId) {
				if (!this.#released) this.#runId = runId;
			}
			bind(error) {
				error.bindCleanupResourceOwner(this);
				if (this.#released) {
					error.resolveCleanup();
					return;
				}
				this.#failures = [...this.#failures.filter((reference) => reference.deref() !== undefined), new WeakRef(error)];
			}
			release() {
				if (this.#released) return;
				this.#released = true;
				for (const reference of this.#failures) reference.deref()?.resolveCleanup();
				this.#failures = [];
			}
		};
		OwnedWorkerRuntime = class {
			options;
			static #pending = new Set();
			#root;
			#cleanupEpoch;
			#supervisor;
			#processId = null;
			#acquisition;
			#cleanupRetryAttempt;
			#stopAttempt;
			#closeAttempt;
			#closing = false;
			#closed = false;
			#lastRunId;
			#terminalCloseRequested = false;
			#inputFailure;
			#stdinGeneration = 0;
			#stdoutListeners = new Set();
			constructor(options) {
				this.options = options;
			}
			get rootPath() {
				return this.#root?.path;
			}
			/** Exposes the exact supervisor so consumers retain their protocol policy. */
			get supervisor() {
				return this.#supervisor;
			}
			get cleanupResources() {
				const resources = [...this.#supervisor === undefined ? [] : [this.#supervisor.launch.ownership?.runId ?? this.#lastRunId], ...this.#root === undefined ? [] : [this.#root.path]].filter((resource) => resource !== undefined);
				return resources.length === 0 ? [] : resources;
			}
			/** Whether this exact owner still retains an unconfirmed resource release. */
			get hasPendingCleanup() {
				return _a.#pending.has(this);
			}
			/** First error observed on the current child's request stream, if any. */
			get inputFailure() {
				return this.#inputFailure;
			}
			/** Keep a returned typed cleanup error live until this exact owner releases. */
			bindCleanupFailure(error) {
				if (this.#cleanupEpoch === undefined) {
					error.bindCleanupResourceOwner(releasedCleanupOwner);
					error.resolveCleanup();
					return;
				}
				this.#cleanupEpoch.bind(error);
			}
			/** Mark this still-owned runtime for retry before any consumer starts a child. */
			retainForCleanup() {
				_a.#pending.add(this);
			}
			/** Retry every earlier worker owner before any consumer admits a new child. */
			static async retryPending(except) {
				for (const owner of [...this.#pending]) if (owner !== except) await owner.#retryPending();
			}
			/**
			* Acquire one child and let the protocol owner complete its own handshake.
			* Close waits for this entire callback, including a late handshake.
			*/
			start(spawnOptions, initialize) {
				if (this.#terminalCloseRequested || this.#closing) return Promise.reject(new Error("Owned worker runtime is closing"));
				if (this.#acquisition !== undefined) return this.#acquisition;
				if (this.#supervisor !== undefined && !_a.#pending.has(this)) return Promise.resolve();
				if (this.options.retryCleanup !== undefined && _a.#pending.has(this)) return this.#retryOwnedCleanup().then(() => {
					if (this.#terminalCloseRequested || this.#closing) throw new Error("Owned worker runtime is closing");
					return this.start(spawnOptions, initialize);
				});
				const ownRetry = _a.#pending.has(this) ? this.#retryPending() : Promise.resolve();
				const acquisition = ownRetry.then(async () => {
					if (this.#closed) this.#closed = false;
					await this.#start(spawnOptions, initialize);
				});
				this.#acquisition = acquisition;
				void acquisition.finally(() => {
					if (this.#acquisition === acquisition) this.#acquisition = undefined;
				}).catch(() => undefined);
				return acquisition;
			}
			/** Attach protocol stdout while ensuring it is detached before process stop. */
			onStdout(listener) {
				const stream = this.#supervisor?.launch.process.stdout;
				if (stream === null || stream === undefined) throw new Error("Owned worker runtime has no stdout stream");
				stream.on("data", listener);
				this.#stdoutListeners.add({
					stream,
					listener
				});
			}
			stop() {
				if (this.#stopAttempt !== undefined) return this.#stopAttempt;
				const attempt = this.#stop();
				this.#stopAttempt = attempt;
				void attempt.finally(() => {
					if (this.#stopAttempt === attempt) this.#stopAttempt = undefined;
				}).catch(() => undefined);
				return attempt;
			}
			/** Stop the exact child before releasing its root; every failure is retryable. */
			close() {
				this.#terminalCloseRequested = true;
				this.#closing = true;
				if (this.#closed) return Promise.resolve();
				if (this.#closeAttempt !== undefined) return this.#closeAttempt;
				const attempt = this.#close();
				this.#closeAttempt = attempt;
				void attempt.finally(() => {
					if (this.#closeAttempt === attempt) this.#closeAttempt = undefined;
				}).catch(() => undefined);
				return attempt;
			}
			async #retryPending() {
				if (this.options.retryCleanup !== undefined) return this.#retryOwnedCleanup();
				if (this.#terminalCloseRequested) return this.close();
				this.#closing = true;
				if (this.#closeAttempt === undefined) {
					const attempt = this.#close();
					this.#closeAttempt = attempt;
					void attempt.finally(() => {
						if (this.#closeAttempt === attempt) this.#closeAttempt = undefined;
					}).catch(() => undefined);
				}
				const attempt = this.#closeAttempt;
				if (attempt === undefined) return;
				try {
					await attempt;
					if (!this.#terminalCloseRequested) {
						this.#closed = false;
						this.#closing = false;
					}
				} catch (cause) {
					if (!this.#terminalCloseRequested) this.#closing = false;
					throw cause;
				}
			}
			#retryOwnedCleanup() {
				if (this.#cleanupRetryAttempt !== undefined) return this.#cleanupRetryAttempt;
				const attempt = Promise.resolve().then(() => this.options.retryCleanup?.()).then(() => {
					if (_a.#pending.has(this)) throw this.#cleanupError("Higher-level cleanup retry returned while ownership remains pending");
				});
				this.#cleanupRetryAttempt = attempt;
				void attempt.finally(() => {
					if (this.#cleanupRetryAttempt === attempt) this.#cleanupRetryAttempt = undefined;
				}).catch(() => undefined);
				return attempt;
			}
			async #start(spawnOptions, initialize) {
				await _a.retryPending(this);
				if (this.#closing) throw new Error("Owned worker runtime is closing");
				this.#root ??= await PrivateRuntimeRoot.create({ prefix: this.options.rootPrefix });
				this.#cleanupEpoch ??= new OwnedWorkerRuntimeCleanupEpoch(this.#root.path);
				if (this.#closing) throw new Error("Owned worker runtime is closing");
				this.#lastRunId = spawnOptions.runId;
				const spawned = await (this.options.launcher ?? spawnOwnedProviderProcess)({
					...spawnOptions,
					cwd: this.#root.path
				});
				this.#inputFailure = undefined;
				this.#observeStdin(spawned.process.stdin);
				this.#processId = spawned.process.pid ?? null;
				this.#cleanupEpoch.setRunId(spawned.ownership?.runId ?? spawnOptions.runId);
				this.#supervisor = new ProviderProcessSupervisor({
					...spawned,
					ownsProcessLifetime: true,
					cleanup: spawned.cleanup ?? (() => cleanupOwnedProcessGroup(spawned.ownership))
				}, this.options.supervisorOptions);
				if (this.#closing) throw new Error("Owned worker runtime is closing");
				await initialize?.(this.#supervisor);
				if (this.#closing) throw new Error("Owned worker runtime is closing");
			}
			async #stop() {
				const acquisition = this.#acquisition;
				if (acquisition !== undefined) await acquisition.catch(() => undefined);
				const supervisor = this.#supervisor;
				if (supervisor === undefined) return { status: "already-exited" };
				this.#detachStdout();
				const stopped = await supervisor.stop();
				if (stopped.status === "incomplete") {
					_a.#pending.add(this);
					const stdin = supervisor.launch.process.stdin;
					if (stdin !== undefined && stdin !== null && !stdin.destroyed && !stdin.writableEnded) {
						try {
							stdin.end();
						} catch {}
					}
					return stopped;
				}
				supervisor.dispose();
				this.#supervisor = undefined;
				this.#processId = null;
				this.#cleanupEpoch?.setRunId(undefined);
				return stopped;
			}
			async #close() {
				const acquisition = this.#acquisition;
				if (acquisition !== undefined) await acquisition.catch(() => undefined);
				const stopped = await this.stop();
				if (stopped.status === "incomplete") throw this.#cleanupError(stopped.reason);
				if (this.#root !== undefined) {
					try {
						await this.#root.close();
						this.#root = undefined;
						this.#cleanupEpoch?.release();
						this.#cleanupEpoch = undefined;
					} catch (cause) {
						_a.#pending.add(this);
						throw this.#cleanupError(message(cause), cause);
					}
				}
				this.#closed = true;
				_a.#pending.delete(this);
			}
			#detachStdout() {
				for (const { stream, listener } of this.#stdoutListeners) stream.off("data", listener);
				this.#stdoutListeners.clear();
			}
			#observeStdin(stream) {
				if (stream === null || stream === undefined) return;
				const generation = ++this.#stdinGeneration;
				const onError = (cause) => {
					if (generation !== this.#stdinGeneration || this.#inputFailure !== undefined) return;
					this.#inputFailure = cause instanceof Error ? cause : new Error("Owned worker request stream failed", { cause });
					this.options.onInputFailure?.(this.#inputFailure);
				};
				const onClose = () => {
					stream.off("error", onError);
					stream.off("close", onClose);
				};
				stream.on("error", onError);
				stream.once("close", onClose);
			}
			#cleanupError(reason, cause) {
				const resources = this.cleanupResources ?? [];
				return new OwnedWorkerRuntimeCleanupError(resources, this.#supervisor?.launch.process.pid ?? null, reason, this.#cleanupEpoch, cause === undefined ? undefined : { cause });
			}
		};
		_a = OwnedWorkerRuntime;
		releasedCleanupOwner = { cleanupResources: [] };
		message = (cause) => cause instanceof Error ? cause.message : String(cause);
	})))();
}

//#endregion
export { javaScriptWorkerMemoryLimitBytes as _, classifySourceMapSections as a, init_readStableArtifact as b, sourceMapJsonText as c, init_CdpTargetEvents as d, authorizedMainFrame as f, init_JavaScriptWorkerMemoryLimit as g, init_CdpAuthorizedTarget as h, classifySourceMapSection as i, sourceMapMappingsSchema as l, authorizeCdpTarget as m, OwnedWorkerRuntimeCleanupError as n, init_sourceMapEnvelope as o, init_CdpAuthorizedMainFrame as p, init_OwnedWorkerRuntime as r, inspectSourceMapEnvelope as s, OwnedWorkerRuntime as t, cdpTargetEventMatches as u, init_runtimeVersion as v, readStableArtifact as x, javaScriptRuntime as y };