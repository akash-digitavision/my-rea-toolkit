import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisAccessDeniedError, AnalysisArtifactChangedError, AnalysisCancelledError, AnalysisCapabilityUnavailableError, AnalysisError, AnalysisOutputError, AnalysisResourceConstraintError, AnalysisTimeoutError, init_analysisErrorBase, init_analysisErrorCore, init_jsonValue, jsonValueSchema } from "./errorSchemas-BjJIu7zO.js";
import { HopperProcessError, HopperRemoteError, HopperTimeoutError, ProviderAdapterError, init_hopperErrors, init_providerAdapterError } from "./cliResultOutput-sm6qfiuc.js";
import { ArtifactReaderFailure, RegularFileChangedError, assertRegularFileActive, init_ArtifactReader, init_RegularFile, sameRegularFileState } from "./ArtifactReader-CGZcqzzo.js";
import { AnalysisCleanupLease, init_AnalysisCleanupLease } from "./AnalysisCleanupLease-CWfTGYKd.js";
import { analysisErrorWithCleanupFailure, init_analysisErrorCleanup } from "./analysisErrorCleanup-D5kfOoKV.js";
import { ProviderCleanupError, init_providerCleanupError } from "./providerCleanupError-BxCL-KMk.js";
import { artifactFileCancellationCause, artifactFilePrimaryFailure, assertArtifactReadActive, bindArtifactFileCleanup, init_ArtifactFileOperation, mapArtifactFileFailure, withArtifactFileHandle, withArtifactRegularFile } from "./ArtifactFileOperation-ynaKMviK.js";
import { DarwinProcessOwnershipInspectionError, init_DarwinProcessRunTokenReader } from "./ProcessOwnershipEvidence-CThMxAij.js";
import { OwnedCommandFailure, init_OwnedCommand } from "./OwnedCommand-Dl2yPZeW.js";
import { lstat, open, stat } from "node:fs/promises";

//#region dist/filesystem/readStableFileBytes.js
var RegularFileCapacityError, readStableFileBytes, readStableFilePrefix, readExtent, assertStableIdentity;
function init_readStableFileBytes() {
	return (init_readStableFileBytes = __esmMin((() => {
		init_RegularFile();
		RegularFileCapacityError = class extends Error {
			path;
			maximumBytes;
			observedBytes;
			_tag = "RegularFileCapacityError";
			constructor(path, maximumBytes, observedBytes) {
				super(`Selected file must be at most ${maximumBytes} bytes: ${path}`);
				this.path = path;
				this.maximumBytes = maximumBytes;
				this.observedBytes = observedBytes;
				this.name = this._tag;
			}
		};
		readStableFileBytes = async (file, path, maximumBytes, options) => {
			if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new RangeError("Maximum file bytes must be a nonnegative safe integer");
			assertRegularFileActive(options.signal);
			const before = await file.stat({ bigint: true });
			if (before.size > BigInt(maximumBytes)) throw new RegularFileCapacityError(path, maximumBytes, before.size);
			const bytes = await readExtent(file, path, Number(before.size), options.signal);
			assertRegularFileActive(options.signal);
			const extra = Buffer.alloc(1);
			if ((await file.read(extra, 0, 1, bytes.length)).bytesRead !== 0) throw new RegularFileChangedError(path);
			await assertStableIdentity(file, path, before, options);
			return bytes;
		};
		readStableFilePrefix = async (file, path, maximumBytes, options) => {
			if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new RangeError("Maximum prefix bytes must be a nonnegative safe integer");
			assertRegularFileActive(options.signal);
			const before = await file.stat({ bigint: true });
			const length = Number(before.size < BigInt(maximumBytes) ? before.size : BigInt(maximumBytes));
			const bytes = await readExtent(file, path, length, options.signal);
			await assertStableIdentity(file, path, before, options);
			return {
				bytes,
				size: before.size
			};
		};
		readExtent = async (file, path, length, signal) => {
			assertRegularFileActive(signal);
			const bytes = Buffer.alloc(length);
			let offset = 0;
			while (offset < bytes.length) {
				assertRegularFileActive(signal);
				const read = await file.read({
					buffer: bytes,
					offset,
					length: bytes.length - offset,
					position: offset
				});
				if (read.bytesRead === 0) throw new RegularFileChangedError(path);
				offset += read.bytesRead;
			}
			assertRegularFileActive(signal);
			return bytes;
		};
		assertStableIdentity = async (file, path, before, options) => {
			assertRegularFileActive(options.signal);
			const named = async () => {
				try {
					return await (options.symlinks === "follow" ? stat : lstat)(path, { bigint: true });
				} catch (cause) {
					if (cause instanceof Error && "code" in cause && (cause.code === "ENOENT" || cause.code === "ENOTDIR" || cause.code === "ELOOP")) throw new RegularFileChangedError(path, { cause });
					throw cause;
				}
			};
			if (!sameRegularFileState(before, await file.stat({ bigint: true })) || !sameRegularFileState(before, await named())) throw new RegularFileChangedError(path);
			assertRegularFileActive(options.signal);
		};
	})))();
}

//#endregion
//#region dist/ghidra/GhidraFileArtifacts.js
var readGhidraProfileArtifact, writeGhidraProfileArtifact, ghidraFileFailure;
function init_GhidraFileArtifacts() {
	return (init_GhidraFileArtifacts = __esmMin((() => {
		init_ArtifactReader();
		init_ArtifactFileOperation();
		init_readStableFileBytes();
		init_analysisErrorBase();
		init_analysisErrorCore();
		init_RegularFile();
		init_providerAdapterError();
		init_providerCleanupError();
		init_analysisErrorCleanup();
		readGhidraProfileArtifact = (path, maximumBytes, resources, signal, interpret) => withArtifactRegularFile(path, resources, signal, async (file) => {
			const bytes = await readStableFileBytes(file, path, maximumBytes, {
				symlinks: "reject",
				...signal === undefined ? {} : { signal }
			});
			return interpret(bytes);
		});
		writeGhidraProfileArtifact = async (path, bytes, resources, signal) => {
			assertArtifactReadActive(signal);
			const file = await open(path, "wx", 384);
			await withArtifactFileHandle(path, file, resources, signal, (handle) => handle.writeFile(bytes));
		};
		ghidraFileFailure = (cause, operation, diagnostics = {}) => {
			cause = mapArtifactFileFailure(cause, (primary) => {
				if (primary instanceof RegularFileCapacityError) return new AnalysisResourceConstraintError(operation, "file-size", primary.message, {
					maximum_bytes: primary.maximumBytes,
					observed_bytes: primary.observedBytes.toString()
				}, {
					cause: primary,
					diagnostics,
					retryable: false
				});
				if (primary instanceof RegularFileChangedError) return new AnalysisArtifactChangedError(operation, primary.path, primary.message, {
					cause: primary,
					diagnostics
				});
				if (primary instanceof Error && "code" in primary && (primary.code === "EACCES" || primary.code === "EPERM")) {
					const path = "path" in primary && typeof primary.path === "string" ? primary.path : diagnostics.path;
					if (typeof path === "string") return new AnalysisAccessDeniedError(operation, path, primary.code, {
						cause: primary,
						diagnostics
					});
				}
				return primary;
			});
			if (cause instanceof AnalysisError) return cause;
			const primary = artifactFilePrimaryFailure(cause);
			const reason = primary instanceof Error ? primary.message : String(primary);
			const cleanup = cause instanceof ArtifactReaderFailure ? cause.cleanup : undefined;
			if (primary instanceof AnalysisError) {
				if (cleanup === undefined) return primary;
				const failure = new ProviderCleanupError("ghidra", cleanup.resources, { reason: cleanup.reason }, { cause });
				bindArtifactFileCleanup(cause, failure);
				return analysisErrorWithCleanupFailure(primary, failure, operation).bindCleanupDependencies([...primary.cleanupIncomplete ? [primary] : [], failure]);
			}
			const error = cause instanceof ArtifactReaderFailure && cause.reason === "cancelled" ? new AnalysisCancelledError(operation, {
				cause: artifactFileCancellationCause(cause),
				cleanup,
				diagnostics
			}) : new ProviderAdapterError("ghidra", operation, {
				cause,
				cleanup,
				diagnostics: {
					...diagnostics,
					...primary instanceof Error && "code" in primary && typeof primary.code === "string" ? { system_code: primary.code } : {},
					...primary instanceof Error && "syscall" in primary && typeof primary.syscall === "string" ? { syscall: primary.syscall } : {},
					reason
				},
				userMessage: reason
			});
			bindArtifactFileCleanup(cause, error);
			return error;
		};
	})))();
}

//#endregion
//#region dist/providers/AnalysisClientFailure.js
var analysisClientFailureContext, analysisClientFailureForOperation;
function init_AnalysisClientFailure() {
	return (init_AnalysisClientFailure = __esmMin((() => {
		init_hopperErrors();
		init_analysisErrorBase();
		init_analysisErrorCore();
		init_providerAdapterError();
		init_providerCleanupError();
		init_ArtifactReader();
		init_ArtifactFileOperation();
		analysisClientFailureContext = (cause, providerId, operation) => {
			const providerRequest = cause instanceof HopperRemoteError || cause instanceof HopperTimeoutError || cause instanceof HopperProcessError ? {
				...cause.operation === undefined ? {} : { operation: cause.operation },
				...cause.requestId === undefined ? {} : { request_id: cause.requestId },
				...cause instanceof HopperRemoteError ? {
					provider_code: cause.code,
					diagnostic_type: cause.diagnosticType
				} : {}
			} : undefined;
			const diagnostics = providerRequest === undefined ? cause.diagnostics : {
				provider_request: providerRequest,
				...cause.diagnostics === undefined ? {} : { provider_diagnostics: cause.diagnostics }
			};
			return {
				cause,
				...cause.cleanupPrimary === undefined ? {} : { cleanupPrimary: analysisClientFailureForOperation(cause.cleanupPrimary, providerId, operation) },
				...cause.partialObservation === undefined ? {} : { partialObservation: cause.partialObservation },
				...cause.capturedOutput === undefined ? {} : { capturedOutput: cause.capturedOutput },
				...diagnostics === undefined ? {} : { diagnostics },
				...cause.cleanupIncomplete ? { cleanup: {
					reason: cause.cleanup?.reason ?? cause.message,
					resources: cause.cleanupResources
				} } : {}
			};
		};
		analysisClientFailureForOperation = (cause, providerId, operation, callerDiagnostics) => {
			if (!(cause instanceof AnalysisError)) {
				const failure = new ProviderAdapterError(providerId, operation, {
					cause,
					...callerDiagnostics === undefined ? {} : { diagnostics: callerDiagnostics },
					...cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined ? { cleanup: cause.cleanup } : {}
				});
				bindArtifactFileCleanup(cause, failure);
				return failure;
			}
			if (!(cause instanceof HopperRemoteError) && !(cause instanceof HopperTimeoutError) && !(cause instanceof HopperProcessError) && !(cause instanceof AnalysisCancelledError) && !(cause instanceof ProviderAdapterError) && !(cause instanceof AnalysisCapabilityUnavailableError) && !(cause instanceof AnalysisAccessDeniedError) && !(cause instanceof AnalysisArtifactChangedError) && !(cause instanceof AnalysisTimeoutError) && !(cause instanceof AnalysisOutputError) && !(cause instanceof AnalysisResourceConstraintError)) return cause;
			const sourceContext = analysisClientFailureContext(cause, providerId, operation);
			const context = {
				...sourceContext,
				...callerDiagnostics === undefined ? {} : { diagnostics: {
					...sourceContext.diagnostics,
					...callerDiagnostics
				} }
			};
			let result;
			if (cause instanceof HopperRemoteError) result = new HopperRemoteError(cause.code, cause.safeMessage, {
				...context,
				operation,
				requestId: cause.requestId,
				diagnosticType: cause.diagnosticType
			});
			else if (cause instanceof HopperTimeoutError) result = new HopperTimeoutError(cause.timeoutMs, operation, cause.requestId, cause.providerState, cause.stage, cause.launcherOutcome, context);
			else if (cause instanceof HopperProcessError) result = new HopperProcessError(cause.exitCode, {
				...context,
				operation,
				requestId: cause.requestId,
				providerState: cause.providerState,
				stage: cause.stage,
				...cause.diagnostic === undefined ? {} : { diagnostic: cause.diagnostic },
				...cause.launcherFailure === undefined ? {} : { launcherFailure: cause.launcherFailure }
			});
			else if (cause instanceof ProviderCleanupError) {
				const { diagnostics, ...outcomeContext } = context;
				result = new ProviderCleanupError(cause.providerId, cause.cleanupResources, diagnostics ?? {}, {
					...outcomeContext,
					operation,
					...cause.remediationAction === undefined ? {} : { remediationAction: cause.remediationAction }
				});
			} else if (cause instanceof AnalysisTimeoutError) result = new AnalysisTimeoutError(operation, cause.timeoutMs, {
				...context,
				...cause.userMessage === undefined ? {} : { userMessage: cause.userMessage },
				...cause.remediationAction === undefined ? {} : { remediationAction: cause.remediationAction }
			});
			else if (cause instanceof AnalysisOutputError) result = new AnalysisOutputError(operation, cause.reason, {
				...context,
				cleanupOnly: cause.cleanupOnly,
				...cause.userMessage === undefined ? {} : { userMessage: cause.userMessage },
				...cause.remediationAction === undefined ? {} : { remediationAction: cause.remediationAction }
			});
			else if (cause instanceof AnalysisCancelledError) result = new AnalysisCancelledError(operation, {
				...context,
				cause: cause.cause
			});
			else if (cause instanceof AnalysisCapabilityUnavailableError) result = new AnalysisCapabilityUnavailableError(cause.providerId, operation, cause.reason, {
				...context,
				...cause.userMessage === undefined ? {} : { userMessage: cause.userMessage },
				retryable: cause.retryable
			});
			else if (cause instanceof AnalysisAccessDeniedError) result = new AnalysisAccessDeniedError(operation, cause.path, cause.systemCode, context);
			else if (cause instanceof AnalysisArtifactChangedError) result = new AnalysisArtifactChangedError(operation, cause.path, cause.reason, context);
			else if (cause instanceof AnalysisResourceConstraintError) result = new AnalysisResourceConstraintError(operation, cause.resource, cause.reason, cause.reportedLimits, {
				...context,
				...cause.retryable === undefined ? {} : { retryable: cause.retryable },
				...cause.remediationAction === undefined ? {} : { remediationAction: cause.remediationAction }
			});
			else result = new ProviderAdapterError(providerId, operation, {
				...context,
				...cause.userMessage === undefined ? {} : { userMessage: cause.userMessage },
				...cause.remediationAction === undefined ? {} : { remediationAction: cause.remediationAction }
			});
			return cause.cleanupIncomplete ? result.bindCleanupDependencies([cause]) : result.resolveCleanup();
		};
	})))();
}

//#endregion
//#region dist/providers/OwnedCommandCleanup.js
var retainOwnedCommandCleanup;
function init_OwnedCommandCleanup() {
	return (init_OwnedCommandCleanup = __esmMin((() => {
		init_jsonValue();
		init_AnalysisCleanupLease();
		init_providerCleanupError();
		init_DarwinProcessRunTokenReader();
		init_OwnedCommand();
		retainOwnedCommandCleanup = (cause, resourceOwner, providerId, operation) => {
			const commandFailure = cause instanceof OwnedCommandFailure ? cause : undefined;
			const preparation = commandFailure?.preparationFailure ?? (cause instanceof DarwinProcessOwnershipInspectionError ? cause : undefined);
			const cleanups = [];
			if (preparation?.cleanupFailure !== undefined) {
				const cleanup = preparation.cleanupFailure;
				const lease = new AnalysisCleanupLease(async () => {
					if (!cleanup.cleanupIncomplete) return;
					if (preparation.cleanupOwner === undefined) throw cleanup;
					await preparation.cleanupOwner.close();
					if (cleanup.cleanupIncomplete) throw cleanup;
				}, cleanup);
				resourceOwner.retain({
					close: () => lease.release(),
					get cleanupResources() {
						return cleanup.cleanupResources;
					}
				}, cleanup.cleanupResources[0] ?? "Provider prerequisite ownership preparation");
				cleanups.push(cleanup);
			}
			if (commandFailure !== undefined && (commandFailure.cleanupOwner !== undefined || commandFailure.cleanupFailure !== null)) {
				const supervisor = commandFailure.cleanupOwner;
				const cleanup = new ProviderCleanupError(providerId, commandFailure.resources, {
					reason: commandFailure.cleanupFailure ?? "Provider prerequisite cleanup remains incomplete",
					...commandFailure.cleanupResult === undefined ? {} : { process_cleanup: jsonValueSchema.parse(commandFailure.cleanupResult) }
				}, {
					cause,
					operation
				});
				const lease = new AnalysisCleanupLease(async () => {
					if (supervisor === undefined) throw cleanup;
					const stopped = await supervisor.stop();
					if (stopped.status === "incomplete") throw cleanup;
				}, commandFailure.resources);
				cleanup.bindCleanupResourceOwner(lease);
				lease.bindCleanupError(cleanup);
				resourceOwner.retain({
					close: () => lease.release(),
					get cleanupResources() {
						return cleanup.cleanupResources;
					}
				}, commandFailure.resources[0] ?? "Provider prerequisite process");
				cleanups.push(cleanup);
			}
			return cleanups;
		};
	})))();
}

//#endregion
export { analysisClientFailureContext, analysisClientFailureForOperation, ghidraFileFailure, init_AnalysisClientFailure, init_GhidraFileArtifacts, init_OwnedCommandCleanup, init_readStableFileBytes, readGhidraProfileArtifact, readStableFileBytes, readStableFilePrefix, retainOwnedCommandCleanup, writeGhidraProfileArtifact };