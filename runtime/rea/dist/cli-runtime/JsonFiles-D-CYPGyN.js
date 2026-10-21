import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisCancelledError, AnalysisResourceConstraintError, init_analysisErrorCore } from "./errorSchemas-BjJIu7zO.js";
import { err, init_result, ok } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { EvidenceFileError, init_evidenceErrors } from "./cliResultOutput-sm6qfiuc.js";
import { absoluteCallerPath, init_callerPath } from "./callerPath-D1wtkHi_.js";
import { ArtifactReaderFailure, NonRegularFileReadError, OwnedFileHandle, RegularFileCleanupFailure, init_ArtifactReader, init_OwnedFileHandle, init_OwnedRegularFile, init_RegularFile } from "./ArtifactReader-CGZcqzzo.js";
import { JsonInputCancellationFailure, JsonInputPhysicalReadFailure, init_JsonInputFile, readJsonInputFile, readJsonObjectFile } from "./JsonInputFile-dgK5dMrc.js";
import { init_RegularFileRead } from "./RegularFileRead-CQP0aNJS.js";
import { OwnedStagedOutput, init_OwnedStagedOutput } from "./OwnedStagedOutput-DQgZIDmg.js";
import { basename, dirname, resolve } from "node:path";
import { link, lstat, mkdtemp, open, realpath, rename } from "node:fs/promises";

//#region dist/application/JsonFiles.js
function writeTextParts(parts, path, overwrite, resources, cancellation) {
	return resources.run(() => writeTextPartsOwned(parts, path, overwrite, resources, cancellation)).catch((cause) => {
		const cleanup = cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined ? cause.cleanup : undefined;
		return err(new EvidenceFileError("write", "io", {
			cause,
			path: absoluteCallerPath(path),
			...cleanup === undefined ? {} : { cleanup }
		}));
	});
}
var readJsonFile, readJsonObjectMembersFile, readJsonFileInput, isJsonReadCancellation, writeTextFile, writeTextPartsOwned, missingOrIo, publishFile, StagedOutputCleanupFailure, failureMessage, writeStagedParts, assertWriteActive, fileErrorCode;
function init_JsonFiles() {
	return (init_JsonFiles = __esmMin((() => {
		init_evidenceErrors();
		init_analysisErrorCore();
		init_result();
		init_JsonInputFile();
		init_RegularFile();
		init_RegularFileRead();
		init_ArtifactReader();
		init_OwnedFileHandle();
		init_OwnedStagedOutput();
		init_callerPath();
		readJsonFile = async (path, signal, resources) => readJsonFileInput(path, (selected) => readJsonInputFile(selected, "read_evidence_file", signal, resources), signal);
		readJsonObjectMembersFile = (path, scans, signal, resources) => readJsonFileInput(path, (selected) => readJsonObjectFile(selected, "read_evidence_file", scans, signal, resources), signal);
		readJsonFileInput = async (path, read, signal) => {
			const requestedPath = absoluteCallerPath(path);
			try {
				const decoded = await read(requestedPath);
				if (!decoded.ok) {
					if (decoded.error instanceof AnalysisResourceConstraintError) return err(decoded.error);
					return err(new EvidenceFileError("read", "invalid-json", {
						cause: decoded.error.cause ?? new SyntaxError(decoded.error.issues[0]?.message ?? decoded.error.message),
						path: requestedPath
					}));
				}
				return ok(decoded.value);
			} catch (cause) {
				if (cause instanceof RegularFileCleanupFailure) throw cause;
				if (cause instanceof AnalysisResourceConstraintError) return err(cause);
				if (cause instanceof JsonInputCancellationFailure) return err(new AnalysisCancelledError("read_evidence_file", { cause: cause.reason }));
				if (cause instanceof JsonInputPhysicalReadFailure) return err(new EvidenceFileError("read", "io", {
					cause: cause.physicalCause,
					path: requestedPath
				}));
				if (isJsonReadCancellation(cause, signal)) return err(new AnalysisCancelledError("read_evidence_file", { cause: signal?.reason }));
				return err(new EvidenceFileError("read", cause instanceof NonRegularFileReadError ? "not-file" : missingOrIo(cause), {
					cause,
					path: requestedPath
				}));
			}
		};
		isJsonReadCancellation = (cause, signal) => {
			if (signal?.aborted !== true) return false;
			if (cause === signal.reason) return true;
			return cause instanceof Error && cause.name === "AbortError" && "code" in cause && cause.code === "ABORT_ERR" && cause.cause === signal.reason;
		};
		writeTextFile = async (encoded, path, overwrite, resources) => writeTextParts([encoded], path, overwrite, resources);
		writeTextPartsOwned = async (parts, path, overwrite, resources, cancellation) => {
			const requestedPath = absoluteCallerPath(path);
			try {
				assertWriteActive(cancellation);
				if (process.platform !== "win32" && requestedPath.endsWith("/")) return err(new EvidenceFileError("write", "not-file", { path: requestedPath }));
				const canonicalParent = await realpath(dirname(requestedPath));
				const destination = resolve(canonicalParent, basename(requestedPath));
				const existing = await lstat(destination).catch((cause) => {
					if (fileErrorCode(cause) === "ENOENT") return undefined;
					throw cause;
				});
				if (existing !== undefined) {
					if (!overwrite) return err(new EvidenceFileError("write", "exists", { path: requestedPath }));
					if (!existing.isFile() || existing.isSymbolicLink()) return err(new EvidenceFileError("write", "not-file", { path: requestedPath }));
				}
				assertWriteActive(cancellation);
				const bytes = await publishFile(destination, parts, overwrite, resources, cancellation);
				return ok({
					path: requestedPath,
					bytes
				});
			} catch (cause) {
				if (cause instanceof StagedOutputCleanupFailure) {
					const cleanup = {
						reason: failureMessage(cause.cleanupCause),
						resources: [cause.owner.directory]
					};
					if (cause.outcome.ok) return err(new EvidenceFileError("write", "io", {
						cause,
						path: requestedPath,
						cleanup,
						published: {
							...cause.outcome.value,
							path: requestedPath
						}
					}));
					if (cause.outcome.error instanceof AnalysisCancelledError) return err(new AnalysisCancelledError(cause.outcome.error.operation, {
						cause: cause.outcome.error.cause,
						cleanupPrimary: cause.outcome.error,
						cleanup
					}));
					return err(new EvidenceFileError("write", missingOrIo(cause.outcome.error), {
						cause,
						path: requestedPath,
						cleanup
					}));
				}
				if (cancellation?.signal.aborted === true && cause instanceof AnalysisCancelledError && cause.operation === cancellation.operation) return err(cause);
				if (!overwrite && fileErrorCode(cause) === "EEXIST") return err(new EvidenceFileError("write", "exists", {
					cause,
					path: requestedPath
				}));
				return err(new EvidenceFileError("write", missingOrIo(cause), {
					cause,
					path: requestedPath
				}));
			}
		};
		missingOrIo = (cause) => {
			const code = fileErrorCode(cause);
			return code === "ENOENT" || code === "ENOTDIR" ? "missing" : "io";
		};
		publishFile = async (destination, parts, overwrite, resources, cancellation) => {
			const stagingDirectory = await mkdtemp(resolve(dirname(destination), ".rea-write-"));
			const owner = await OwnedStagedOutput.create(stagingDirectory);
			let outcome;
			const staged = resolve(stagingDirectory, "content");
			try {
				const file = await open(staged, "wx", 384);
				owner.setFile(new OwnedFileHandle(file));
				let written;
				try {
					const bytes = await writeStagedParts(file, parts, cancellation);
					assertWriteActive(cancellation);
					await file.sync();
					written = ok(bytes);
				} catch (cause) {
					written = err(cause);
				}
				try {
					await owner.closeFile();
				} catch (cause) {
					if (written.ok) written = err(cause);
				}
				if (!written.ok) throw written.error;
				assertWriteActive(cancellation);
				await owner.assertReadyForPublication(staged);
				assertWriteActive(cancellation);
				if (overwrite) {
					await rename(staged, destination);
					owner.recordPublishedRename();
				} else await link(staged, destination);
				outcome = ok({
					path: destination,
					bytes: written.value
				});
			} catch (cause) {
				outcome = err(cause);
			}
			const released = await resources.release({
				kind: "staged-output",
				resource: owner.directory,
				output: owner
			});
			if (released.kind === "failed") throw new StagedOutputCleanupFailure(outcome, released.cause, owner);
			if (!outcome.ok) throw outcome.error;
			return outcome.value.bytes;
		};
		StagedOutputCleanupFailure = class extends Error {
			outcome;
			cleanupCause;
			owner;
			constructor(outcome, cleanupCause, owner) {
				super("Staged output cleanup failed", { cause: outcome.ok ? cleanupCause : outcome.error });
				this.outcome = outcome;
				this.cleanupCause = cleanupCause;
				this.owner = owner;
			}
		};
		failureMessage = (cause) => cause instanceof Error ? cause.message || cause.name : String(cause);
		writeStagedParts = async (file, parts, cancellation) => {
			assertWriteActive(cancellation);
			const iterator = parts[Symbol.iterator]();
			let exhausted = false;
			let bytes = 0;
			try {
				for (;;) {
					assertWriteActive(cancellation);
					const part = iterator.next();
					if (part.done) exhausted = true;
					assertWriteActive(cancellation);
					if (part.done) return bytes;
					await file.writeFile(part.value, { encoding: "utf8" });
					bytes += Buffer.byteLength(part.value, "utf8");
				}
			} finally {
				if (!exhausted) iterator.return?.();
			}
		};
		assertWriteActive = (cancellation) => {
			if (cancellation?.signal.aborted === true) throw new AnalysisCancelledError(cancellation.operation, { cause: cancellation.signal.reason });
		};
		fileErrorCode = (cause) => typeof cause === "object" && cause !== null && "code" in cause ? cause.code : undefined;
	})))();
}

//#endregion
export { init_JsonFiles, readJsonFile, readJsonObjectMembersFile, writeTextFile, writeTextParts };