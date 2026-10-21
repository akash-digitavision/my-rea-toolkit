import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { _ as init_OwnedFileHandle, d as RegularFileOperationCancelled, g as OwnedFileHandle, i as init_OwnedRegularFile, n as RegularFileCancelled, o as withOwnedFileHandle, p as init_RegularFile, r as RegularFileCleanupFailure, s as withOwnedRegularFile, v as ArtifactReaderFailure, x as init_ArtifactReader, y as artifactPrimaryCleanupLeases } from "./OwnedRegularFile--jcCKh4T.js";
import { n as AnalysisCleanupLeaseGroup, r as init_AnalysisCleanupLease, t as AnalysisCleanupLease } from "./AnalysisCleanupLease-Dw4q6-cP.js";

//#region dist/artifacts/ArtifactFileOperation.js
var ArtifactFileCleanupFailure, mapArtifactFileFailure, artifactFilePrimaryFailure, ArtifactFileCancelled, bindArtifactFileCleanup, artifactFileCancellationCause, assertArtifactReadActive, withArtifactRegularFile, withArtifactFileHandle, artifactOperationCause;
function init_ArtifactFileOperation() {
	return (init_ArtifactFileOperation = __esmMin((() => {
		init_RegularFile();
		init_OwnedFileHandle();
		init_OwnedRegularFile();
		init_ArtifactReader();
		init_AnalysisCleanupLease();
		ArtifactFileCleanupFailure = class extends ArtifactReaderFailure {
			cleanupLease;
			cleanupLeases;
			fileCleanupFailure;
			constructor(fileCleanupFailure, cleanupLease) {
				const outcome = fileCleanupFailure.outcome;
				if (outcome.kind === "failed" && outcome.cause instanceof RegularFileOperationCancelled) fileCleanupFailure = new RegularFileCleanupFailure(fileCleanupFailure.path, fileCleanupFailure.owner, {
					kind: "failed",
					cause: artifactOperationCause(outcome.cause)
				}, fileCleanupFailure.cleanupCause, fileCleanupFailure.retention, fileCleanupFailure.completionCancellation);
				const completionCancellation = fileCleanupFailure.completionCancellation;
				const primary = fileCleanupFailure.outcome.kind === "failed" ? fileCleanupFailure.outcome.cause : completionCancellation === undefined ? fileCleanupFailure.cleanupCause : new ArtifactReaderFailure("cancelled", "Artifact read cancelled during close", { cause: completionCancellation.reason });
				const projected = ArtifactReaderFailure.withCleanup(primary, ArtifactReaderFailure.cleanupObservation(fileCleanupFailure.cleanupCause, fileCleanupFailure.path));
				super(projected.reason, projected.message, {
					cause: fileCleanupFailure,
					cleanup: projected.cleanup,
					partialObservation: projected.partialObservation,
					cancellation: projected.cancellation,
					...projected.boundary === undefined ? {} : { boundary: projected.boundary }
				}, projected.details);
				this.cleanupLease = cleanupLease;
				this.fileCleanupFailure = fileCleanupFailure;
				const inherited = fileCleanupFailure.outcome.kind === "failed" ? artifactPrimaryCleanupLeases(fileCleanupFailure.outcome.cause) : [];
				this.cleanupLeases = inherited === undefined ? undefined : [...new Set([cleanupLease, ...inherited])];
			}
		};
		mapArtifactFileFailure = (cause, classify) => {
			if (!(cause instanceof ArtifactFileCleanupFailure)) return classify(cause);
			const physical = cause.fileCleanupFailure;
			if (physical.outcome.kind !== "failed") return cause;
			const primary = physical.outcome.cause instanceof ArtifactFileCleanupFailure ? mapArtifactFileFailure(physical.outcome.cause, classify) : classify(physical.outcome.cause);
			if (primary === physical.outcome.cause) return cause;
			return new ArtifactFileCleanupFailure(new RegularFileCleanupFailure(physical.path, physical.owner, {
				kind: "failed",
				cause: primary
			}, physical.cleanupCause, physical.retention, physical.completionCancellation), cause.cleanupLease);
		};
		artifactFilePrimaryFailure = (cause) => {
			while (cause instanceof ArtifactFileCleanupFailure && cause.fileCleanupFailure.outcome.kind === "failed") cause = cause.fileCleanupFailure.outcome.cause;
			return cause;
		};
		ArtifactFileCancelled = class extends ArtifactReaderFailure {
			fileCancellation;
			constructor(fileCancellation) {
				super("cancelled", "Artifact read cancelled", { cause: fileCancellation.reason });
				this.fileCancellation = fileCancellation;
			}
		};
		bindArtifactFileCleanup = (cause, error) => {
			const leases = cause instanceof ArtifactReaderFailure ? cause.cleanupLeases : undefined;
			if (leases !== undefined) new AnalysisCleanupLeaseGroup(error, leases);
		};
		artifactFileCancellationCause = (cause) => {
			return cause.cancellation === undefined ? cause.cause : cause.cancellation.reason;
		};
		assertArtifactReadActive = (signal) => {
			if (signal?.aborted) throw new ArtifactReaderFailure("cancelled", "Artifact read cancelled", { cause: signal.reason });
		};
		withArtifactRegularFile = async (path, resources, signal, operation, symlinks = "reject") => {
			let cleanupLease;
			assertArtifactReadActive(signal);
			try {
				const value = await withOwnedRegularFile(path, {
					symlinks,
					...signal === undefined ? {} : { signal },
					retainFailedClose: (owner) => {
						cleanupLease = new AnalysisCleanupLease(() => owner.close(), [path]);
						resources.retain({
							kind: "lease",
							resource: path,
							lease: cleanupLease
						});
					}
				}, async (file) => {
					assertArtifactReadActive(signal);
					return await operation(file);
				});
				return value;
			} catch (cause) {
				if (cause instanceof RegularFileCleanupFailure && cleanupLease !== undefined) throw new ArtifactFileCleanupFailure(cause, cleanupLease);
				if (cause instanceof RegularFileCancelled) throw new ArtifactFileCancelled(cause);
				throw artifactOperationCause(cause);
			}
		};
		withArtifactFileHandle = async (path, file, resources, signal, operation) => {
			const owner = new OwnedFileHandle(file);
			const cleanupLease = new AnalysisCleanupLease(() => owner.close(), [path]);
			try {
				return await withOwnedFileHandle(path, owner, {
					...signal === undefined ? {} : { signal },
					retainFailedClose: () => resources?.retain({
						kind: "lease",
						resource: path,
						lease: cleanupLease
					})
				}, operation);
			} catch (cause) {
				if (cause instanceof RegularFileCleanupFailure) throw new ArtifactFileCleanupFailure(cause, cleanupLease);
				if (cause instanceof RegularFileCancelled) throw new ArtifactFileCancelled(cause);
				throw artifactOperationCause(cause);
			}
		};
		artifactOperationCause = (cause) => cause instanceof RegularFileOperationCancelled ? new ArtifactReaderFailure("cancelled", "Artifact file operation cancelled", { cause: cause.reason }) : cause;
	})))();
}

//#endregion
export { assertArtifactReadActive as a, mapArtifactFileFailure as c, artifactFilePrimaryFailure as i, withArtifactFileHandle as l, ArtifactFileCleanupFailure as n, bindArtifactFileCleanup as o, artifactFileCancellationCause as r, init_ArtifactFileOperation as s, ArtifactFileCancelled as t, withArtifactRegularFile as u };