import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { n as init_analysisErrorBase, t as AnalysisError } from "./analysisErrorBase-C1inc3JA.js";
import { v as ArtifactReaderFailure, x as init_ArtifactReader } from "./OwnedRegularFile--jcCKh4T.js";
import { n as ArtifactResourceScope, r as init_ArtifactResourceScope } from "./ArtifactResourceScope-DvfrfS9d.js";
import { _ as init_providerAdapterError, g as ProviderAdapterError } from "./analysisErrorProjection-DPMozIkD.js";
import { f as init_analysisErrorCore, i as AnalysisCancelledError } from "./analysisErrorCore-BMJXbfFY.js";
import { i as init_providerCleanupError, n as init_analysisErrorCleanup, r as ProviderCleanupError, t as analysisErrorWithCleanupFailure } from "./analysisErrorCleanup-LFIV2yDc.js";
import { a as assertArtifactReadActive, l as withArtifactFileHandle, n as ArtifactFileCleanupFailure, o as bindArtifactFileCleanup, s as init_ArtifactFileOperation } from "./ArtifactFileOperation-B41PVRrO.js";
import { i as init_AsarHeader, n as admitAsarHeader, t as MAX_ASAR_HEADER_BYTES } from "./AsarHeader-BdSam8d1.js";
import { isAbsolute, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { open, realpath, stat } from "node:fs/promises";

//#region dist/browser/ElectronFileScope.js
var resources, authorizedElectronFile, retryElectronFileCleanup, mapElectronFileAuthorizationFailure, resolveAuthorizedElectronFile, authorizedAsarMember, MAX_CACHED_HEADERS, headerCache, archiveIdentity, asarFiles, isAsarRegularFile, isRecord, throwIfAborted;
function init_ElectronFileScope() {
	return (init_ElectronFileScope = __esmMin((() => {
		init_analysisErrorCore();
		init_analysisErrorBase();
		init_analysisErrorCleanup();
		init_providerAdapterError();
		init_providerCleanupError();
		init_ArtifactFileOperation();
		init_ArtifactReader();
		init_ArtifactResourceScope();
		init_AsarHeader();
		resources = new ArtifactResourceScope();
		authorizedElectronFile = async (value, signal, operation = "inspect_electron_page") => {
			try {
				return await resources.run(async () => await resolveAuthorizedElectronFile(value, signal));
			} catch (cause) {
				if (cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined) throw cause;
				if (signal?.aborted === true) throw new AnalysisCancelledError(operation, { cause: signal.reason });
				throw cause;
			}
		};
		retryElectronFileCleanup = async () => await resources.retryCleanup();
		mapElectronFileAuthorizationFailure = (cause, providerId, operation, diagnostics) => {
			if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined) return undefined;
			const physical = cause instanceof ArtifactFileCleanupFailure ? cause.fileCleanupFailure : undefined;
			const physicalPrimary = physical?.outcome.kind === "failed" ? physical.outcome.cause : undefined;
			const cancellationReason = physical?.completionCancellation === undefined ? physicalPrimary instanceof ArtifactReaderFailure && physicalPrimary.reason === "cancelled" ? physicalPrimary.cancellation === undefined ? physicalPrimary.cause : physicalPrimary.cancellation.reason : undefined : physical.completionCancellation.reason;
			const hasCancellation = physical?.completionCancellation !== undefined || physicalPrimary instanceof ArtifactReaderFailure && physicalPrimary.reason === "cancelled";
			const primary = hasCancellation ? new AnalysisCancelledError(operation, {
				cause: cancellationReason,
				...diagnostics === undefined ? {} : { diagnostics }
			}) : physicalPrimary instanceof AnalysisError ? physicalPrimary : physicalPrimary === undefined ? undefined : new ProviderAdapterError(providerId, operation, { cause: physicalPrimary });
			const cleanup = new ProviderCleanupError(providerId, cause.cleanup.resources, { reason: cause.cleanup.reason }, {
				operation,
				cause
			});
			bindArtifactFileCleanup(cause, cleanup);
			if (primary === undefined) return cleanup;
			const composed = analysisErrorWithCleanupFailure(primary, cleanup, operation);
			bindArtifactFileCleanup(cause, composed);
			return composed;
		};
		resolveAuthorizedElectronFile = async (value, signal) => {
			throwIfAborted(signal);
			if (/%(?:2f|5c)/iu.test(value)) return undefined;
			let url;
			try {
				url = new URL(value);
			} catch (cause) {
				void cause;
				return undefined;
			}
			if (url.protocol !== "file:" || url.hostname !== "" || url.username !== "" || url.password !== "") return undefined;
			let path;
			try {
				path = fileURLToPath(url);
			} catch (cause) {
				void cause;
				return undefined;
			}
			if (!isAbsolute(path) || path.includes("\0")) return undefined;
			try {
				const metadata = await stat(path);
				throwIfAborted(signal);
				if (metadata.isFile()) {
					const canonical = await realpath(path);
					throwIfAborted(signal);
					return canonical;
				}
			} catch (cause) {
				throwIfAborted(signal);
				void cause;
			}
			throwIfAborted(signal);
			return await authorizedAsarMember(path, signal);
		};
		authorizedAsarMember = async (path, signal) => {
			const segments = path.split(sep);
			for (let index = 1; index < segments.length - 1; index += 1) {
				throwIfAborted(signal);
				if (!(segments[index] ?? "").toLowerCase().endsWith(".asar")) continue;
				const archive = segments.slice(0, index + 1).join(sep);
				const member = segments.slice(index + 1);
				if (member.some((part) => part === "" || part === "." || part === "..")) return undefined;
				try {
					const metadata = await stat(archive);
					throwIfAborted(signal);
					if (!metadata.isFile()) continue;
					const canonical = await realpath(archive);
					throwIfAborted(signal);
					const files = await asarFiles(canonical, metadata, signal, resources);
					throwIfAborted(signal);
					return isAsarRegularFile(files, member) ? join(canonical, ...member) : undefined;
				} catch (cause) {
					if (cause instanceof ArtifactFileCleanupFailure) throw cause;
					if (cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined) throw cause;
					throwIfAborted(signal);
					void cause;
					return undefined;
				}
			}
			return undefined;
		};
		MAX_CACHED_HEADERS = 8;
		headerCache = new Map();
		archiveIdentity = (metadata) => `${String(metadata.dev)}:${String(metadata.ino)}:${String(metadata.size)}:${String(metadata.mtimeMs)}`;
		asarFiles = async (archive, metadata, signal, resources) => {
			throwIfAborted(signal);
			const identity = archiveIdentity(metadata);
			const cached = headerCache.get(archive);
			if (cached?.identity === identity) return cached.files;
			const handle = await open(archive, "r");
			const admitted = await withArtifactFileHandle(archive, handle, resources, signal, async (file) => {
				let jsonBytes;
				throwIfAborted(signal);
				const opened = await file.stat();
				throwIfAborted(signal);
				if (!opened.isFile() || archiveIdentity(opened) !== identity) throw new Error("ASAR identity changed before header read");
				const header = await admitAsarHeader(file, signal);
				throwIfAborted(signal);
				jsonBytes = header.jsonBytes;
				const json = Buffer.alloc(jsonBytes);
				let offset = 0;
				while (offset < json.length) {
					throwIfAborted(signal);
					const part = await file.read(json, offset, json.length - offset, 16 + offset);
					throwIfAborted(signal);
					if (part.bytesRead === 0) throw new Error("Truncated ASAR JSON header");
					offset += part.bytesRead;
				}
				const afterRead = await file.stat();
				throwIfAborted(signal);
				if (archiveIdentity(afterRead) !== identity) throw new Error("ASAR identity changed during header read");
				const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(json));
				if (!isRecord(parsed) || !isRecord(parsed.files)) throw new Error("ASAR header has no file tree");
				return {
					files: parsed.files,
					jsonBytes
				};
			});
			throwIfAborted(signal);
			headerCache.delete(archive);
			headerCache.set(archive, {
				identity,
				files: admitted.files,
				bytes: admitted.jsonBytes
			});
			const retainedBytes = () => [...headerCache.values()].reduce((sum, entry) => sum + entry.bytes, 0);
			while (headerCache.size > MAX_CACHED_HEADERS || retainedBytes() > 16777216) headerCache.delete(headerCache.keys().next().value ?? archive);
			return admitted.files;
		};
		isAsarRegularFile = (files, member) => {
			let node = { files };
			for (const part of member) {
				const children = isRecord(node) ? node.files : undefined;
				if (!isRecord(children) || !Object.hasOwn(children, part)) return false;
				node = children[part];
			}
			return isRecord(node) && typeof node.size === "number" && !("files" in node) && !("link" in node);
		};
		isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
		throwIfAborted = (signal) => {
			assertArtifactReadActive(signal);
		};
	})))();
}

//#endregion
export { retryElectronFileCleanup as i, init_ElectronFileScope as n, mapElectronFileAuthorizationFailure as r, authorizedElectronFile as t };