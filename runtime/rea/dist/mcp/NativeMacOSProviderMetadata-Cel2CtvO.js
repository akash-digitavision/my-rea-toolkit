import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { d as RegularFileOperationCancelled, f as assertRegularFileActive, h as sameRegularFileState, i as init_OwnedRegularFile, n as RegularFileCancelled, p as init_RegularFile, r as RegularFileCleanupFailure, s as withOwnedRegularFile, u as RegularFileChangedError } from "./OwnedRegularFile--jcCKh4T.js";
import { Jt as createAnalysisProfile, Yt as init_analysisProfile } from "./nativeValueTrace-Cm--GSDT.js";
import { cn as init_nativeToolContracts, sn as NATIVE_TOOL_CONTRACTS } from "./toolContracts-BwSJfgou.js";
import { stat } from "node:fs/promises";
import { createHash } from "node:crypto";

//#region dist/filesystem/StableFileHash.js
async function readStableFile(path, options, includePrefix) {
	try {
		return await withOwnedRegularFile(path, options, async (handle) => {
			const initial = await handle.stat();
			if (!Number.isSafeInteger(initial.size) || initial.size < 0) throw new RangeError(`Regular file size cannot be represented safely: ${path}`);
			const hash = createHash("sha256");
			const chunk = Buffer.allocUnsafe(64 * 1024);
			const prefix = Buffer.alloc(includePrefix ? Math.min(STABLE_FILE_PREFIX_BYTES, initial.size) : 0);
			let position = 0;
			while (position <= initial.size) {
				assertRegularFileActive(options.signal);
				const length = Math.min(chunk.length, initial.size - position + 1);
				if (length <= 0) break;
				const read = await handle.read(chunk, 0, length, position);
				if (position + read.bytesRead > initial.size || read.bytesRead === 0 && position < initial.size) throw new RegularFileChangedError(path);
				assertRegularFileActive(options.signal);
				if (read.bytesRead === 0) break;
				if (position < prefix.length) {
					const prefixBytes = Math.min(read.bytesRead, prefix.length - position);
					chunk.copy(prefix, position, 0, prefixBytes);
				}
				hash.update(chunk.subarray(0, read.bytesRead));
				position += read.bytesRead;
			}
			assertRegularFileActive(options.signal);
			const [opened, currentPath] = await Promise.all([handle.stat(), stat(path)]);
			if (position !== initial.size || !sameRegularFileState(initial, opened) || !sameRegularFileState(initial, currentPath)) throw new RegularFileChangedError(path);
			assertRegularFileActive(options.signal);
			const fingerprint = {
				sha256: hash.digest("hex"),
				bytes: position
			};
			return includePrefix ? {
				...fingerprint,
				prefix
			} : fingerprint;
		});
	} catch (cause) {
		if (cause instanceof RegularFileCleanupFailure || cause instanceof RegularFileCancelled || cause instanceof RegularFileOperationCancelled) throw cause;
		throw new StableFileHashFailure(path, cause);
	}
}
var STABLE_FILE_PREFIX_BYTES, StableFileHashFailure, stableFileHashCause, hashStableFile, observeStableFile;
function init_StableFileHash() {
	return (init_StableFileHash = __esmMin((() => {
		init_OwnedRegularFile();
		init_RegularFile();
		STABLE_FILE_PREFIX_BYTES = 2;
		StableFileHashFailure = class extends Error {
			path;
			cause;
			_tag = "StableFileHashFailure";
			constructor(path, cause) {
				super(`Could not hash ${path}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
				this.path = path;
				this.cause = cause;
				this.name = this._tag;
			}
		};
		stableFileHashCause = (cause) => cause instanceof StableFileHashFailure ? cause.cause : cause;
		hashStableFile = async (path, options) => {
			return await readStableFile(path, options, false);
		};
		observeStableFile = (path, options) => readStableFile(path, options, true);
	})))();
}

//#endregion
//#region dist/native/NativeMacOSProviderMetadata.js
var NATIVE_MACOS_PROVIDER_IDENTITY, APPLE_DISPATCH_METADATA_ANALYSIS_PROFILE, OWNED_PROCESS_OPERATIONS, nativeMacOSCapabilities;
function init_NativeMacOSProviderMetadata() {
	return (init_NativeMacOSProviderMetadata = __esmMin((() => {
		init_analysisProfile();
		init_nativeToolContracts();
		NATIVE_MACOS_PROVIDER_IDENTITY = Object.freeze({
			id: "native-macos",
			name: "macOS native inspection utilities",
			version: null
		});
		APPLE_DISPATCH_METADATA_ANALYSIS_PROFILE = createAnalysisProfile({
			id: NATIVE_MACOS_PROVIDER_IDENTITY.id,
			name: NATIVE_MACOS_PROVIDER_IDENTITY.name,
			version: "apple-metadata-reader-1"
		}, {
			operation: "inspect_native_dispatch_metadata",
			reader: "apple-dispatch-metadata",
			revision: 1
		});
		OWNED_PROCESS_OPERATIONS = new Set(["capture_native_ui_scenario", "observe_native_calls"]);
		nativeMacOSCapabilities = (platform = process.platform) => {
			const available = platform === "darwin";
			return Object.freeze([...NATIVE_TOOL_CONTRACTS, { name: "inspect_native_dispatch_metadata" }].map((contract) => {
				const availability = available ? {
					available: true,
					reason: null
				} : {
					available: false,
					availabilityCode: "unsupported_host",
					reason: "Native macOS utilities require macOS."
				};
				return Object.freeze({
					provider: NATIVE_MACOS_PROVIDER_IDENTITY,
					operation: contract.name,
					...contract.name === "inspect_native_dispatch_metadata" ? { analysisProfile: APPLE_DISPATCH_METADATA_ANALYSIS_PROFILE } : {},
					...availability,
					effects: Object.freeze({
						mutatesArtifact: false,
						launchesProcess: contract.name !== "inspect_native_dispatch_metadata",
						mayShowUi: OWNED_PROCESS_OPERATIONS.has(contract.name),
						mayAccessNetwork: OWNED_PROCESS_OPERATIONS.has(contract.name),
						mayWriteFilesystem: OWNED_PROCESS_OPERATIONS.has(contract.name) || contract.name === "observe_native_ui",
						changesPermissions: false,
						requiresRoot: false
					}),
					limitations: Object.freeze(["Availability and textual formats depend on the installed macOS/Xcode toolchain."])
				});
			}));
		};
	})))();
}

//#endregion
export { StableFileHashFailure as a, observeStableFile as c, nativeMacOSCapabilities as i, stableFileHashCause as l, NATIVE_MACOS_PROVIDER_IDENTITY as n, hashStableFile as o, init_NativeMacOSProviderMetadata as r, init_StableFileHash as s, APPLE_DISPATCH_METADATA_ANALYSIS_PROFILE as t };