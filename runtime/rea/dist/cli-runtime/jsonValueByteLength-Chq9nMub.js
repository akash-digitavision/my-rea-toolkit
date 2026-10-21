import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { ArtifactReaderFailure, OwnedFileHandle, RegularFileCancelled, RegularFileCleanupFailure, RegularFileOperationCancelled, init_ArtifactReader, init_OwnedFileHandle, init_OwnedRegularFile, init_RegularFile, sameArtifactSourceIdentity, withOwnedFileHandle } from "./ArtifactReader-CGZcqzzo.js";
import { AnalysisCleanupLease, init_AnalysisCleanupLease } from "./AnalysisCleanupLease-CWfTGYKd.js";
import { ArtifactFileCancelled, ArtifactFileCleanupFailure, init_ArtifactFileOperation } from "./ArtifactFileOperation-ynaKMviK.js";
import { OwnedDirectoryHandle, init_OwnedDirectoryHandle } from "./OwnedDirectoryHandle-Cq1F1Ded.js";
import { init_readArtifactFileChunks, readArtifactFileChunks } from "./readArtifactFileChunks-BAi2w2R8.js";
import { init_StreamBytes, streamChunkToBuffer } from "./ArtifactPaths-CJ5y197z.js";
import { createAsarHeaderSignatureProbe, init_AsarHeader } from "./AsarHeader-BPMcFWQV.js";
import { MAX_XML_PLIST_PROBE_BYTES, createXmlPlistSignatureProbe, init_appleArchiveFormat } from "./appleArchiveFormat-B-JoSBSY.js";
import { init_machoContainer, readFatContainerHeader, readFatContainerTable, readMachoHeaderPrefixFacts } from "./machoContainer-m8c6KOuY.js";
import { init_jsonStringByteLength, jsonStringByteLength } from "./jsonStringByteLength-BNWQbts4.js";
import { createHash } from "node:crypto";
import { extname, isAbsolute, join, relative, sep } from "node:path";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { constants } from "node:fs";
import { Readable } from "node:stream";

//#region dist/artifacts/hostExecutableMarking.js
var windowsLaunchableExtensions, hostExecutableMarking;
function init_hostExecutableMarking() {
	return (init_hostExecutableMarking = __esmMin((() => {
		windowsLaunchableExtensions = new Set([
			".bat",
			".cmd",
			".com",
			".exe"
		]);
		hostExecutableMarking = (path, metadata, platform = process.platform) => platform === "win32" ? metadata.isFile() && windowsLaunchableExtensions.has(extname(path).toLowerCase()) : typeof metadata.mode === "bigint" ? (metadata.mode & 73n) !== 0n : (metadata.mode & 73) !== 0;
	})))();
}

//#endregion
//#region dist/artifacts/DirectoryArtifactReader.js
var DirectoryArtifactTraversalLimit, DirectoryArtifactRootFailure, DirectoryArtifactReader, unsupportedEntryKind, artifactEntry, safeArtifactSize, directoryIoFailure, failureMessage, mapStableFileRead, withDirectoryIoContext, abortIfNeeded$1, assertContainedDirectory;
function init_DirectoryArtifactReader() {
	return (init_DirectoryArtifactReader = __esmMin((() => {
		init_ArtifactReader();
		init_hostExecutableMarking();
		init_OwnedDirectoryHandle();
		init_OwnedFileHandle();
		init_readArtifactFileChunks();
		init_OwnedRegularFile();
		init_RegularFile();
		init_ArtifactFileOperation();
		init_AnalysisCleanupLease();
		DirectoryArtifactTraversalLimit = class extends ArtifactReaderFailure {
			examinedEntries;
			maximumEntries;
			constructor(examinedEntries, maximumEntries) {
				super("limit", "Directory traversal reached its examined-entry budget", { boundary: "capacity" });
				this.examinedEntries = examinedEntries;
				this.maximumEntries = maximumEntries;
			}
		};
		DirectoryArtifactRootFailure = class extends ArtifactReaderFailure {};
		DirectoryArtifactReader = class {
			format = "directory";
			#rootPromise;
			#rootPath;
			#directories = new Set();
			#files = new Map();
			#fileCleanup = new WeakMap();
			constructor(root) {
				this.#rootPath = root;
			}
			/** Enumerate entries, optionally restricting descent while retaining directories. */
			async *entries(signal, selection) {
				const admittedRoot = await this.#resolveRoot();
				const root = admittedRoot.canonicalPath;
				const options = typeof selection === "function" ? { descendInto: selection } : selection;
				const maximum = options?.maximumEntries;
				if (maximum !== undefined && (!Number.isSafeInteger(maximum) || maximum < 0)) throw new RangeError("Directory traversal maximumEntries must be a nonnegative safe integer");
				let examined = 0;
				const examine = () => {
					if (maximum !== undefined && examined >= maximum) throw new DirectoryArtifactTraversalLimit(examined, maximum);
					examined += 1;
				};
				const pending = [root];
				while (pending.length > 0) {
					abortIfNeeded$1(signal);
					const directory = pending.pop();
					if (directory === undefined) break;
					await withDirectoryIoContext("inspect directory", directory, () => assertContainedDirectory(root, directory, admittedRoot.identity));
					for await (const entry of this.#readDirectory(directory, pending, signal, options, examine)) yield entry;
					await withDirectoryIoContext("inspect directory", directory, () => assertContainedDirectory(root, directory, admittedRoot.identity));
				}
			}
			/** Admission facts, shared with traversal; the selected root may be a symlink. */
			rootObservation() {
				return this.#resolveRoot();
			}
			async #resolveRoot() {
				return this.#rootPromise ??= (async () => {
					const root = await realpath(this.#rootPath);
					const metadata = await lstat(root, { bigint: true });
					if (metadata.isSymbolicLink()) throw new ArtifactReaderFailure("path", "Artifact root changed during traversal");
					if (!metadata.isDirectory()) throw new DirectoryArtifactRootFailure("path", "Artifact root must be a directory");
					return Object.freeze({
						canonicalPath: root,
						identity: Object.freeze({
							dev: metadata.dev,
							ino: metadata.ino
						})
					});
				})().catch((cause) => {
					if (cause instanceof ArtifactReaderFailure) throw cause;
					throw directoryIoFailure("resolve artifact root", this.#rootPath, cause, DirectoryArtifactRootFailure);
				});
			}
			async *#readDirectory(directory, pending, signal, options, examine) {
				const admittedRoot = await this.#resolveRoot();
				const root = admittedRoot.canonicalPath;
				const handle = new OwnedDirectoryHandle(await opendir(directory).catch((cause) => {
					throw directoryIoFailure("open directory", directory, cause, directory === root ? DirectoryArtifactRootFailure : ArtifactReaderFailure);
				}));
				this.#directories.add(handle);
				const childDirectories = [];
				let traversal = { kind: "complete" };
				try {
					for (;;) {
						await withDirectoryIoContext("inspect directory", directory, () => assertContainedDirectory(root, directory, admittedRoot.identity));
						const child = await handle.handle.read();
						if (child === null) break;
						examine();
						abortIfNeeded$1(signal);
						const absolute = join(directory, child.name);
						const metadata = await lstat(absolute, { bigint: true }).catch((cause) => {
							throw directoryIoFailure("inspect entry", absolute, cause);
						});
						const path = relative(root, absolute).split(sep).join("/");
						const entry = artifactEntry(path, absolute, metadata);
						if (entry === undefined) {
							options?.onOmission?.({
								path,
								kind: unsupportedEntryKind(metadata)
							});
							continue;
						}
						yield entry;
						if (entry.kind === "directory") {
							if (options?.descendInto?.(path) ?? true) childDirectories.push(absolute);
							else options?.onOmission?.({
								path,
								kind: "directory-descendants"
							});
						}
					}
				} catch (cause) {
					traversal = {
						kind: "failed",
						cause: cause instanceof ArtifactReaderFailure ? cause : directoryIoFailure("read directory", directory, cause)
					};
				} finally {
					await this.#finishDirectory(handle, directory, traversal);
				}
				if (traversal.kind === "failed") throw traversal.cause;
				childDirectories.reverse();
				pending.push(...childDirectories);
			}
			async #finishDirectory(handle, path, traversal) {
				try {
					await handle.close();
					this.#directories.delete(handle);
				} catch (cause) {
					const closeFailure = directoryIoFailure("close directory", path, cause);
					if (traversal.kind === "failed") throw ArtifactReaderFailure.withCleanup(traversal.cause, ArtifactReaderFailure.cleanupObservation(closeFailure, path));
					throw closeFailure;
				}
			}
			async #openFile(entry, signal) {
				abortIfNeeded$1(signal);
				if (entry.kind !== "file") throw new ArtifactReaderFailure("format", "Only regular files can be opened");
				const fileHandle = await open(entry.adapterKey, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK).catch((cause) => {
					throw directoryIoFailure("open entry", entry.adapterKey, cause);
				});
				const owner = new OwnedFileHandle(fileHandle);
				this.#files.set(owner, entry.adapterKey);
				try {
					const observed = await owner.handle.stat({ bigint: true }).catch((cause) => {
						throw directoryIoFailure("inspect opened entry", entry.adapterKey, cause);
					});
					if (!observed.isFile() || !sameArtifactSourceIdentity(entry.sourceIdentity, observed)) {
						throw new ArtifactReaderFailure("integrity", `Directory entry changed before open: ${entry.path}`);
					}
					abortIfNeeded$1(signal);
					return owner;
				} catch (cause) {
					try {
						await this.#closeFile(owner);
					} catch (closeCause) {
						throw ArtifactReaderFailure.withCleanup(cause, ArtifactReaderFailure.cleanupObservation(directoryIoFailure("close opened entry", entry.adapterKey, closeCause), entry.adapterKey));
					}
					throw cause;
				}
			}
			/** Borrow an admitted entry for bounded random reads; retain failed cleanup. */
			async inspectFile(entry, inspect, signal) {
				const owner = await this.#openFile(entry, signal);
				try {
					const value = await withOwnedFileHandle(entry.adapterKey, owner, signal === undefined ? {} : { signal }, async (file) => {
						let outcome;
						try {
							outcome = {
								kind: "completed",
								value: await inspect(file)
							};
						} catch (cause) {
							outcome = {
								kind: "failed",
								cause
							};
						}
						const [opened, named] = await Promise.all([file.stat({ bigint: true }), lstat(entry.adapterKey, { bigint: true })]);
						abortIfNeeded$1(signal);
						if (!opened.isFile() || !named.isFile() || !sameArtifactSourceIdentity(entry.sourceIdentity, opened) || !sameArtifactSourceIdentity(entry.sourceIdentity, named)) throw new ArtifactReaderFailure("integrity", `Directory entry changed during inspection: ${entry.path}`);
						if (outcome.kind === "failed") throw outcome.cause;
						return outcome.value;
					});
					this.#files.delete(owner);
					return value;
				} catch (cause) {
					if (cause instanceof RegularFileCleanupFailure) {
						const lease = new AnalysisCleanupLease(() => this.#closeFile(owner), [entry.adapterKey]);
						this.#fileCleanup.set(owner, lease);
						throw new ArtifactFileCleanupFailure(cause, lease);
					}
					this.#files.delete(owner);
					if (cause instanceof RegularFileCancelled) throw new ArtifactFileCancelled(cause);
					if (cause instanceof RegularFileOperationCancelled) throw new ArtifactReaderFailure("cancelled", "Directory inspection cancelled", { cause: cause.reason });
					throw directoryIoFailure("inspect entry", entry.adapterKey, cause);
				}
			}
			async open(entry, signal) {
				const owner = await this.#openFile(entry, signal);
				const source = Readable.from(mapStableFileRead(owner.handle, entry, signal), { objectMode: false });
				source.once("close", () => {
					void this.#closeFile(owner).catch(() => undefined);
				});
				return source;
			}
			async close() {
				const failures = [];
				for (const [owner, path] of this.#files) {
					try {
						const lease = this.#fileCleanup.get(owner);
						if (lease === undefined) await this.#closeFile(owner);
						else await lease.release();
					} catch (cause) {
						failures.push(directoryIoFailure("close opened entry", path, cause));
					}
				}
				for (const owner of this.#directories) {
					try {
						await owner.close();
						this.#directories.delete(owner);
					} catch (cause) {
						failures.push(directoryIoFailure("close directory", owner.handle.path, cause));
					}
				}
				if (failures.length > 0) {
					const reason = failures.map(failureMessage).join("; ");
					throw new ArtifactReaderFailure("io", `Directory artifact cleanup failed: ${reason}`, {
						cause: new AggregateError(failures),
						cleanup: {
							reason,
							resources: [...this.#files.values(), ...[...this.#directories].map((owner) => owner.handle.path)]
						}
					});
				}
			}
			async #closeFile(owner) {
				await owner.close();
				this.#files.delete(owner);
				this.#fileCleanup.delete(owner);
			}
			provenance() {
				return [];
			}
		};
		unsupportedEntryKind = (metadata) => metadata.isFIFO() ? "fifo" : metadata.isSocket() ? "socket" : metadata.isBlockDevice() ? "block-device" : metadata.isCharacterDevice() ? "character-device" : "unsupported";
		artifactEntry = (path, absolute, metadata) => {
			const kind = metadata.isSymbolicLink() ? "symlink" : metadata.isDirectory() ? "directory" : metadata.isFile() ? "file" : undefined;
			if (kind === undefined) return undefined;
			return {
				path,
				kind,
				declaredSize: kind === "file" ? safeArtifactSize(metadata.size) : null,
				compressedSize: null,
				executable: hostExecutableMarking(absolute, metadata),
				encrypted: false,
				byteOffset: null,
				declaredIntegrity: null,
				unpacked: false,
				limitations: kind === "symlink" ? ["Symlink target was not followed or disclosed."] : [],
				adapterKey: absolute,
				...kind === "file" ? { sourceIdentity: {
					device: metadata.dev,
					inode: metadata.ino,
					size: metadata.size,
					mode: metadata.mode,
					mtimeNs: metadata.mtimeNs,
					ctimeNs: metadata.ctimeNs
				} } : {}
			};
		};
		safeArtifactSize = (size) => {
			if (size < 0n || size > BigInt(Number.MAX_SAFE_INTEGER)) return null;
			return Number(size);
		};
		directoryIoFailure = (operation, path, cause, Failure = ArtifactReaderFailure) => {
			if (cause instanceof ArtifactReaderFailure) return cause;
			const code = typeof cause === "object" && cause !== null && "code" in cause && typeof cause.code === "string" ? ` (${cause.code})` : "";
			const detail = failureMessage(cause);
			return new Failure("io", `Could not ${operation} at ${path}${code}: ${detail}`, { cause });
		};
		failureMessage = (cause) => cause instanceof Error ? cause.message : String(cause);
		mapStableFileRead = async function* (handle, entry, signal) {
			let bytes = 0n;
			try {
				const expectedBytes = entry.sourceIdentity?.size;
				if (expectedBytes === undefined) throw new ArtifactReaderFailure("integrity", `Directory entry has no captured file state: ${entry.path}`);
				for await (const chunk of readArtifactFileChunks(handle, {
					end: expectedBytes,
					signal
				})) {
					abortIfNeeded$1(signal);
					bytes += BigInt(chunk.length);
					yield chunk;
				}
				abortIfNeeded$1(signal);
				const [opened, current] = await Promise.all([handle.stat({ bigint: true }), lstat(entry.adapterKey, { bigint: true })]);
				abortIfNeeded$1(signal);
				if (!opened.isFile() || !current.isFile() || !sameArtifactSourceIdentity(entry.sourceIdentity, opened) || !sameArtifactSourceIdentity(entry.sourceIdentity, current) || bytes !== expectedBytes) throw new ArtifactReaderFailure("integrity", `Directory entry changed during read: ${entry.path}`);
			} catch (cause) {
				if (cause instanceof Error && "code" in cause && [
					"ENOENT",
					"ENOTDIR",
					"ELOOP"
				].includes(String(cause.code))) throw new ArtifactReaderFailure("integrity", `Directory entry changed during read: ${entry.path}`, { cause });
				if (!(cause instanceof ArtifactReaderFailure)) throw directoryIoFailure("validate read entry", entry.adapterKey, cause);
				throw cause;
			}
		};
		withDirectoryIoContext = async (operation, path, action) => {
			try {
				return await action();
			} catch (cause) {
				throw directoryIoFailure(operation, path, cause);
			}
		};
		abortIfNeeded$1 = (signal) => {
			if (signal?.aborted === true) throw new ArtifactReaderFailure("cancelled", "Artifact traversal cancelled", { cause: signal.reason });
		};
		assertContainedDirectory = async (root, directory, rootIdentity) => {
			const canonical = await realpath(directory);
			const fromRoot = relative(root, canonical);
			const metadata = await lstat(directory);
			const currentRoot = await lstat(root, { bigint: true });
			if (rootIdentity === undefined || currentRoot.dev !== rootIdentity.dev || currentRoot.ino !== rootIdentity.ino || metadata.isSymbolicLink() || !metadata.isDirectory() || fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) throw new ArtifactReaderFailure("path", "Directory traversal escaped or changed its artifact root");
		};
	})))();
}

//#endregion
//#region dist/artifacts/ArtifactClassificationProbe.js
var ARTIFACT_CLASSIFICATION_PREFIX_BYTES, observeFatSliceHeaders, finishClassificationEvidence, createArtifactClassificationProbe;
function init_ArtifactClassificationProbe() {
	return (init_ArtifactClassificationProbe = __esmMin((() => {
		init_AsarHeader();
		init_appleArchiveFormat();
		init_machoContainer();
		ARTIFACT_CLASSIFICATION_PREFIX_BYTES = 8192;
		observeFatSliceHeaders = (input) => {
			const { table, observedHeaders, partialHeaders, streamOffset, bytes } = input;
			if (table?.state !== "parsed") return;
			for (const slice of table.slices) {
				if (observedHeaders.has(slice.offset) && !partialHeaders.has(slice.offset)) continue;
				const headerLength = Math.min(12, slice.size);
				const headerEnd = slice.offset + headerLength;
				if (!Number.isSafeInteger(headerEnd)) continue;
				const start = Math.max(slice.offset, streamOffset);
				const end = Math.min(headerEnd, streamOffset + bytes.length);
				if (start >= end) continue;
				let pending = partialHeaders.get(slice.offset);
				if (pending === undefined) {
					pending = {
						bytes: Buffer.alloc(12),
						count: 0
					};
					partialHeaders.set(slice.offset, pending);
				}
				Buffer.from(bytes.subarray(start - streamOffset, end - streamOffset)).copy(pending.bytes, start - slice.offset);
				pending.count += end - start;
				observedHeaders.set(slice.offset, readMachoHeaderPrefixFacts(pending.bytes.subarray(0, Math.min(pending.count, headerLength))));
				if (pending.count === headerLength) {
					partialHeaders.delete(slice.offset);
				}
			}
		};
		finishClassificationEvidence = (prefix, archiveBytes, finishAsar, sliceHeadersByOffset) => {
			const finalHeader = readFatContainerHeader(prefix, archiveBytes);
			if (finalHeader.state === "parsed") {
				for (let index = 0; index < finalHeader.slices.length; index += 1) {
					const slice = finalHeader.slices[index];
					if (slice === undefined || sliceHeadersByOffset.has(slice.offset)) continue;
					const available = Math.max(0, Math.min(slice.size, prefix.length - slice.offset));
					if (available === 0) continue;
					sliceHeadersByOffset.set(slice.offset, readMachoHeaderPrefixFacts(prefix.subarray(slice.offset, slice.offset + available)));
				}
			}
			const fatSliceHeaders = finalHeader.state === "parsed" ? {
				header: finalHeader,
				sliceHeadersByOffset
			} : undefined;
			return {
				prefix,
				asarHeader: finishAsar(archiveBytes),
				...fatSliceHeaders === undefined ? {} : { fatSliceHeaders }
			};
		};
		createArtifactClassificationProbe = () => {
			const xml = createXmlPlistSignatureProbe();
			const asar = createAsarHeaderSignatureProbe();
			const blocks = [];
			let retainedBytes = 0;
			let observedBytes = 0;
			let fatTable;
			const fatSliceHeadersByOffset = new Map();
			const partialFatHeaders = new Map();
			const retain = (bytes) => {
				let offset = 0;
				while (offset < bytes.length) {
					const blockOffset = retainedBytes % ARTIFACT_CLASSIFICATION_PREFIX_BYTES;
					if (blockOffset === 0) blocks.push(Buffer.allocUnsafe(ARTIFACT_CLASSIFICATION_PREFIX_BYTES));
					const count = Math.min(ARTIFACT_CLASSIFICATION_PREFIX_BYTES - blockOffset, bytes.length - offset);
					blocks[blocks.length - 1].set(bytes.subarray(offset, offset + count), blockOffset);
					retainedBytes += count;
					offset += count;
				}
			};
			const retainedPrefix = () => {
				const prefix = Buffer.allocUnsafe(retainedBytes);
				let copied = 0;
				for (const block of blocks) {
					const count = Math.min(block.length, retainedBytes - copied);
					prefix.set(block.subarray(0, count), copied);
					copied += count;
				}
				return prefix;
			};
			return {
				get length() {
					return observedBytes;
				},
				get limit() {
					if (observedBytes < 8192) return ARTIFACT_CLASSIFICATION_PREFIX_BYTES;
					return Math.max(ARTIFACT_CLASSIFICATION_PREFIX_BYTES, xml.state === "pending" ? MAX_XML_PLIST_PROBE_BYTES : 0, asar.observation.state === "pending" ? asar.limit : 0);
				},
				write(bytes) {
					const streamOffset = observedBytes;
					asar.write(bytes);
					let offset = 0;
					while (offset < bytes.length) {
						const limit = retainedBytes < 8192 ? ARTIFACT_CLASSIFICATION_PREFIX_BYTES : xml.state === "pending" ? MAX_XML_PLIST_PROBE_BYTES : retainedBytes;
						if (retainedBytes >= limit) break;
						const selected = bytes.subarray(offset, offset + Math.min(limit - retainedBytes, bytes.length - offset));
						retain(selected);
						xml.write(selected);
						offset += selected.length;
					}
					if ((fatTable === undefined || fatTable.state === "needs-data") && retainedBytes >= 8) fatTable = readFatContainerTable(retainedPrefix());
					observeFatSliceHeaders({
						table: fatTable,
						observedHeaders: fatSliceHeadersByOffset,
						partialHeaders: partialFatHeaders,
						streamOffset,
						bytes
					});
					observedBytes += bytes.length;
				},
				finish(archiveBytes) {
					return finishClassificationEvidence(retainedPrefix(), archiveBytes, (bytes) => asar.finish(bytes), fatSliceHeadersByOffset);
				}
			};
		};
	})))();
}

//#endregion
//#region dist/artifacts/ArtifactHash.js
var abortIfNeeded, hashReadable;
function init_ArtifactHash() {
	return (init_ArtifactHash = __esmMin((() => {
		init_ArtifactReader();
		init_StreamBytes();
		init_ArtifactClassificationProbe();
		abortIfNeeded = (signal) => {
			if (signal?.aborted === true) throw new ArtifactReaderFailure("cancelled", "Artifact inventory cancelled", { cause: signal.reason });
		};
		hashReadable = async (stream, signal, integrityAlgorithm) => {
			const hash = createHash("sha256");
			const md5 = integrityAlgorithm === "md5" ? createHash("md5") : undefined;
			const probe = createArtifactClassificationProbe();
			let bytes = 0;
			for await (const raw of stream) {
				abortIfNeeded(signal);
				const chunk = streamChunkToBuffer(raw);
				bytes += chunk.length;
				hash.update(chunk);
				md5?.update(chunk);
				probe.write(chunk);
			}
			abortIfNeeded(signal);
			return {
				sha256: hash.digest("hex"),
				...md5 === undefined ? {} : { md5: md5.digest("hex") },
				bytes,
				...probe.finish(bytes)
			};
		};
	})))();
}

//#endregion
//#region dist/domain/jsonValueByteLength.js
var jsonValueByteLength;
function init_jsonValueByteLength() {
	return (init_jsonValueByteLength = __esmMin((() => {
		init_jsonStringByteLength();
		jsonValueByteLength = (value, budget = Number.POSITIVE_INFINITY) => {
			if (typeof value === "string") return jsonStringByteLength(value, budget);
			if (Array.isArray(value)) {
				let bytes = 2 + Math.max(0, value.length - 1);
				for (const child of value) {
					if (bytes > budget) break;
					bytes += jsonValueByteLength(child, budget - bytes);
				}
				return bytes;
			}
			if (value !== null && typeof value === "object") {
				const keys = Object.keys(value);
				let bytes = 2 + Math.max(0, keys.length - 1);
				for (const key of keys) {
					if (bytes > budget) break;
					bytes += jsonStringByteLength(key, budget - bytes) + 1;
					if (bytes <= budget) bytes += jsonValueByteLength(value[key], budget - bytes);
				}
				return bytes;
			}
			return typeof value === "number" && !Number.isFinite(value) ? 4 : String(value).length;
		};
	})))();
}

//#endregion
export { DirectoryArtifactReader, DirectoryArtifactRootFailure, DirectoryArtifactTraversalLimit, abortIfNeeded, createArtifactClassificationProbe, hashReadable, hostExecutableMarking, init_ArtifactClassificationProbe, init_ArtifactHash, init_DirectoryArtifactReader, init_hostExecutableMarking, init_jsonValueByteLength, jsonValueByteLength };