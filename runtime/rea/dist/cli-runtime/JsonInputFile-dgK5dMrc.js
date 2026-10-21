import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisInputError, AnalysisResourceConstraintError, freezeOwnedJsonSnapshotSteps, init_analysisErrorCore, init_immutableJson, init_jsonValue, jsonValueValidationSteps } from "./errorSchemas-BjJIu7zO.js";
import { err, init_result, init_safeJson, ok, safeParseJson } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { RegularFileChangedError, assertRegularFileActive, init_RegularFile } from "./ArtifactReader-CGZcqzzo.js";
import { RegularFileReadFailure, init_RegularFileRead, withRegularFile } from "./RegularFileRead-CQP0aNJS.js";
import { setImmediate } from "node:timers/promises";
import { createHash } from "node:crypto";
import { constants } from "node:buffer";
import { pipeline } from "node:stream/promises";
import { getHeapStatistics } from "node:v8";
import { asStream, none } from "stream-chain";
import fun from "stream-chain/fun.js";
import parser from "stream-json/parser.js";
import streamValues from "stream-json/streamers/stream-values.js";
import streamArray from "stream-json/streamers/stream-array.js";

//#region dist/application/OwnedJsonInput.js
var finish, sealOwnedJsonInput;
function init_OwnedJsonInput() {
	return (init_OwnedJsonInput = __esmMin((() => {
		init_analysisErrorCore();
		init_immutableJson();
		init_jsonValue();
		init_result();
		finish = async (steps, signal) => {
			let completed = false;
			try {
				for (;;) {
					signal?.throwIfAborted();
					const step = steps.next();
					if (step.done) {
						completed = true;
						return step.value;
					}
					await setImmediate(undefined, signal === undefined ? {} : { signal });
				}
			} finally {
				if (!completed) steps.return(undefined);
			}
		};
		sealOwnedJsonInput = async (value, operation, signal) => {
			const issue = await finish(jsonValueValidationSteps(value), signal);
			if (issue !== undefined) return err(new AnalysisInputError(operation, { userMessage: issue }, [{
				path: [],
				reason: "invalid_value",
				expected: "bounded JSON-safe input",
				message: issue
			}]));
			return ok(await finish(freezeOwnedJsonSnapshotSteps(value), signal));
		};
	})))();
}

//#endregion
//#region dist/application/Utf8JsonInput.js
var JSON_INPUT_RESOURCE_REMEDIATION, JSON_BYTE_ORDER_MARK_MESSAGE, parseUtf8Json;
function init_Utf8JsonInput() {
	return (init_Utf8JsonInput = __esmMin((() => {
		init_analysisErrorCore();
		init_safeJson();
		JSON_INPUT_RESOURCE_REMEDIATION = "Provide a smaller valid JSON value. For Evidence workflows, re-analyze a smaller selection of the original target and use its complete Evidence; splitting JSON text or trimming Evidence fields does not produce valid workflow input.";
		JSON_BYTE_ORDER_MARK_MESSAGE = "JSON input begins with a UTF-8 byte-order mark (EF BB BF), which strict JSON input does not accept. Save the file as UTF-8 without a byte-order mark.";
		parseUtf8Json = (bytes, operation, path, boundary = "json-input") => {
			const stringLimitFailure = (cause, decodedUnits) => new AnalysisResourceConstraintError(operation, "memory", "JSON input exceeds the runtime's maximum decoded string length", {
				boundary,
				input_path: path,
				input_bytes: bytes.byteLength,
				max_string_code_units: constants.MAX_STRING_LENGTH,
				...decodedUnits === undefined ? {} : { decoded_string_code_units_at_least: decodedUnits }
			}, {
				...cause === undefined ? {} : { cause },
				remediationAction: JSON_INPUT_RESOURCE_REMEDIATION
			});
			let text;
			try {
				const decoder = new TextDecoder("utf-8", {
					fatal: true,
					ignoreBOM: true
				});
				if (bytes.byteLength <= constants.MAX_STRING_LENGTH) {
					text = decoder.decode(bytes);
				} else {
					const parts = [];
					let decodedUnits = 0;
					const append = (part) => {
						decodedUnits += part.length;
						if (decodedUnits > constants.MAX_STRING_LENGTH) throw stringLimitFailure(undefined, decodedUnits);
						parts.push(part);
					};
					const chunkBytes = 1024 * 1024;
					for (let offset = 0; offset < bytes.byteLength; offset += chunkBytes) append(decoder.decode(bytes.subarray(offset, offset + chunkBytes), { stream: true }));
					append(decoder.decode());
					text = parts.join("");
				}
			} catch (cause) {
				if (cause instanceof AnalysisResourceConstraintError) throw cause;
				const code = typeof cause === "object" && cause !== null && "code" in cause ? cause.code : undefined;
				if (code === "ERR_STRING_TOO_LONG") throw stringLimitFailure(cause);
				if (code !== "ERR_ENCODING_INVALID_ENCODED_DATA") throw cause;
				return {
					ok: false,
					error: "JSON input is not valid UTF-8",
					cause
				};
			}
			if (text.startsWith("﻿")) return {
				ok: false,
				error: JSON_BYTE_ORDER_MARK_MESSAGE,
				cause: undefined
			};
			return safeParseJson(text);
		};
	})))();
}

//#endregion
//#region dist/application/JsonInputFile.js
async function* decodedChunks(handle, admittedBytes, path, signal, observe, physicalRead = {}) {
	const decoder = new TextDecoder("utf-8", {
		fatal: true,
		ignoreBOM: true
	});
	let leading = true;
	const checked = (text) => {
		if (leading && text.length > 0) {
			leading = false;
			if (text.startsWith("﻿")) throw new JsonByteOrderMarkError();
		}
		return text;
	};
	const bytes = Buffer.allocUnsafe(READ_CHUNK_BYTES);
	let observedBytes = 0;
	while (true) {
		assertRegularFileActive(signal);
		const read = await readPhysicalJsonInput(physicalRead, () => handle.read(bytes, 0, Math.min(bytes.length, admittedBytes - observedBytes + 1), observedBytes));
		assertRegularFileActive(signal);
		if (read.bytesRead === 0) break;
		observedBytes += read.bytesRead;
		if (observedBytes > admittedBytes) throw new RegularFileChangedError(path);
		const chunk = bytes.subarray(0, read.bytesRead);
		observe?.(chunk);
		yield checked(decoder.decode(chunk, { stream: true }));
	}
	if (observedBytes !== admittedBytes) throw new RegularFileChangedError(path);
	yield checked(decoder.decode());
}
var READ_CHUNK_BYTES, PACKED_TOKEN_PART_CODE_UNITS, NATIVE_PARSE_READ_BUDGET, JsonInputPhysicalReadFailure, JsonInputCancellationFailure, readPhysicalJsonInput, withJsonInputFile, withJsonInputPipeline, nativeJsonParseRequiredBytes, nativeParseFits, readJsonObjectFile, memberConsumer, readJsonInputFile, jsonReadFailure, packJsonScalars, admitJsonAssembly, requireStringAssemblyHeadroom, JsonByteOrderMarkError, readPrefix, readNativeJson, invalidJson;
function init_JsonInputFile() {
	return (init_JsonInputFile = __esmMin((() => {
		init_RegularFile();
		init_OwnedJsonInput();
		init_RegularFileRead();
		init_Utf8JsonInput();
		init_analysisErrorCore();
		init_result();
		READ_CHUNK_BYTES = 64 * 1024;
		PACKED_TOKEN_PART_CODE_UNITS = 64 * 1024;
		NATIVE_PARSE_READ_BUDGET = 8 * 1024 * 1024;
		JsonInputPhysicalReadFailure = class extends Error {
			_tag = "JsonInputPhysicalReadFailure";
			physicalCause;
			constructor(physicalCause) {
				super("JSON input descriptor read failed");
				this.physicalCause = physicalCause;
			}
		};
		JsonInputCancellationFailure = class extends Error {
			reason;
			_tag = "JsonInputCancellationFailure";
			constructor(reason) {
				super(reason instanceof Error ? reason.message : "JSON input read cancelled");
				this.reason = reason;
			}
		};
		readPhysicalJsonInput = async (observation, read) => {
			try {
				return await read();
			} catch (physicalCause) {
				const failure = new JsonInputPhysicalReadFailure(physicalCause);
				observation.failure = failure;
				throw failure;
			}
		};
		withJsonInputFile = (path, read, options) => withRegularFile(path, read, {
			...options,
			cancellationFailure: (reason) => new JsonInputCancellationFailure(reason)
		}).catch((cause) => {
			if (cause instanceof RegularFileReadFailure) throw cause.operationCause;
			throw cause;
		});
		withJsonInputPipeline = async (signal, run) => {
			if (signal === undefined) return run();
			const controller = new AbortController();
			const cancel = () => {
				controller.abort(new JsonInputCancellationFailure(signal.reason));
			};
			if (signal.aborted) cancel();
			else signal.addEventListener("abort", cancel, { once: true });
			try {
				return await run(controller.signal);
			} finally {
				signal.removeEventListener("abort", cancel);
			}
		};
		nativeJsonParseRequiredBytes = (inputBytes, snapshot = false) => (inputBytes * 72 + READ_CHUNK_BYTES) * (snapshot ? 2 : 1);
		nativeParseFits = (inputBytes, snapshot = false) => inputBytes <= NATIVE_PARSE_READ_BUDGET && nativeJsonParseRequiredBytes(inputBytes, snapshot) <= getHeapStatistics().total_available_size;
		readJsonObjectFile = (path, operation, scans, signal, resources) => withJsonInputFile(path, async (handle, stats) => {
			let previousDigest;
			const physicalRead = {};
			try {
				const native = await readNativeJson(handle, stats.size, path, operation, signal, false, physicalRead);
				if (native !== undefined) {
					if (!native.ok) return native;
					const value = native.value;
					if (typeof value !== "object" || value === null || Array.isArray(value)) return err(invalidJson(operation, "JSON document root must be an object"));
					for (const members of scans) for (const [key, member] of members) {
						if (!Object.hasOwn(value, key)) continue;
						assertRegularFileActive(signal);
						member.begin();
						const selected = Reflect.get(value, key);
						if (member.mode === "array" && !Array.isArray(selected)) {
							member.reject(new TypeError(`JSON member ${key} must be an array`));
							continue;
						}
						for (const item of member.mode === "array" && Array.isArray(selected) ? selected : [selected]) {
							assertRegularFileActive(signal);
							try {
								await member.accept(item);
							} catch (cause) {
								member.reject(cause);
							}
						}
					}
					return ok(undefined);
				}
				for (const members of scans) {
					const hash = createHash("sha256");
					let rootObject = false;
					let depth = 0;
					let key;
					let consume;
					await withJsonInputPipeline(signal, (pipelineSignal) => pipeline(decodedChunks(handle, stats.size, path, signal, (bytes) => {
						hash.update(bytes);
					}, physicalRead), asStream(fun(parser({
						jsonStreaming: false,
						streamValues: false,
						packKeys: false,
						packStrings: false,
						packNumbers: false
					}), packJsonScalars(operation, stats.size, path), (token) => {
						const opens = token.name === "startObject" || token.name === "startArray";
						const closes = token.name === "endObject" || token.name === "endArray";
						if (depth === 0) {
							rootObject = token.name === "startObject";
						} else if (rootObject && depth === 1 && token.name === "keyValue") {
							key = token.value;
						} else if (rootObject && depth === 1 && !closes) {
							const member = key === undefined ? undefined : members.get(key);
							consume = undefined;
							if (member !== undefined) {
								member.begin();
								if (member.mode === "array" && token.name !== "startArray") {
									member.reject(new TypeError(`JSON member ${key} must be an array`));
								} else {
									consume = memberConsumer(member, operation, stats.size, path);
								}
							}
							key = undefined;
						}
						const selected = consume;
						if (opens) depth += 1;
						if (closes) depth -= 1;
						if (rootObject && depth === 1 && token.name !== "keyValue") consume = undefined;
						if (selected === undefined) return none;
						return selected(token);
					})), pipelineSignal === undefined ? {} : { signal: pipelineSignal }));
					if (!rootObject) return err(invalidJson(operation, "JSON document root must be an object"));
					const digest = hash.digest("hex");
					if (previousDigest !== undefined && digest !== previousDigest) throw new RegularFileChangedError(path);
					previousDigest = digest;
				}
				return ok(undefined);
			} catch (cause) {
				if (physicalRead.failure !== undefined) throw physicalRead.failure;
				const failure = jsonReadFailure(cause, operation, stats.size, path);
				if (failure !== undefined) return err(failure);
				throw cause;
			}
		}, {
			signal,
			...resources === undefined ? {} : { resources }
		});
		memberConsumer = (member, operation, size, path) => {
			let admit = admitJsonAssembly(operation, size, path);
			const streamer = member.mode === "array" ? streamArray() : streamValues();
			const consume = fun((token) => admit(token), streamer, (row) => {
				if (typeof row !== "object" || row === null || !("value" in row)) throw new Error("Unexpected JSON member parser result");
				admit = admitJsonAssembly(operation, size, path);
				try {
					const accepted = member.accept(row.value);
					if (accepted instanceof Promise) return accepted.then(() => none, (cause) => {
						member.reject(cause);
						return none;
					});
				} catch (cause) {
					member.reject(cause);
				}
				return none;
			});
			return (token) => {
				const consumed = consume(token);
				return consumed instanceof Promise ? consumed.then(() => none) : none;
			};
		};
		readJsonInputFile = (path, operation, signal, resources, snapshot = false) => withJsonInputFile(path, async (handle, stats) => {
			let found = false;
			let value;
			const physicalRead = {};
			try {
				const native = await readNativeJson(handle, stats.size, path, operation, signal, snapshot, physicalRead);
				if (native !== undefined) return native.ok && snapshot ? await sealOwnedJsonInput(native.value, operation, signal) : native;
				await withJsonInputPipeline(signal, (pipelineSignal) => pipeline(decodedChunks(handle, stats.size, path, signal, undefined, physicalRead), asStream(fun(parser({
					jsonStreaming: false,
					streamValues: false,
					packKeys: false,
					packStrings: false,
					packNumbers: false
				}), packJsonScalars(operation, stats.size, path), admitJsonAssembly(operation, stats.size, path, snapshot ? 2 : 1), streamValues(), (row) => {
					if (found || typeof row !== "object" || row === null || !("key" in row) || row.key !== 0 || !("value" in row)) throw new Error("Unexpected JSON parser result");
					found = true;
					value = row.value;
					return none;
				})), pipelineSignal === undefined ? {} : { signal: pipelineSignal }));
				return found ? snapshot ? await sealOwnedJsonInput(value, operation, signal) : ok(value) : err(invalidJson(operation, "JSON document is empty"));
			} catch (cause) {
				if (physicalRead.failure !== undefined) throw physicalRead.failure;
				const failure = jsonReadFailure(cause, operation, stats.size, path);
				if (failure !== undefined) return err(failure);
				throw cause;
			}
		}, {
			signal,
			...resources === undefined ? {} : { resources }
		});
		jsonReadFailure = (cause, operation, size, path) => {
			if (cause instanceof AnalysisResourceConstraintError) return cause;
			if (cause instanceof TypeError && "code" in cause && cause.code === "ERR_ENCODING_INVALID_ENCODED_DATA") return invalidJson(operation, "JSON input is not valid UTF-8", cause);
			if (cause instanceof SyntaxError || cause instanceof Error && cause.message.startsWith("Parser ")) return invalidJson(operation, cause.message, cause);
			if (cause instanceof Error && (cause instanceof RangeError && cause.message === "Invalid string length" || "code" in cause && cause.code === "ERR_STRING_TOO_LONG")) return new AnalysisResourceConstraintError(operation, "memory", "An individual JSON string or number token exceeds the runtime string limit", {
				input_path: path,
				input_file_bytes: size,
				max_string_code_units: constants.MAX_STRING_LENGTH
			}, {
				cause,
				remediationAction: JSON_INPUT_RESOURCE_REMEDIATION
			});
			return undefined;
		};
		packJsonScalars = (operation, inputFileBytes, path) => {
			let kind;
			let length = 0;
			let value = "";
			let parts = [];
			let partLength = 0;
			return (token) => {
				if (typeof token !== "object" || token === null || !("name" in token)) throw new Error("Unexpected JSON parser token");
				switch (token.name) {
					case "startKey":
					case "startString":
						kind = token.name === "startKey" ? "keyValue" : "stringValue";
						break;
					case "startNumber":
						kind = "numberValue";
						break;
					case "numberChunk":
					case "stringChunk":
						if (kind === undefined || !("value" in token) || typeof token.value !== "string") throw new Error("Unexpected JSON scalar fragment");
						length += token.value.length;
						if (length > constants.MAX_STRING_LENGTH) throw new RangeError("Invalid string length");
						parts.push(token.value);
						partLength += token.value.length;
						if (partLength >= PACKED_TOKEN_PART_CODE_UNITS) {
							requireStringAssemblyHeadroom(operation, inputFileBytes, path, length);
							value += parts.join("");
							parts = [];
							partLength = 0;
						}
						break;
					case "endKey":
					case "endString":
					case "endNumber": {
						if (kind === undefined) throw new Error("Unexpected JSON scalar end");
						requireStringAssemblyHeadroom(operation, inputFileBytes, path, length);
						const packed = {
							name: kind,
							value: value + parts.join("")
						};
						kind = undefined;
						length = 0;
						value = "";
						parts = [];
						partLength = 0;
						return packed;
					}
					default: return token;
				}
				return none;
			};
		};
		admitJsonAssembly = (operation, inputFileBytes, path, retainedMultiplier = 1) => {
			let projectedBytes = 0;
			let nextCheck = 0;
			return (token) => {
				if (typeof token !== "object" || token === null || !("name" in token)) throw new Error("Unexpected JSON assembly token");
				if (token.name === "startObject" || token.name === "startArray") {
					projectedBytes += 128;
				} else if (token.name === "keyValue" || token.name === "stringValue") {
					if (!("value" in token) || typeof token.value !== "string") throw new Error("Unexpected packed JSON string");
					projectedBytes += 64 + token.value.length * 2;
				} else if (token.name === "numberValue" || token.name === "nullValue" || token.name === "trueValue" || token.name === "falseValue") {
					projectedBytes += 64;
				}
				if (projectedBytes >= nextCheck) {
					const heap = getHeapStatistics();
					const requiredBytes = projectedBytes * retainedMultiplier + READ_CHUNK_BYTES;
					if (requiredBytes > heap.total_available_size) throw new AnalysisResourceConstraintError(operation, "memory", "Insufficient heap headroom to materialize the complete JSON value", {
						input_path: path,
						input_file_bytes: inputFileBytes,
						projected_value_bytes: projectedBytes,
						assembly_headroom_bytes: requiredBytes,
						available_heap_bytes: heap.total_available_size,
						heap_size_limit_bytes: heap.heap_size_limit
					}, { remediationAction: JSON_INPUT_RESOURCE_REMEDIATION });
					nextCheck = projectedBytes + READ_CHUNK_BYTES;
				}
				return token;
			};
		};
		requireStringAssemblyHeadroom = (operation, inputFileBytes, path, stringCodeUnits) => {
			if (stringCodeUnits < PACKED_TOKEN_PART_CODE_UNITS) return;
			const heap = getHeapStatistics();
			const requiredBytes = 2 * (stringCodeUnits + PACKED_TOKEN_PART_CODE_UNITS);
			if (requiredBytes > heap.total_available_size) throw new AnalysisResourceConstraintError(operation, "memory", "Insufficient heap headroom to assemble a complete JSON string", {
				input_path: path,
				input_file_bytes: inputFileBytes,
				string_code_units: stringCodeUnits,
				string_assembly_headroom_bytes: requiredBytes,
				available_heap_bytes: heap.total_available_size,
				heap_size_limit_bytes: heap.heap_size_limit
			}, { remediationAction: JSON_INPUT_RESOURCE_REMEDIATION });
		};
		JsonByteOrderMarkError = class extends SyntaxError {
			constructor() {
				super(JSON_BYTE_ORDER_MARK_MESSAGE);
			}
		};
		readPrefix = async (handle, size, signal, physicalRead) => {
			const bytes = Buffer.allocUnsafe(size);
			let offset = 0;
			while (offset < bytes.length) {
				assertRegularFileActive(signal);
				const read = await readPhysicalJsonInput(physicalRead, () => handle.read(bytes, offset, bytes.length - offset, null));
				assertRegularFileActive(signal);
				if (read.bytesRead === 0) return {
					bytes: bytes.subarray(0, offset),
					complete: true
				};
				offset += read.bytesRead;
			}
			return {
				bytes,
				complete: false
			};
		};
		readNativeJson = async (handle, size, path, operation, signal, snapshot = false, physicalRead = {}) => {
			if (!nativeParseFits(size, snapshot)) return undefined;
			const prefix = await readPrefix(handle, size + 1, signal, physicalRead);
			if (!prefix.complete || prefix.bytes.length !== size) throw new RegularFileChangedError(path);
			const parsed = parseUtf8Json(prefix.bytes, operation, path, "json-file-input");
			return parsed.ok ? ok(parsed.value) : err(invalidJson(operation, parsed.error, parsed.cause));
		};
		invalidJson = (operation, message, cause) => new AnalysisInputError(operation, cause === undefined ? undefined : { cause }, [{
			path: [],
			reason: "invalid_format",
			expected: "JSON",
			message
		}]);
	})))();
}

//#endregion
export { JSON_INPUT_RESOURCE_REMEDIATION, JsonInputCancellationFailure, JsonInputPhysicalReadFailure, init_JsonInputFile, init_OwnedJsonInput, init_Utf8JsonInput, nativeJsonParseRequiredBytes, parseUtf8Json, readJsonInputFile, readJsonObjectFile, sealOwnedJsonInput };