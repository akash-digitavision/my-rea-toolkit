import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, o as ok } from "./analysisErrorBase-C1inc3JA.js";
import { a as nulFreeStringSchema, n as init_localPath } from "./localPath-BCKW5wEI.js";
import { n as init_canonicalDigest, t as digestCanonicalValue } from "./canonicalDigest-Bi_0_zGi.js";
import { a as jsonValueValidationIssue, c as freezeJsonSnapshot, d as init_immutableJson, f as isImmutableJsonSnapshot, i as jsonValueSchema, n as init_jsonValue, o as jsonValueValidationSteps, r as jsonObjectSchema, s as canBorrowParsedJsonSnapshot } from "./jsonValue-sVQvKuTs.js";
import { g as init_digests, h as digestSchema, v as prefixedDigestSchema } from "./providerOperationHealth-DN_9xJFQ.js";
import { n as compositeKey, r as init_unicodeCodePointOrder, t as compareUnicodeCodePoints } from "./unicodeCodePointOrder-BezCbTpg.js";
import { f as init_analysisErrorCore, s as AnalysisOutputError } from "./analysisErrorCore-BMJXbfFY.js";
import { basename } from "node:path";
import { z } from "zod";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

//#region dist/domain/binaryTargetTypes.js
var BINARY_ARCHITECTURES, RAW_ONLY_ARCHITECTURES, ELF_METADATA_ARCHITECTURES, isElfMetadataArchitecture, isMachOFormat;
function init_binaryTargetTypes() {
	return (init_binaryTargetTypes = __esmMin((() => {
		BINARY_ARCHITECTURES = [
			"x86",
			"x86_64",
			"arm",
			"arm64",
			"mips",
			"6502",
			"riscv",
			"powerpc",
			"m68k",
			"hexagon"
		];
		RAW_ONLY_ARCHITECTURES = ["6502", "m68k"];
		ELF_METADATA_ARCHITECTURES = [
			"mips",
			"riscv",
			"powerpc"
		];
		isElfMetadataArchitecture = (architecture) => ELF_METADATA_ARCHITECTURES.includes(architecture);
		isMachOFormat = (format) => format === "mach-o" || format === "mach-o-universal";
	})))();
}

//#endregion
//#region dist/domain/canonicalJsonDigestSteps.js
/** Hash owned, validated JSON in bounded steps without a document-sized string. */
function* canonicalJsonDigestSteps(value) {
	const hash = createHash("sha256");
	const ancestors = new Set();
	const stack = [{
		kind: "value",
		value
	}];
	const encodedKeys = new Map();
	let remainingKeyCodeUnits = 8192;
	let buffered = "";
	let flushed = false;
	const emit = (part) => {
		buffered += part;
		if (buffered.length >= 8192) {
			hash.update(buffered);
			buffered = "";
			flushed = true;
		}
	};
	try {
		while (stack.length > 0) {
			if (flushed) {
				flushed = false;
				yield;
			}
			const frame = stack.pop();
			if (frame === undefined) break;
			if (frame.kind === "separator") {
				emit(":");
				continue;
			}
			if (frame.kind === "string") {
				if (frame.index === frame.value.length) {
					emit("\"");
					continue;
				}
				let end = Math.min(frame.index + 8192, frame.value.length);
				const last = frame.value.charCodeAt(end - 1);
				const next = frame.value.charCodeAt(end);
				if (end < frame.value.length && last >= 55296 && last <= 56319 && next >= 56320 && next <= 57343) end -= 1;
				emit(JSON.stringify(frame.value.slice(frame.index, end)).slice(1, -1));
				frame.index = end;
				stack.push(frame);
				continue;
			}
			let item;
			if (frame.kind === "array") {
				if (frame.index === frame.length) {
					emit("]");
					ancestors.delete(frame.value);
					continue;
				}
				const element = frame.value[frame.index];
				if (element === undefined) throw new TypeError("Canonical JSON digest requires dense JSON arrays");
				if (frame.index++ > 0) emit(",");
				stack.push(frame);
				item = element;
			} else if (frame.kind === "object") {
				if (frame.index === frame.keys.length) {
					emit("}");
					ancestors.delete(frame.value);
					continue;
				}
				const key = frame.keys[frame.index++];
				if (key === undefined) throw new TypeError("Canonical JSON object changed during hashing");
				const property = frame.value[key];
				if (property === undefined) {
					stack.push(frame);
					continue;
				}
				if (frame.written++ > 0) emit(",");
				if (key.length > 8192) {
					emit("\"");
					stack.push(frame, {
						kind: "value",
						value: property
					}, { kind: "separator" }, {
						kind: "string",
						value: key,
						index: 0
					});
					continue;
				}
				let encodedKey = encodedKeys.get(key);
				if (encodedKey === undefined) {
					encodedKey = JSON.stringify(key);
					if (encodedKey.length <= remainingKeyCodeUnits) {
						encodedKeys.set(key, encodedKey);
						remainingKeyCodeUnits -= encodedKey.length;
					}
				}
				emit(encodedKey);
				emit(":");
				stack.push(frame);
				item = property;
			} else {
				item = frame.value;
			}
			if (flushed) {
				flushed = false;
				yield;
			}
			if (typeof item === "string" && item.length > 8192) {
				emit("\"");
				stack.push({
					kind: "string",
					value: item,
					index: 0
				});
			} else if (item === null || typeof item !== "object") {
				if (typeof item === "number" && !Number.isFinite(item)) throw new Error(Number.isNaN(item) ? "NaN is not allowed" : "Infinity is not allowed");
				emit(JSON.stringify(item));
			} else {
				if (ancestors.has(item)) throw new Error("Circular reference detected");
				ancestors.add(item);
				if (Array.isArray(item)) {
					emit("[");
					stack.push({
						kind: "array",
						value: item,
						length: item.length,
						index: 0
					});
				} else {
					emit("{");
					stack.push({
						kind: "object",
						value: item,
						keys: Object.keys(item).sort(),
						index: 0,
						written: 0
					});
				}
			}
		}
		if (buffered !== "") hash.update(buffered);
		return hash.digest("hex");
	} finally {
		stack.length = 0;
		ancestors.clear();
		encodedKeys.clear();
		buffered = "";
	}
}
function init_canonicalJsonDigestSteps() {
	return (init_canonicalJsonDigestSteps = __esmMin((() => {})))();
}

//#endregion
//#region dist/domain/analysisProfile.js
var committedProviderSchema, unsignedAnalysisProfileSchema, analysisProfileSchema, createAnalysisProfile, analysisProfilesEqual, profileDigest, canonicalJson;
function init_analysisProfile() {
	return (init_analysisProfile = __esmMin((() => {
		init_jsonValue();
		init_digests();
		committedProviderSchema = z.strictObject({
			id: z.string().min(1),
			name: z.string().min(1),
			version: z.string().min(1)
		});
		unsignedAnalysisProfileSchema = z.strictObject({
			provider: committedProviderSchema,
			parameters: jsonObjectSchema
		});
		analysisProfileSchema = unsignedAnalysisProfileSchema.extend({ digest: digestSchema }).superRefine((profile, context) => {
			const { digest: _digest, ...unsigned } = profile;
			if (profileDigest(unsigned) !== profile.digest) context.addIssue({
				code: "custom",
				path: ["digest"],
				message: "Analysis profile digest does not match its parameters"
			});
		});
		createAnalysisProfile = (provider, parameters) => {
			const unsigned = unsignedAnalysisProfileSchema.parse({
				provider: {
					id: provider.id,
					name: provider.name,
					version: provider.version
				},
				parameters
			});
			return analysisProfileSchema.parse({
				...unsigned,
				digest: profileDigest(unsigned)
			});
		};
		analysisProfilesEqual = (left, right) => left.digest === right.digest && left.provider.id === right.provider.id && left.provider.name === right.provider.name && left.provider.version === right.provider.version;
		profileDigest = (profile) => createHash("sha256").update(canonicalJson(profile)).digest("hex");
		canonicalJson = (value) => {
			const encoded = canonicalize(value);
			if (encoded === undefined) throw new TypeError("RFC 8785 canonicalization rejected analysis profile");
			return encoded;
		};
	})))();
}

//#endregion
//#region dist/domain/fixedTupleSchema.js
var fixedTupleSchema;
function init_fixedTupleSchema() {
	return (init_fixedTupleSchema = __esmMin((() => {
		fixedTupleSchema = (items) => z.tuple(items, z.union(items)).check(z.minLength(items.length), z.maxLength(items.length));
	})))();
}

//#endregion
//#region dist/domain/relationshipCoverage.js
var diagnostics, completeCoverage, limitedDirections, partialCoverage, unknownCoverage, relationshipCoverageSchema, relationshipCoverageLimitations;
function init_relationshipCoverage() {
	return (init_relationshipCoverage = __esmMin((() => {
		init_fixedTupleSchema();
		diagnostics = z.array(z.string().min(1)).min(1).exactOptional();
		completeCoverage = z.strictObject({
			status: z.literal("complete"),
			diagnostics
		});
		limitedDirections = z.union([
			fixedTupleSchema([z.literal("callers")]),
			fixedTupleSchema([z.literal("callees")]),
			fixedTupleSchema([z.literal("callers"), z.literal("callees")])
		]);
		partialCoverage = z.strictObject({
			status: z.literal("partial"),
			limitations: z.array(z.string().min(1)).min(1),
			limited_directions: limitedDirections.exactOptional(),
			diagnostics
		});
		unknownCoverage = z.strictObject({
			status: z.literal("unknown"),
			reason: z.string().min(1),
			limited_directions: limitedDirections.exactOptional(),
			diagnostics
		});
		relationshipCoverageSchema = z.discriminatedUnion("status", [
			completeCoverage,
			partialCoverage,
			unknownCoverage
		]);
		relationshipCoverageLimitations = (coverage) => {
			switch (coverage?.status) {
				case undefined: return ["Provider did not report relationship coverage."];
				case "complete": return [];
				case "partial": return coverage.limitations;
				case "unknown": return [coverage.reason];
			}
		};
	})))();
}

//#endregion
//#region dist/domain/evidence.js
/** Create Evidence from owned immutable JSON while exposing cooperative computation steps. */
function* createImmutableEvidenceSteps(target, provider, observation) {
	if (!isImmutableJsonSnapshot(observation.result)) throw new TypeError("Cooperative Evidence requires an authenticated immutable result");
	yield* jsonValueValidationSteps(observation.result);
	const { normalized } = normalizeEvidenceObservation(target, provider, observation);
	const digest = yield* canonicalJsonDigestSteps(semanticProjection(normalized));
	return rememberImmutableEvidence({
		...normalized,
		evidence_id: `ev_${digest}`
	});
}
var providerSchema, subjectFormatSchema, subjectBaseSchema, subjectSchema, evidenceLocationSchema, evidenceAuthoritySchema, executionEnvironmentSchema, evidenceBaseSchema, validateAnalysisProfileProvider, evidenceSchema, authenticatedEvidenceSchema, immutableEvidenceSnapshots, immutableResultSchema, rebindEvidenceSubjectTargetPath, semanticProjection, computeEvidenceId, parseEvidence, immutableEvidence, rebindEvidenceToTargetPath, isImmutableEvidence, rememberImmutableEvidence, createEvidence, normalizeEvidenceObservation;
function init_evidence() {
	return (init_evidence = __esmMin((() => {
		init_canonicalDigest();
		init_canonicalJsonDigestSteps();
		init_localPath();
		init_analysisProfile();
		init_binaryTargetTypes();
		init_jsonValue();
		init_immutableJson();
		init_digests();
		init_relationshipCoverage();
		providerSchema = z.strictObject({
			id: z.string().min(1),
			name: z.string().min(1),
			version: z.string().nullable()
		});
		subjectFormatSchema = z.enum([
			"hopper",
			"analysis-database",
			"mach-o",
			"elf",
			"pe",
			"dos-mz",
			"dos-com",
			"raw-binary",
			"zip",
			"ipa",
			"apk",
			"msix",
			"appx",
			"hap",
			"hsp",
			"app-pack",
			"asar",
			"godot-pck",
			"dmg",
			"pkg",
			"plist",
			"javascript",
			"source-map",
			"directory",
			"file",
			"unknown",
			"mach-o-universal",
			"javascript-bundle",
			"entitlements",
			"pyinstaller"
		]);
		subjectBaseSchema = z.strictObject({
			name: z.string().min(1),
			digest: z.strictObject({ sha256: digestSchema }),
			local_path: nulFreeStringSchema
		});
		subjectSchema = z.discriminatedUnion("format", [subjectBaseSchema.extend({
			format: subjectFormatSchema.exclude(["raw-binary"]),
			architecture: z.enum(BINARY_ARCHITECTURES).exclude([...RAW_ONLY_ARCHITECTURES]).nullable()
		}), subjectBaseSchema.extend({
			format: z.literal("raw-binary"),
			architecture: z.enum(BINARY_ARCHITECTURES).nullable()
		})]);
		evidenceLocationSchema = z.discriminatedUnion("kind", [
			z.strictObject({
				kind: z.literal("address"),
				address: z.string().min(1)
			}),
			z.strictObject({
				kind: z.literal("address-range"),
				start: z.string().min(1),
				end: z.string().min(1)
			}),
			z.strictObject({
				kind: z.literal("artifact-path"),
				path: z.string().min(1)
			}),
			z.strictObject({
				kind: z.literal("file-offset"),
				offset: z.number().int().min(0)
			}),
			z.strictObject({
				kind: z.literal("file-offset-range"),
				start: z.number().int().min(0),
				end: z.number().int().min(0)
			})
		]);
		evidenceAuthoritySchema = z.enum([
			"shipped-artifact",
			"controlled-replay",
			"historical-reference",
			"external-service",
			"analyst-inference"
		]);
		executionEnvironmentSchema = z.strictObject({
			id: z.string().min(1),
			platform: z.string().min(1),
			architecture: z.string().min(1),
			isolation: z.enum([
				"none",
				"process",
				"container",
				"virtual-machine"
			])
		});
		evidenceBaseSchema = z.object({
			evidence_id: prefixedDigestSchema("ev"),
			subject: subjectSchema.nullable(),
			provider: providerSchema,
			analysis_profile: analysisProfileSchema.nullable(),
			predicate_type: z.string().min(1),
			operation: z.string().min(1),
			parameters: jsonObjectSchema,
			raw_result: jsonValueSchema.nullable(),
			normalized_result: jsonValueSchema,
			confidence: z.enum([
				"observed",
				"derived",
				"inferred"
			]),
			authority: evidenceAuthoritySchema,
			environment: executionEnvironmentSchema.nullable(),
			limitations: z.array(z.string()),
			relationship_coverage: relationshipCoverageSchema.nullable(),
			locations: z.array(evidenceLocationSchema),
			evidence_links: z.array(prefixedDigestSchema("ev"))
		}).strict();
		validateAnalysisProfileProvider = (evidence, context) => {
			const profile = evidence.analysis_profile;
			if (profile !== null && (profile.provider.id !== evidence.provider.id || profile.provider.name !== evidence.provider.name || profile.provider.version !== evidence.provider.version)) context.addIssue({
				code: "custom",
				path: ["analysis_profile", "provider"],
				message: "Analysis profile provider does not match Evidence provider"
			});
		};
		evidenceSchema = evidenceBaseSchema.superRefine(validateAnalysisProfileProvider);
		authenticatedEvidenceSchema = evidenceSchema.superRefine((evidence, context) => {
			const { evidence_id: evidenceId, ...withoutId } = evidence;
			if (computeEvidenceId(withoutId) !== evidenceId) context.addIssue({
				code: "custom",
				path: ["evidence_id"],
				message: "Evidence semantic identifier does not match its record"
			});
		});
		immutableEvidenceSnapshots = new WeakMap();
		immutableResultSchema = z.custom(isImmutableJsonSnapshot).superRefine((value, context) => {
			const issue = jsonValueValidationIssue(value);
			if (issue !== undefined) context.addIssue({
				code: "custom",
				message: issue
			});
		});
		rebindEvidenceSubjectTargetPath = (subject, target) => subject.sha256 === target.sha256 && subject.format === target.format && (subject.architecture ?? null) === (target.architecture ?? null) ? {
			...subject,
			path: target.path
		} : subject;
		semanticProjection = (evidence) => ({
			subject: evidence.subject === null ? null : {
				digest: evidence.subject.digest,
				format: evidence.subject.format,
				architecture: evidence.subject.architecture
			},
			provider: evidence.provider,
			analysis_profile: evidence.analysis_profile,
			predicate_type: evidence.predicate_type,
			operation: evidence.operation,
			parameters: evidence.parameters,
			raw_result: evidence.raw_result,
			normalized_result: evidence.normalized_result,
			confidence: evidence.confidence,
			authority: evidence.authority,
			environment: evidence.environment,
			limitations: evidence.limitations,
			relationship_coverage: evidence.relationship_coverage,
			locations: evidence.locations,
			evidence_links: evidence.evidence_links
		});
		computeEvidenceId = (evidence) => `ev_${digestCanonicalValue(semanticProjection(evidence), "Evidence")}`;
		parseEvidence = (input) => {
			const immutable = typeof input === "object" && input !== null ? immutableEvidenceSnapshots.get(input) : undefined;
			if (immutable !== undefined) return immutable;
			return authenticatedEvidenceSchema.parse(input);
		};
		immutableEvidence = (input) => {
			const parsed = parseEvidence(input);
			return rememberImmutableEvidence(canBorrowParsedJsonSnapshot(input, parsed) ? input : parsed);
		};
		rebindEvidenceToTargetPath = (evidence, target) => {
			const subject = evidence.subject;
			if (subject === null) return evidence;
			const rebound = rebindEvidenceSubjectTargetPath({
				path: subject.local_path,
				sha256: subject.digest.sha256,
				format: subject.format,
				...subject.architecture === null ? {} : { architecture: subject.architecture }
			}, target);
			if (rebound.path === subject.local_path) return evidence;
			const reboundSubject = subjectSchema.parse({
				...subject,
				name: basename(target.path) || "artifact",
				local_path: target.path
			});
			const reboundEvidence = {
				...evidence,
				subject: reboundSubject
			};
			if (!isImmutableEvidence(evidence)) return immutableEvidence(reboundEvidence);
			Object.freeze(reboundSubject.digest);
			Object.freeze(reboundSubject);
			Object.freeze(reboundEvidence);
			immutableEvidenceSnapshots.set(reboundEvidence, reboundEvidence);
			return reboundEvidence;
		};
		isImmutableEvidence = (evidence) => immutableEvidenceSnapshots.has(evidence);
		rememberImmutableEvidence = (evidence) => {
			freezeJsonSnapshot(evidence);
			immutableEvidenceSnapshots.set(evidence, evidence);
			return evidence;
		};
		createEvidence = (target, provider, observation) => {
			const { normalized, sharedResult } = normalizeEvidenceObservation(target, provider, observation);
			const evidence = {
				...normalized,
				evidence_id: computeEvidenceId(normalized)
			};
			return sharedResult ? rememberImmutableEvidence(evidence) : evidence;
		};
		normalizeEvidenceObservation = (target, provider, observation) => {
			const subject = target === undefined ? null : {
				name: basename(target.path) || "artifact",
				digest: { sha256: target.sha256 },
				format: target.format,
				architecture: target.architecture ?? null,
				local_path: target.path
			};
			const semantic = {
				subject: subject === null ? null : {
					digest: subject.digest,
					format: subject.format,
					architecture: subject.architecture
				},
				provider: {
					id: provider.id,
					name: provider.name,
					version: provider.version
				},
				analysis_profile: observation.analysisProfile ?? null,
				predicate_type: observation.predicateType ?? "rea.analysis",
				operation: observation.operation,
				parameters: observation.parameters,
				raw_result: observation.rawResult ?? null,
				normalized_result: observation.result,
				confidence: observation.confidence ?? "observed",
				authority: observation.authority ?? "shipped-artifact",
				environment: observation.environment ?? null,
				limitations: [...target === undefined ? [observation.subjectUnavailableReason ?? "Artifact identity is unavailable for this observation."] : [], ...observation.limitations ?? []],
				...observation.relationshipCoverage === undefined ? { relationship_coverage: null } : { relationship_coverage: observation.relationshipCoverage },
				locations: [...observation.locations ?? []],
				evidence_links: [...observation.evidenceLinks ?? []]
			};
			const sharedResult = typeof observation.result === "object" && observation.result !== null && isImmutableJsonSnapshot(observation.result);
			const selectedSchema = sharedResult ? evidenceSchema.safeExtend({ normalized_result: immutableResultSchema }) : evidenceSchema;
			const normalized = selectedSchema.parse({
				...semantic,
				evidence_id: `ev_${"0".repeat(64)}`,
				subject
			});
			return {
				normalized,
				sharedResult
			};
		};
	})))();
}

//#endregion
//#region dist/domain/swiftSymbolClassification.js
var LEGACY_CATEGORIES, NOMINAL_CATEGORIES, classifySwiftSymbol, SWIFT_MANGLING_PREFIXES, isSwiftMangledSymbolName, identifierEnd;
function init_swiftSymbolClassification() {
	return (init_swiftSymbolClassification = __esmMin((() => {
		LEGACY_CATEGORIES = [
			["_TtC", "classes"],
			["_TtV", "structs"],
			["_TtO", "enums"],
			["_TtP", "protocols"],
			["_TtE", "extensions"]
		];
		NOMINAL_CATEGORIES = new Map([
			["C", "classes"],
			["V", "structs"],
			["O", "enums"],
			["P", "protocols"]
		]);
		classifySwiftSymbol = (name) => {
			const prefix = /^_?(?:\$[sS]|_T0)/u.exec(name);
			if (prefix === null) {
				if (!name.includes("_Tt")) return undefined;
				return { category: LEGACY_CATEGORIES.find(([prefix]) => name.startsWith(prefix))?.[1] ?? null };
			}
			const mangling = name.slice(prefix[0].length);
			let offset = identifierEnd(mangling, 0);
			if (offset === undefined) return { category: null };
			let category = null;
			for (;;) {
				const end = identifierEnd(mangling, offset);
				if (end === undefined) {
					if (mangling.charAt(offset) === "0") category = null;
					break;
				}
				const kind = mangling.charAt(end);
				const nominal = NOMINAL_CATEGORIES.get(kind);
				if (nominal === undefined) {
					if (mangling.slice(end) === "Mp") category = "protocols";
					else if (kind === "E" && category !== null) category = "extensions";
					break;
				}
				category = nominal;
				offset = end + 1;
			}
			return { category };
		};
		SWIFT_MANGLING_PREFIXES = [
			"_T0",
			"$S",
			"_$S",
			"$s",
			"_$s",
			"@__swiftmacro_",
			"$e",
			"_$e"
		];
		isSwiftMangledSymbolName = (name) => SWIFT_MANGLING_PREFIXES.some((prefix) => name.startsWith(prefix));
		identifierEnd = (mangling, offset) => {
			const lengthToken = /^[1-9][0-9]*/u.exec(mangling.slice(offset))?.[0];
			if (lengthToken === undefined) return undefined;
			const start = offset + lengthToken.length;
			const end = start + Number(lengthToken);
			if (!Number.isSafeInteger(end) || end > mangling.length || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(mangling.slice(start, end))) return undefined;
			return end;
		};
	})))();
}

//#endregion
//#region dist/domain/native/nativeCallReference.js
var nativeCallClassificationSchema, nativeCallReferenceSchema;
function init_nativeCallReference() {
	return (init_nativeCallReference = __esmMin((() => {
		nativeCallClassificationSchema = z.strictObject({
			classification: z.enum([
				"none",
				"unknown",
				"direct",
				"objective_c"
			]),
			provider_type: z.number().int(),
			provenance: z.string().min(1)
		});
		nativeCallReferenceSchema = nativeCallClassificationSchema.extend({
			source_address: z.string(),
			target_address: z.string()
		});
	})))();
}

//#endregion
//#region dist/domain/apple/machoTargetSelection.js
var machoTargetSelectionSchema, profileMachoTargetSelection, machoTargetSelectionMatchesArchitecture, machoTargetSelectionMatchesFormat, sameMachoTargetSelection;
function init_machoTargetSelection() {
	return (init_machoTargetSelection = __esmMin((() => {
		machoTargetSelectionSchema = z.strictObject({
			kind: z.literal("macho-selected-image-v1"),
			container: z.enum(["thin", "fat"]),
			offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
			byte_length: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
			cpu_type: z.number().int().nonnegative().max(4294967295),
			/** Keep the complete raw subtype, including capability bits. */
			cpu_subtype: z.number().int().nonnegative().max(4294967295),
			container_table_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable()
		}).superRefine((selection, context) => {
			if (selection.container === "thin" && (selection.offset !== 0 || selection.container_table_sha256 !== null) || selection.container === "fat" && selection.container_table_sha256 === null) context.addIssue({
				code: "custom",
				message: "Invalid Mach-O container identity"
			});
		});
		profileMachoTargetSelection = (profile) => {
			const raw = profile?.parameters.target_selection;
			if (raw === undefined) return undefined;
			const parsed = machoTargetSelectionSchema.safeParse(raw);
			return parsed.success ? parsed.data : undefined;
		};
		machoTargetSelectionMatchesArchitecture = (selection, architecture) => {
			const cpuType = {
				x86: 7,
				x86_64: 16777223,
				arm: 12,
				arm64: 16777228
			};
			return cpuType[architecture] === selection.cpu_type;
		};
		machoTargetSelectionMatchesFormat = (selection, format) => selection.container === (format === "mach-o" ? "thin" : "fat");
		sameMachoTargetSelection = (left, right) => left !== undefined && right !== undefined && left.container === right.container && left.offset === right.offset && left.byte_length === right.byte_length && left.cpu_type === right.cpu_type && left.cpu_subtype === right.cpu_subtype && left.container_table_sha256 === right.container_table_sha256;
	})))();
}

//#endregion
//#region dist/domain/native/objcSwiftMetadata.js
var isAppleDispatchMetadataTarget, objcMethodTypeSchema, objcPropertyAttributeSchema, objcMethodSchema, objcPropertySchema, objcProtocolSchema, objcClassSchema, nativeMetadataLocationSchema, nativeMetadataDecodeSchema, nativeMetadataEvidenceSchema, objcIvarSchema, objcProtocolRecordSchema, objcDispatchImplementationSchema, objcCategorySchema, machoImportBindingSchema, swiftConformanceSchema, swiftDispatchSlotSchema, relativePointerSchema, swiftSymbolSchema, nativeMetadataCoverageSchema, objcClassImportIdentitySchema, objcClassImportBindingCoverageSchema, swiftDeclKindSchema, swiftAccessLevelSchema, swiftDeclSchema, dbOperationSchema, dbSaveResultSchema, objcSwiftMetadataSchema, nativeDispatchMetadataResultSchema, inspectNativeDispatchMetadata, parseMetadataAddress;
function init_objcSwiftMetadata() {
	return (init_objcSwiftMetadata = __esmMin((() => {
		init_binaryTargetTypes();
		init_evidence();
		init_swiftSymbolClassification();
		init_nativeCallReference();
		init_machoTargetSelection();
		init_unicodeCodePointOrder();
		isAppleDispatchMetadataTarget = (target) => target.kind === "executable" && isMachOFormat(target.format);
		objcMethodTypeSchema = z.enum([
			"instance",
			"class",
			"ivar_getter",
			"ivar_setter"
		]);
		objcPropertyAttributeSchema = z.strictObject({
			name: z.string().min(1),
			value: z.string()
		});
		objcMethodSchema = z.strictObject({
			selector: z.string().min(1),
			method_type: objcMethodTypeSchema,
			address: z.number().int().nullable(),
			is_required: z.boolean().nullable(),
			is_optional: z.boolean().nullable()
		});
		objcPropertySchema = z.strictObject({
			name: z.string().min(1),
			type_encoding: z.string().nullable(),
			attributes: z.array(objcPropertyAttributeSchema),
			atomicity: z.enum(["atomic", "nonatomic"]).nullable(),
			is_readonly: z.boolean().nullable(),
			getter: z.string().nullable(),
			setter: z.string().nullable()
		});
		objcProtocolSchema = z.strictObject({
			name: z.string().min(1),
			methods: z.array(objcMethodSchema).default([]),
			optional_methods: z.array(objcMethodSchema).default([]),
			properties: z.array(objcPropertySchema).default([])
		});
		objcClassSchema = z.strictObject({
			name: z.string().min(1),
			super_class: z.string().nullable(),
			is_meta_class: z.boolean().nullable(),
			is_root_class: z.boolean().nullable(),
			methods: z.array(objcMethodSchema).default([]),
			properties: z.array(objcPropertySchema).default([]),
			protocols: z.array(z.string()).default([]),
			ivar_count: z.number().int().nonnegative().nullable(),
			instance_size: z.number().int().nonnegative().nullable(),
			location: z.object({
				address: z.string().nullable(),
				file_offset: z.number().int().nonnegative().nullable()
			}).optional(),
			superclass_address: z.string().nullable().optional(),
			metaclass_address: z.string().nullable().optional(),
			decode: z.object({
				status: z.enum([
					"decoded",
					"partial",
					"unsupported",
					"invalid"
				]),
				reason: z.string().nullable()
			}).optional(),
			evidence: z.array(z.object({
				kind: z.literal("binary_metadata"),
				description: z.string(),
				location: z.object({
					address: z.string().nullable(),
					file_offset: z.number().int().nonnegative().nullable()
				}),
				artifact_path: z.string(),
				artifact_sha256: z.string()
			})).optional()
		});
		nativeMetadataLocationSchema = z.strictObject({
			address: z.string().nullable(),
			file_offset: z.number().int().nonnegative().nullable()
		});
		nativeMetadataDecodeSchema = z.strictObject({
			status: z.enum([
				"decoded",
				"partial",
				"unsupported",
				"invalid"
			]),
			reason: z.string().nullable()
		});
		nativeMetadataEvidenceSchema = z.strictObject({
			kind: z.enum([
				"binary_metadata",
				"interface_builder_resource",
				"symbol",
				"reference",
				"decompiler"
			]),
			description: z.string().min(1),
			provider: providerSchema.optional(),
			location: nativeMetadataLocationSchema,
			/** Preserve a provider's source value when it does not establish a location. */
			reported_address: z.string().optional(),
			call_reference: nativeCallReferenceSchema.exactOptional(),
			artifact_path: z.string().min(1).nullable().default(null),
			artifact_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable().default(null)
		});
		objcIvarSchema = z.strictObject({
			class_name: z.string().min(1),
			name: z.string().min(1),
			type_encoding: z.string().nullable(),
			offset: z.number().int().nonnegative().nullable(),
			size: z.number().int().nonnegative().nullable().default(null),
			alignment: z.number().int().positive().nullable().default(null),
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		objcProtocolRecordSchema = z.strictObject({
			name: z.string(),
			adopted_protocols: z.array(z.string()),
			methods: z.array(objcMethodSchema),
			optional_methods: z.array(objcMethodSchema),
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		objcDispatchImplementationSchema = z.strictObject({
			class_name: z.string().min(1),
			selector: z.string().min(1),
			method_type: z.enum(["instance", "class"]),
			implementation_address: z.string().nullable(),
			/** Category that adds this method, when it is not defined by the class itself. */
			category: z.string().nullable().optional(),
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		objcCategorySchema = z.strictObject({
			name: z.string().min(1),
			/** Extended class; external classes come from the category's bind symbol. */
			class_name: z.string().min(1).nullable(),
			class_source: z.enum([
				"local",
				"external",
				"unresolved"
			]),
			instance_methods: z.array(z.string()),
			class_methods: z.array(z.string()),
			protocols: z.array(z.string()),
			properties: z.array(objcPropertySchema),
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		machoImportBindingSchema = z.strictObject({
			requested_address: z.string().min(1),
			symbol: z.string().min(1),
			binding_source: z.enum([
				"chained",
				"bind",
				"weak",
				"lazy"
			]),
			library_ordinal: z.number().int().min(-3).max(Number.MAX_SAFE_INTEGER),
			library: z.string().nullable(),
			weak: z.boolean(),
			addend: z.string().regex(/^-?\d+$/u)
		});
		swiftConformanceSchema = z.strictObject({
			type_name: z.string().min(1).nullable(),
			/** Raw three-bit Swift ABI type-reference kind; absent in older Evidence. */
			type_reference_kind: z.number().int().min(0).max(7).optional(),
			/** Address of the descriptor, class-name string, or resolved ObjC class reference. */
			type_reference_target: nativeMetadataLocationSchema.optional(),
			type_binding: machoImportBindingSchema.nullable().optional(),
			protocol_name: z.string().min(1).nullable(),
			/** Resolved protocol descriptor address, retained when its bytes are unavailable. */
			protocol_target: nativeMetadataLocationSchema.optional(),
			protocol_binding: machoImportBindingSchema.nullable().optional(),
			module: z.string().nullable(),
			witness_table: nativeMetadataLocationSchema,
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		swiftDispatchSlotSchema = z.strictObject({
			owner: z.string().min(1),
			table_kind: z.enum(["witness_table", "class_vtable"]),
			slot_index: z.number().int().nonnegative(),
			requirement: z.string().nullable(),
			implementation: z.string().nullable(),
			implementation_address: z.string().nullable(),
			implementation_binding: machoImportBindingSchema.nullable().optional(),
			thunk_address: z.string().nullable(),
			location: nativeMetadataLocationSchema,
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		relativePointerSchema = z.strictObject({
			field: nativeMetadataLocationSchema,
			target: nativeMetadataLocationSchema,
			displacement: z.number().int(),
			indirectable: z.boolean(),
			indirect: z.boolean().nullable(),
			encoding_tag: z.number().int().nonnegative().optional(),
			binding: machoImportBindingSchema.optional(),
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		swiftSymbolSchema = z.strictObject({
			mangled_name: z.string().min(1),
			address: z.string().min(1).nullable(),
			decode: nativeMetadataDecodeSchema,
			evidence: z.array(nativeMetadataEvidenceSchema).min(1)
		});
		nativeMetadataCoverageSchema = z.strictObject({
			facet: z.string().min(1),
			status: z.enum([
				"complete",
				"partial",
				"unsupported",
				"not_requested"
			]),
			reason: z.string().nullable(),
			examined: z.number().int().nonnegative(),
			decoded: z.number().int().nonnegative()
		});
		objcClassImportIdentitySchema = machoImportBindingSchema.omit({ requested_address: true });
		objcClassImportBindingCoverageSchema = z.strictObject({
			facet: z.literal("objc_class_import_bindings"),
			status: z.enum([
				"complete",
				"partial",
				"unsupported",
				"not_requested"
			]),
			reason: z.string().nullable(),
			examined: z.number().int().nonnegative(),
			decoded: z.number().int().nonnegative()
		});
		swiftDeclKindSchema = z.enum([
			"class",
			"struct",
			"enum",
			"protocol",
			"extension",
			"actor",
			"global_var",
			"global_func"
		]);
		swiftAccessLevelSchema = z.enum([
			"private",
			"fileprivate",
			"internal",
			"public",
			"open"
		]);
		swiftDeclSchema = z.strictObject({
			kind: swiftDeclKindSchema,
			name: z.string().min(1),
			module: z.string().nullable(),
			access_level: swiftAccessLevelSchema.default("internal"),
			super_class: z.string().nullable(),
			protocols: z.array(z.string()).default([]),
			is_final: z.boolean().default(false),
			is_required: z.boolean().default(false),
			is_convenience_init: z.boolean().default(false),
			is_override: z.boolean().default(false)
		});
		dbOperationSchema = z.enum([
			"save",
			"readback",
			"open_database",
			"close_database",
			"export",
			"import"
		]);
		dbSaveResultSchema = z.strictObject({
			operation: dbOperationSchema,
			succeeded: z.boolean(),
			preserved_names: z.number().int().nonnegative().default(0),
			preserved_comments: z.number().int().nonnegative().default(0),
			preserved_bookmarks: z.number().int().nonnegative().default(0),
			database_path: z.string().nullable(),
			error: z.string().nullable()
		});
		objcSwiftMetadataSchema = z.strictObject({
			objc_classes: z.array(objcClassSchema).default([]),
			objc_protocols: z.array(objcProtocolSchema).default([]),
			objc_categories: z.array(objcCategorySchema).default([]),
			swift_decls: z.array(swiftDeclSchema).default([]),
			objc_ivars: z.array(objcIvarSchema).default([]),
			objc_protocol_records: z.array(objcProtocolRecordSchema).default([]),
			objc_dispatch_implementations: z.array(objcDispatchImplementationSchema).default([]),
			swift_conformances: z.array(swiftConformanceSchema).default([]),
			swift_dispatch_slots: z.array(swiftDispatchSlotSchema).default([]),
			swift_symbols: z.array(swiftSymbolSchema).default([]),
			objc_class_import_bindings: z.array(machoImportBindingSchema).optional(),
			objc_class_import_binding_coverage: objcClassImportBindingCoverageSchema.optional(),
			target_selection: machoTargetSelectionSchema.optional(),
			relative_pointers: z.array(relativePointerSchema).default([]),
			coverage: z.array(nativeMetadataCoverageSchema).default([]),
			db_save_result: dbSaveResultSchema.nullable()
		});
		nativeDispatchMetadataResultSchema = z.strictObject({
			target_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable(),
			target_architecture: z.enum(BINARY_ARCHITECTURES).nullable().optional(),
			provider: z.strictObject({
				id: z.string().min(1),
				name: z.string().min(1),
				version: z.string().nullable()
			}),
			analysis_profile_digest: z.string().min(1).nullable(),
			result: objcSwiftMetadataSchema
		});
		inspectNativeDispatchMetadata = (names, maxRecords = 5e3) => {
			const symbolEvidence = (entry, address) => [{
				kind: "symbol",
				description: `Provider symbol ${entry.name}`,
				location: {
					address,
					file_offset: null
				},
				...address === null ? { reported_address: entry.address } : {},
				artifact_path: null,
				artifact_sha256: null
			}];
			const classNames = new Set();
			const implementations = new Map();
			const swiftSymbols = [];
			const examinedNames = names.slice(0, maxRecords);
			for (const entry of examinedNames) {
				const address = entry.address === "" ? null : entry.address;
				const classMatch = /(?:OBJC_CLASS_|OBJC_METACLASS_)\$_([^\s]+)/u.exec(entry.name);
				if (classMatch?.[1] !== undefined) classNames.add(classMatch[1]);
				const methodMatch = /^([+-])\[([^\s\]]+)\s+([^\]]+)\]$/u.exec(entry.name);
				if (methodMatch?.[1] !== undefined && methodMatch[2] && methodMatch[3]) {
					const methodType = methodMatch[1] === "+" ? "class" : "instance";
					const selector = methodMatch[3];
					implementations.set(`${methodMatch[2]}:${selector}:${methodType}`, {
						class_name: methodMatch[2],
						selector,
						method_type: methodType,
						implementation_address: address,
						location: {
							address,
							file_offset: null
						},
						decode: {
							status: "partial",
							reason: "symbol_name_only"
						},
						evidence: symbolEvidence(entry, address)
					});
					classNames.add(methodMatch[2]);
				}
				if (isSwiftMangledSymbolName(entry.name) || entry.name.startsWith("_Tt")) swiftSymbols.push({
					mangled_name: entry.name,
					address,
					decode: {
						status: "partial",
						reason: "mangled_symbol_not_demangled"
					},
					evidence: symbolEvidence(entry, address)
				});
			}
			const methodsByClass = new Map();
			for (const implementation of implementations.values()) {
				const methods = methodsByClass.get(implementation.class_name) ?? [];
				methods.push({
					selector: implementation.selector,
					method_type: implementation.method_type,
					address: parseMetadataAddress(implementation.implementation_address),
					is_required: null,
					is_optional: null
				});
				methodsByClass.set(implementation.class_name, methods);
			}
			const classes = [...classNames].sort().map((name) => ({
				name,
				super_class: null,
				is_meta_class: null,
				is_root_class: null,
				methods: methodsByClass.get(name) ?? [],
				properties: [],
				protocols: [],
				ivar_count: null,
				instance_size: null
			}));
			const decodedImplementations = [...implementations.values()].sort((left, right) => compareUnicodeCodePoints(compositeKey([left.class_name, left.selector]), compositeKey([right.class_name, right.selector])));
			const swift = swiftSymbols.length > 0;
			return objcSwiftMetadataSchema.parse({
				objc_classes: classes,
				objc_dispatch_implementations: decodedImplementations,
				swift_symbols: swiftSymbols,
				coverage: [
					{
						facet: "objc_class_symbols",
						status: "partial",
						reason: names.length > examinedNames.length ? "record_limit_reached_and_symbol_names_are_not_runtime_class_metadata" : "symbol_names_do_not_recover_all_runtime_class_metadata",
						examined: examinedNames.length,
						decoded: classes.length
					},
					{
						facet: "objc_dispatch_implementations",
						status: decodedImplementations.length > 0 ? "partial" : "unsupported",
						reason: names.length > examinedNames.length ? "record_limit_reached_and_only_symbolized_methods_are_resolved" : decodedImplementations.length > 0 ? "only_symbolized_methods_are_resolved" : "provider_name_inventory_has_no_objc_method_symbols",
						examined: examinedNames.length,
						decoded: decodedImplementations.length
					},
					{
						facet: "objc_ivar_layouts",
						status: "unsupported",
						reason: "symbol_inventory_does_not_expose_runtime_ivar_layouts",
						examined: 0,
						decoded: 0
					},
					{
						facet: "swift_declarations",
						status: swift ? "partial" : "unsupported",
						reason: swift ? "symbols_are_not_demangled_declarations" : "no_swift_symbols_observed",
						examined: swiftSymbols.length,
						decoded: 0
					},
					{
						facet: "swift_dispatch_tables",
						status: "unsupported",
						reason: "provider_name_inventory_does_not_decode_witness_or_class_vtables",
						examined: 0,
						decoded: 0
					},
					{
						facet: "relative_pointers",
						status: "unsupported",
						reason: "provider_name_inventory_does_not_decode_binary_relative_pointers",
						examined: 0,
						decoded: 0
					}
				],
				db_save_result: null
			});
		};
		parseMetadataAddress = (address) => {
			if (address === null) return null;
			const match = /(?:^|:)0x([0-9a-f]+)$/iu.exec(address);
			if (match?.[1] === undefined) return null;
			const value = Number.parseInt(match[1], 16);
			return Number.isSafeInteger(value) ? value : null;
		};
	})))();
}

//#endregion
//#region dist/domain/native/addressCoordinate.js
var addressCoordinate;
function init_addressCoordinate() {
	return (init_addressCoordinate = __esmMin((() => {
		addressCoordinate = (value) => {
			const separator = value.lastIndexOf(":0x");
			if (separator === 0) return null;
			const space = separator < 0 ? null : value.slice(0, separator);
			const offset = separator < 0 ? value : value.slice(separator + 1);
			if (!/^0x[0-9a-f]+$/u.test(offset)) return null;
			return {
				space,
				offset: BigInt(offset)
			};
		};
	})))();
}

//#endregion
//#region dist/domain/native/nativeApiBoundary.js
var inferenceConfidenceSchema, inferenceEvidenceSchema, inferredBoundaryTypeFacts, inferredReturnTypeSchema, inferredParameterTypeSchema, jumpTableDataSourceSchema, jumpTableMappingSchema, jumpTableDefaultTargetSchema, inferredJumpTableSchema, availableNativeApiBoundarySchema, unavailableNativeApiBoundarySchema, nativeApiBoundarySchema, nativeApiInspectionSubstepSchema, nativeApiInspectionResultSchema;
function init_nativeApiBoundary() {
	return (init_nativeApiBoundary = __esmMin((() => {
		inferenceConfidenceSchema = z.enum([
			"low",
			"medium",
			"high"
		]);
		inferenceEvidenceSchema = z.object({
			kind: z.enum([
				"signature-source",
				"decompiler-type",
				"type-lock",
				"calling-convention",
				"jump-table"
			]),
			source: z.string().min(1),
			detail: z.string().min(1)
		}).strict();
		inferredBoundaryTypeFacts = {
			ordinal: z.number().int().min(0).nullable(),
			name: z.string().min(1).nullable(),
			data_type: z.string().min(1),
			size_bytes: z.number().int().min(0).nullable(),
			storage: z.string().min(1).nullable(),
			confidence: inferenceConfidenceSchema,
			evidence: z.array(inferenceEvidenceSchema).min(1),
			decompiler_artifacts: z.array(z.enum([
				"recovered-signature",
				"register-or-stack-storage",
				"compiler-generated-variable"
			]))
		};
		inferredReturnTypeSchema = z.strictObject({
			...inferredBoundaryTypeFacts,
			role: z.literal("return"),
			ordinal: z.null(),
			name: z.null()
		});
		inferredParameterTypeSchema = z.strictObject({
			...inferredBoundaryTypeFacts,
			role: z.literal("parameter"),
			ordinal: z.number().int().min(0)
		});
		jumpTableDataSourceSchema = z.object({
			address: z.string().min(1),
			provenance: z.enum([
				"ghidra-decompiler-load-table",
				"ghidra-dispatch-block-data-reference",
				"ghidra-aarch64-byte-table",
				"ghidra-aarch64-halfword-table"
			]),
			entry_size_bytes: z.number().int().min(1).nullable(),
			entry_count: z.number().int().min(0).nullable(),
			confidence: inferenceConfidenceSchema,
			evidence: z.array(inferenceEvidenceSchema).min(1)
		}).strict();
		jumpTableMappingSchema = z.object({
			case_value: z.number().int().nullable(),
			target_address: z.string().min(1),
			confidence: inferenceConfidenceSchema,
			evidence: z.array(inferenceEvidenceSchema).min(1)
		}).strict();
		jumpTableDefaultTargetSchema = z.strictObject({
			target_address: z.string().min(1),
			confidence: inferenceConfidenceSchema,
			evidence: z.array(inferenceEvidenceSchema).min(1)
		});
		inferredJumpTableSchema = z.object({
			dispatch_address: z.string().min(1),
			data_sources: z.array(jumpTableDataSourceSchema),
			mappings: z.array(jumpTableMappingSchema),
			default_targets: z.array(jumpTableDefaultTargetSchema),
			limitations: z.array(z.string())
		}).strict();
		availableNativeApiBoundarySchema = z.object({
			available: z.literal(true),
			provenance: z.string().min(1),
			signature_source: z.string().min(1),
			calling_convention: z.string().min(1),
			return_type: inferredReturnTypeSchema,
			parameters: z.array(inferredParameterTypeSchema),
			jump_tables: z.array(inferredJumpTableSchema),
			pseudocode: z.object({
				classification: z.literal("decompiler-generated-non-source"),
				compilable: z.literal(false)
			}).strict(),
			decompiler_artifacts: z.array(z.enum([
				"recovered-signature",
				"register-and-stack-variables",
				"compiler-generated-control-flow",
				"pointer-arithmetic",
				"pseudocode"
			])),
			limitations: z.array(z.string())
		}).strict();
		unavailableNativeApiBoundarySchema = z.object({
			available: z.literal(false),
			reason: z.string().min(1),
			residual_unknowns: z.array(z.string().min(1)).min(1)
		}).strict();
		nativeApiBoundarySchema = z.discriminatedUnion("available", [unavailableNativeApiBoundarySchema, availableNativeApiBoundarySchema]);
		nativeApiInspectionSubstepSchema = z.object({
			operation: z.enum([
				"analyze_function",
				"project_native_api_boundary",
				"preserve_residual_unknowns"
			]),
			status: z.enum(["completed", "unsupported"]),
			observations: z.array(z.string().min(1))
		}).strict();
		nativeApiInspectionResultSchema = z.object({
			procedure: z.object({
				address: z.string().min(1),
				name: z.string().min(1)
			}).strict(),
			boundary: nativeApiBoundarySchema,
			substeps: z.array(nativeApiInspectionSubstepSchema).length(3),
			unsupported_branches: z.array(z.string().min(1)),
			residual_unknowns: z.array(z.string().min(1))
		}).strict();
	})))();
}

//#endregion
//#region dist/domain/native/nativeValueFlow.js
var nativeVarnodeSchema, nativePcodeOperationSchema, nativePcodeDefUseSchema, nativePcodeEffectSchema, nativeValueFlowSchema;
function init_nativeValueFlow() {
	return (init_nativeValueFlow = __esmMin((() => {
		nativeVarnodeSchema = z.strictObject({
			kind: z.enum([
				"constant",
				"address",
				"register",
				"unique",
				"other"
			]),
			size_bytes: z.number().int().nonnegative(),
			location: z.string().nullable(),
			constant_hex: z.string().regex(/^[0-9a-f]+$/u).nullable()
		});
		nativePcodeOperationSchema = z.strictObject({
			id: z.string().min(1),
			address: z.string().min(1),
			sequence: z.number().int().nonnegative(),
			opcode: z.string().min(1),
			is_dead: z.boolean(),
			block_membership: z.enum([
				"member",
				"detached",
				"unavailable"
			]),
			inputs: z.array(nativeVarnodeSchema),
			output: nativeVarnodeSchema.nullable()
		});
		nativePcodeDefUseSchema = z.strictObject({
			definition: z.string().min(1),
			use: z.string().min(1),
			input_index: z.number().int().nonnegative()
		});
		nativePcodeEffectSchema = z.strictObject({
			operation: z.string().min(1),
			kind: z.enum([
				"memory_read",
				"memory_write",
				"conditional_branch",
				"indirect_branch",
				"direct_call",
				"indirect_call"
			]),
			operand_input: z.number().int().nonnegative().nullable(),
			value_input: z.number().int().nonnegative().nullable()
		});
		nativeValueFlowSchema = z.discriminatedUnion("available", [z.strictObject({
			available: z.literal(true),
			provenance: z.literal("ghidra-high-pcode"),
			operations: z.array(nativePcodeOperationSchema),
			def_use: z.array(nativePcodeDefUseSchema),
			effects: z.array(nativePcodeEffectSchema),
			parameters: z.array(z.strictObject({
				ordinal: z.number().int().nonnegative(),
				name: z.string(),
				data_type: z.string()
			})),
			parameter_uses: z.array(z.strictObject({
				ordinal: z.number().int().nonnegative(),
				use: z.string(),
				input_index: z.number().int().nonnegative()
			})),
			truncated: z.boolean(),
			omitted_operations_lower_bound: z.number().int().nonnegative(),
			known_omitted_inputs: z.number().int().nonnegative(),
			known_omitted_edges: z.number().int().nonnegative(),
			limitations: z.array(z.string().min(1))
		}), z.strictObject({
			available: z.literal(false),
			reason: z.string().min(1),
			limitations: z.array(z.string().min(1))
		})]);
	})))();
}

//#endregion
//#region dist/domain/hopperValues.js
var addressDistance, procedureMapSchema, addressedNamesSchema, addressedNameMapSchema, segmentSchema, unavailableAnalysisFactSchema, analysisStringSchema, analysisBookmarkSchema, functionBodySchema, functionBodyEntryAgrees, procedureClassificationSchema, procedureIdentitySchema, localVariableSchema, functionInstructionWindowSchema, availableReferenceKindSchema, referenceKindSchema, unresolvedCallSchema, swiftStringLiteralFields, swiftStringLiteralSchema, swiftStringLiteralOmissionFields, swiftStringLiteralOmissionSchema, referenceEdgeSchema, facetAvailabilitySchema, functionDossierSchema, parseFunctionDossier, parseProcedures, parseNames, parseRelatedAddresses, parseSegments, parseSegmentImageBase, projectBinaryOverview, parseDocuments, parseListCount, unwrapProperty, invalid;
function init_hopperValues() {
	return (init_hopperValues = __esmMin((() => {
		init_fixedTupleSchema();
		init_addressCoordinate();
		init_result();
		init_nativeApiBoundary();
		init_nativeValueFlow();
		init_nativeCallReference();
		init_analysisErrorCore();
		addressDistance = (start, end) => {
			const left = addressCoordinate(start);
			const right = addressCoordinate(end);
			if (left === null || right === null || left.space !== right.space) return null;
			const distance = right.offset - left.offset;
			if (distance < 0n || distance > BigInt(Number.MAX_SAFE_INTEGER)) return null;
			return Number(distance);
		};
		procedureMapSchema = z.record(z.string(), z.string());
		addressedNamesSchema = z.array(z.object({
			address: z.string(),
			name: z.string()
		}));
		addressedNameMapSchema = z.record(z.string(), z.string());
		segmentSchema = z.object({
			name: z.string(),
			start: z.string(),
			end: z.string(),
			readable: z.boolean().nullable(),
			writable: z.boolean().nullable(),
			executable: z.boolean().nullable(),
			image_base: z.string().min(1).exactOptional(),
			address_space: z.string().min(1).exactOptional()
		});
		unavailableAnalysisFactSchema = z.object({
			available: z.literal(false),
			reason: z.string()
		}).strict();
		analysisStringSchema = z.object({
			address: z.string(),
			value: z.string(),
			provider_value: z.string().exactOptional().describe("Original provider display text, which may shorten the typed object."),
			decoding: unavailableAnalysisFactSchema.exactOptional().describe("When present, value retains native display text because typed bytes could not be decoded."),
			string: z.object({
				encoding: z.string().min(1),
				encoding_status: z.enum(["observed", "inferred"]).exactOptional().describe("Whether the provider declares the encoding or REA infers it from the typed bytes and native display. This does not establish the original source's intended encoding."),
				termination: z.enum(["missing", "present_or_not_required"]),
				byte_length: z.number().int().min(0)
			}).exactOptional()
		});
		analysisBookmarkSchema = z.strictObject({
			address: z.string(),
			name: z.string().nullable()
		});
		functionBodySchema = z.discriminatedUnion("available", [unavailableAnalysisFactSchema, z.strictObject({
			available: z.literal(true),
			provenance: z.string().min(1),
			ranges: z.array(z.strictObject({
				start: z.string(),
				end: z.string().describe("Inclusive last address of this observed body range.")
			})),
			total_bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
			span_bytes: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(),
			non_contiguous: z.boolean(),
			contains_entry: z.boolean()
		}).superRefine((body, context) => {
			let total = 0n;
			const bounds = new Map();
			const closedSpaces = new Set();
			let previousSpace;
			for (const range of body.ranges) {
				const start = addressCoordinate(range.start);
				const end = addressCoordinate(range.end);
				if (start === null || end === null || start.space !== end.space || end.offset < start.offset) {
					context.addIssue({
						code: "custom",
						message: "Function body range has invalid inclusive endpoints"
					});
					return;
				}
				if (previousSpace !== undefined && previousSpace !== start.space) closedSpaces.add(previousSpace);
				const previous = bounds.get(start.space);
				if (closedSpaces.has(start.space) || previous !== undefined && start.offset <= previous.end + 1n) {
					context.addIssue({
						code: "custom",
						message: "Function body ranges must be ordered, disjoint and maximal within each address space"
					});
					return;
				}
				bounds.set(start.space, {
					start: previous?.start ?? start.offset,
					end: end.offset
				});
				previousSpace = start.space;
				total += end.offset - start.offset + 1n;
			}
			const onlyBounds = bounds.size === 1 ? [...bounds.values()][0] : undefined;
			const span = bounds.size === 0 ? 0n : onlyBounds === undefined ? null : onlyBounds.end - onlyBounds.start + 1n;
			const reportedSpan = body.span_bytes === null ? null : BigInt(body.span_bytes);
			if (total !== BigInt(body.total_bytes) || span !== reportedSpan || body.non_contiguous !== body.ranges.length > 1) context.addIssue({
				code: "custom",
				message: "Function body counts, enclosing span or contiguity disagree with inclusive ranges"
			});
		})]);
		functionBodyEntryAgrees = (body, address) => {
			if (!body.available) return true;
			const entry = addressCoordinate(address);
			if (entry === null) return false;
			const contains = body.ranges.some((range) => {
				const start = addressCoordinate(range.start);
				const end = addressCoordinate(range.end);
				return start !== null && end !== null && start.space === entry.space && entry.offset >= start.offset && entry.offset <= end.offset;
			});
			return contains === body.contains_entry;
		};
		procedureClassificationSchema = z.object({
			external: z.boolean(),
			thunk: z.boolean(),
			thunk_target: z.string().nullable(),
			provenance: z.string().min(1)
		}).strict();
		procedureIdentitySchema = z.object({
			address: z.string(),
			name: z.string(),
			classification: procedureClassificationSchema.nullable(),
			body: functionBodySchema
		}).strict().superRefine((identity, context) => {
			if (!functionBodyEntryAgrees(identity.body, identity.address)) context.addIssue({
				code: "custom",
				message: "Function body entry membership disagrees with procedure identity"
			});
		});
		localVariableSchema = z.object({
			description: z.string(),
			provenance: z.string().min(1),
			name: z.string().nullable().exactOptional(),
			stack_displacement: z.string().regex(/^-?\d+$/u).nullable().exactOptional().describe("Observed signed stack byte displacement, encoded as decimal to preserve precision.")
		}).strict();
		functionInstructionWindowSchema = z.object({
			procedure: procedureIdentitySchema,
			instructions: z.array(z.string()),
			limitations: z.array(z.string())
		}).strict();
		availableReferenceKindSchema = z.object({
			available: z.literal(true),
			provenance: z.string().min(1),
			type: z.string(),
			flow: z.boolean(),
			call: z.boolean(),
			jump: z.boolean(),
			data: z.boolean(),
			read: z.boolean(),
			write: z.boolean(),
			indirect: z.boolean(),
			computed: z.boolean(),
			conditional: z.boolean(),
			terminal: z.boolean(),
			primary: z.boolean(),
			operand_index: z.number().int(),
			external: z.boolean()
		}).strict();
		referenceKindSchema = z.discriminatedUnion("available", [unavailableAnalysisFactSchema, availableReferenceKindSchema]);
		unresolvedCallSchema = z.strictObject({
			address: z.string(),
			reason: z.string()
		});
		swiftStringLiteralFields = {
			source_address: z.string().describe("Instruction that consumes both words: a call, tail call, return, or paired store."),
			value: z.string().describe("Decoded UTF-8 text, including the canonical empty string."),
			registers: fixedTupleSchema([z.string(), z.string()]),
			words: fixedTupleSchema([z.string(), z.string()]).describe("Observed constant register values, in register order.")
		};
		swiftStringLiteralSchema = z.discriminatedUnion("representation", [z.strictObject({
			...swiftStringLiteralFields,
			representation: z.literal("small").describe("The UTF-8 bytes are inside the two words."),
			address: z.null().describe("A small literal has no storage of its own.")
		}), z.strictObject({
			...swiftStringLiteralFields,
			representation: z.literal("large").describe("An immortal literal whose words hold its count and a pointer to its bytes."),
			address: z.string().describe("Address of a large literal's bytes.")
		})]);
		swiftStringLiteralOmissionFields = {
			source_address: swiftStringLiteralFields.source_address,
			byte_length: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
			reason: z.enum(["capacity", "unresolved_jump"]).describe("Why this candidate is omitted: capacity stopped decoding, or an unresolved jump left its use unknown."),
			registers: swiftStringLiteralFields.registers,
			words: swiftStringLiteralFields.words
		};
		swiftStringLiteralOmissionSchema = z.discriminatedUnion("representation", [z.strictObject({
			...swiftStringLiteralOmissionFields,
			representation: z.literal("small"),
			address: z.null()
		}), z.strictObject({
			...swiftStringLiteralOmissionFields,
			representation: z.literal("large"),
			address: z.string().describe("Address of the literal's bytes.")
		})]);
		referenceEdgeSchema = z.object({
			source_address: z.string(),
			target_address: z.string(),
			source_procedure: procedureIdentitySchema.nullable(),
			target_procedure: procedureIdentitySchema.nullable(),
			kind: referenceKindSchema,
			call: nativeCallClassificationSchema.exactOptional()
		}).strict();
		facetAvailabilitySchema = z.discriminatedUnion("available", [z.object({ available: z.literal(true) }).strict(), z.object({
			available: z.literal(false),
			reason: z.string().min(1)
		}).strict()]);
		functionDossierSchema = z.object({
			procedure: procedureIdentitySchema.safeExtend({
				signature: z.string().nullable(),
				locals: z.array(localVariableSchema)
			}),
			pseudocode: z.string(),
			assembly: z.array(z.string()),
			comments: z.array(z.object({
				address: z.string(),
				kind: z.enum(["comment", "inline"]),
				text: z.string()
			}).strict()),
			callers: z.array(procedureIdentitySchema),
			callees: z.array(procedureIdentitySchema),
			incoming_references: z.array(referenceEdgeSchema),
			outgoing_references: z.array(referenceEdgeSchema),
			unresolved_calls: z.array(unresolvedCallSchema).exactOptional(),
			referenced_strings: z.array(analysisStringSchema.extend({ source_address: z.string() })),
			referenced_names: z.array(z.object({
				address: z.string(),
				value: z.string(),
				source_address: z.string()
			}).strict()),
			swift_string_literals: z.array(swiftStringLiteralSchema).exactOptional().describe("Swift String literals decoded from constant register values. Absent when the provider does not decode them for this target."),
			swift_string_literal_omissions: z.array(swiftStringLiteralOmissionSchema).exactOptional().describe("Literal candidates omitted for capacity or unresolved control flow. Present exactly when swift_string_literals is present; empty when all examined use sites were classified."),
			basic_blocks: z.array(z.object({
				start: z.string(),
				end: z.string(),
				successors: z.array(z.string())
			}).strict()),
			native_api: nativeApiBoundarySchema.nullable(),
			native_value_flow: nativeValueFlowSchema.nullable(),
			facet_availability: z.object({
				pseudocode: facetAvailabilitySchema.exactOptional(),
				assembly: facetAvailabilitySchema.exactOptional(),
				comments: facetAvailabilitySchema.exactOptional(),
				callers: facetAvailabilitySchema.exactOptional(),
				callees: facetAvailabilitySchema.exactOptional(),
				references: facetAvailabilitySchema.exactOptional(),
				strings_names: facetAvailabilitySchema.exactOptional(),
				cfg: facetAvailabilitySchema.exactOptional()
			}).strict().exactOptional(),
			limitations: z.array(z.string())
		}).strict();
		parseFunctionDossier = (value) => {
			const parsed = functionDossierSchema.safeParse(value);
			return parsed.success ? ok(parsed.data) : err(new AnalysisOutputError("analyze_function", "provider output did not match the dossier contract", { cause: parsed.error }));
		};
		parseProcedures = (value, operation = "list_procedures") => {
			const parsed = procedureMapSchema.safeParse(unwrapProperty(value, "procedures"));
			return parsed.success ? ok(Object.entries(parsed.data).map(([address, name]) => ({
				address,
				name
			}))) : invalid(operation, "procedure map", parsed.error);
		};
		parseNames = (value, operation = "list_names") => {
			const unwrapped = unwrapProperty(value, "names");
			const records = addressedNamesSchema.safeParse(unwrapped);
			if (records.success) return ok(records.data);
			const map = addressedNameMapSchema.safeParse(unwrapped);
			return map.success ? ok(Object.entries(map.data).map(([address, name]) => ({
				address,
				name
			}))) : invalid(operation, "name list", map.error);
		};
		parseRelatedAddresses = (value, relation, operation = relation === "callees" ? "procedure_callees" : "procedure_callers") => {
			const parsed = z.array(z.string()).safeParse(unwrapProperty(value, relation));
			return parsed.success ? ok(parsed.data) : invalid(operation, `${relation} list`, parsed.error);
		};
		parseSegments = (value, operation = "list_segments") => {
			const parsed = z.array(segmentSchema).safeParse(unwrapProperty(value, "segments"));
			return parsed.success ? ok(parsed.data) : invalid(operation, "segment list", parsed.error);
		};
		parseSegmentImageBase = (segments) => {
			const base = segments[0]?.image_base;
			return base !== undefined && segments.every((segment) => segment.image_base === base) ? base : undefined;
		};
		projectBinaryOverview = (input) => {
			const { document, procedure_count, string_count, segments } = input;
			const imageBase = segments === undefined ? undefined : parseSegmentImageBase(segments);
			return {
				document,
				...imageBase === undefined ? {} : { image_base: imageBase },
				...segments === undefined ? {} : {
					segments: segments.map(({ name, start, end, image_base, address_space }) => ({
						name,
						start,
						end,
						length: addressDistance(start, end),
						...image_base === undefined ? {} : { image_base },
						...address_space === undefined ? {} : { address_space }
					})),
					segment_count: segments.length
				},
				procedure_count,
				string_count
			};
		};
		parseDocuments = (value, operation = "list_documents") => {
			const parsed = z.array(z.string()).safeParse(unwrapProperty(value, "documents"));
			return parsed.success ? ok(parsed.data) : invalid(operation, "document list", parsed.error);
		};
		parseListCount = (value, property, operation = property === "procedures" ? "list_procedures" : "list_strings") => {
			const unwrapped = unwrapProperty(value, property);
			const list = z.array(z.unknown()).safeParse(unwrapped);
			if (list.success) return ok(list.data.length);
			const map = z.record(z.string(), z.unknown()).safeParse(unwrapped);
			return map.success ? ok(Object.keys(map.data).length) : invalid(operation, `${property} list`, map.error);
		};
		unwrapProperty = (value, property) => {
			if (typeof value === "object" && value !== null && !Array.isArray(value) && property in value) {
				return value[property] ?? null;
			}
			return value;
		};
		invalid = (operation, expected, cause) => err(new AnalysisOutputError(operation, `Provider returned an invalid ${expected}`, { cause }));
	})))();
}

//#endregion
//#region dist/domain/native/nativeInstruction.js
var nativeInstructionInputSchema, reference, nativeInstructionSchema, nativeCallTargetsSchema;
function init_nativeInstruction() {
	return (init_nativeInstruction = __esmMin((() => {
		nativeInstructionInputSchema = z.strictObject({
			address: z.string().min(1),
			document: z.string().optional()
		});
		reference = z.strictObject({
			target_address: z.string(),
			type: z.string(),
			call: z.boolean(),
			jump: z.boolean(),
			indirect: z.boolean(),
			computed: z.boolean(),
			operand_index: z.number().int(),
			source_address: z.string().min(1).nullable().optional(),
			data: z.boolean().nullable().optional(),
			read: z.boolean().nullable().optional(),
			write: z.boolean().nullable().optional(),
			primary: z.boolean().nullable().optional().describe("Provider primary-reference status, not proof of literal addressing or a runtime access. Null or omission means unavailable."),
			provenance: z.string().min(1).nullable().optional().describe("Provider subsystem reporting this reference; null or omission means unavailable."),
			source: z.string().min(1).nullable().optional().describe("Provider reference origin, such as analysis, default, imported or user_defined; null or omission means unavailable.")
		});
		nativeInstructionSchema = z.strictObject({
			address: z.string(),
			status: z.enum([
				"decoded",
				"not-instruction-boundary",
				"data",
				"undecodable",
				"outside-memory"
			]),
			procedure: z.string().nullable(),
			architecture: z.string(),
			mode: z.string().describe("Provider-reported mode label. Per-address decoder context, when available, is reported separately; a program-wide label does not establish runtime encoding mode."),
			decoder_context: z.array(z.strictObject({
				register: z.string().min(1),
				value: z.string().min(1).nullable(),
				source: z.string().min(1)
			})).optional().describe("Observed per-address decoder context. Null means no value was available; omission means the provider or older capture does not expose this facet. The separate mode field retains the program language variant."),
			bytes: z.string().nullable(),
			length: z.number().int().positive().nullable(),
			mnemonic: z.string().nullable(),
			raw_disassembly: z.string().nullable(),
			operands: z.array(z.strictObject({
				index: z.number().int().nonnegative(),
				raw: z.string(),
				provider_type: z.number().int(),
				components: z.array(z.strictObject({
					kind: z.enum([
						"register",
						"immediate",
						"address",
						"unknown"
					]),
					text: z.string(),
					value: z.string().nullable(),
					bit_width: z.number().int().nonnegative().nullable()
				})),
				memory_addressing: z.literal("unavailable")
			})),
			flow: z.strictObject({
				kind: z.enum([
					"call",
					"jump",
					"return",
					"fallthrough",
					"terminal",
					"unavailable"
				]),
				conditional: z.boolean(),
				computed: z.boolean(),
				direct_destinations: z.array(z.string()),
				classification_evidence: z.array(z.strictObject({
					source: z.string().min(1),
					value: z.string().min(1)
				})).optional().describe("Observed provider facts used to classify flow; older captures or other providers may omit them.")
			}),
			references: z.array(reference),
			incoming_references: z.array(reference).nullable().optional().describe("Static references to this exact code or data address, excluding synthetic entry-point references. An empty array means the provider examined the address and found none; null or omission means unavailable. Analyzer references do not prove literal addressing or runtime access."),
			limitations: z.array(z.string())
		});
		nativeCallTargetsSchema = z.strictObject({
			call_site: z.string(),
			procedure: z.string().nullable(),
			status: z.enum([
				"direct",
				"resolved-indirect",
				"ambiguous",
				"unresolved",
				"not-call",
				"unavailable"
			]),
			mechanism: z.enum([
				"direct",
				"computed",
				"indirect",
				"unavailable"
			]),
			targets: z.array(z.strictObject({
				address: z.string(),
				procedure: z.string().nullable(),
				status: z.enum([
					"direct",
					"resolved-indirect",
					"candidate"
				]),
				basis: z.literal("provider-reference"),
				references: z.array(reference)
			})),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeInventory.js
var addressedValueSchema, nativeInventoryRowsSchemas, NATIVE_INVENTORY_OPERATIONS, nativeInventoryOperationSchema, isNativeInventoryOperation;
function init_nativeInventory() {
	return (init_nativeInventory = __esmMin((() => {
		init_hopperValues();
		addressedValueSchema = z.object({
			address: z.string(),
			value: z.string(),
			symbol: z.object({
				primary: z.boolean(),
				dynamic: z.boolean(),
				external: z.boolean(),
				type: z.string(),
				source: z.enum([
					"default",
					"analysis",
					"ai",
					"imported",
					"user_defined"
				])
			}).exactOptional(),
			objc_class_label: z.literal("hopper_legacy_class_object").exactOptional(),
			procedure: z.object({
				external: z.boolean(),
				thunk: z.boolean(),
				thunk_target: z.string().nullable()
			}).exactOptional(),
			string: z.object({
				encoding: z.string(),
				termination: z.enum(["missing", "present_or_not_required"]),
				byte_length: z.number().int().min(0)
			}).exactOptional()
		});
		nativeInventoryRowsSchemas = {
			names: z.array(addressedValueSchema),
			strings: z.array(analysisStringSchema)
		};
		NATIVE_INVENTORY_OPERATIONS = [
			"list_procedures",
			"search_procedures",
			"list_strings",
			"search_strings",
			"list_names"
		];
		nativeInventoryOperationSchema = z.enum(NATIVE_INVENTORY_OPERATIONS);
		isNativeInventoryOperation = (operation) => NATIVE_INVENTORY_OPERATIONS.some((supported) => supported === operation);
	})))();
}

//#endregion
//#region dist/domain/apple/bundleResourceRoot.js
var bundleResourceRootSchema, bundleResourceBoundResultSchema;
function init_bundleResourceRoot() {
	return (init_bundleResourceRoot = __esmMin((() => {
		bundleResourceRootSchema = z.strictObject({
			caller_path: z.string().min(1),
			canonical_path: z.string().min(1),
			info_plist_path: z.string().min(1),
			layout: z.enum(["contents", "root"]),
			executable_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable()
		});
		bundleResourceBoundResultSchema = (executableSha256, fields) => z.union([z.strictObject({
			target_sha256: executableSha256,
			resource_root: bundleResourceRootSchema.optional(),
			...fields
		}), z.strictObject({
			target_sha256: z.null(),
			resource_root: bundleResourceRootSchema,
			...fields
		})]);
	})))();
}

//#endregion
//#region dist/domain/apple/plistNumbers.js
var incompletePlistNumberLimitation, createPlistNumberCollector, createPlistNumberProjection;
function init_plistNumbers() {
	return (init_plistNumbers = __esmMin((() => {
		incompletePlistNumberLimitation = "Property-list number metadata could not be completely observed; decoded numbers may lose integer precision and exact integer/real association is unavailable.";
		createPlistNumberCollector = () => {
			const integers = new Map();
			const reals = new Set();
			let unsafeIntegerLiterals = 0;
			return {
				integer: (exact) => {
					if (exact >= BigInt(Number.MIN_SAFE_INTEGER) && exact <= BigInt(Number.MAX_SAFE_INTEGER)) return;
					unsafeIntegerLiterals++;
					const rounded = Number(exact);
					integers.set(rounded, (integers.get(rounded) ?? new Set()).add(exact.toString()));
				},
				real: (value) => {
					reals.add(value);
				},
				result: (incomplete = false) => ({
					integers,
					reals,
					unsafeIntegerLiterals,
					incomplete
				})
			};
		};
		createPlistNumberProjection = (literals) => {
			let exactIntegerCount = 0;
			let ambiguousNumberCount = 0;
			const mapNumber = (item) => {
				if (Number.isSafeInteger(item) || !Number.isInteger(item)) return item;
				if (literals.incomplete) {
					ambiguousNumberCount += 1;
					return item;
				}
				const decimals = literals.integers.get(item);
				if (decimals === undefined) {
					if (!literals.reals.has(item)) ambiguousNumberCount += 1;
					return item;
				}
				const [decimal] = decimals;
				if (decimals.size !== 1 || decimal === undefined || literals.reals.has(item)) {
					ambiguousNumberCount += 1;
					return item;
				}
				exactIntegerCount += 1;
				return {
					$plist_type: "integer",
					decimal
				};
			};
			const map = (item) => {
				if (typeof item === "number") return mapNumber(item);
				if (Array.isArray(item)) return item.map(map);
				if (item !== null && typeof item === "object") {
					const keys = Object.keys(item);
					const marker = item[keys[0] ?? ""];
					const reference = keys.length === 1 && (keys[0] === "UID" || keys[0] === "CF$UID") && typeof marker === "number";
					if (reference) {
						if (typeof marker === "number" && !Number.isSafeInteger(marker) && (literals.integers.has(marker) || !literals.reals.has(marker))) ambiguousNumberCount += 1;
						return item;
					}
					return Object.fromEntries(Object.entries(item).map(([key, child]) => [key, map(child)]));
				}
				return item;
			};
			return {
				project: map,
				limitations: () => [
					...literals.incomplete ? [incompletePlistNumberLimitation] : [],
					...literals.unsafeIntegerLiterals === 0 ? [] : [`${String(literals.unsafeIntegerLiterals)} observed integer literal(s) in the original archive exceed the exact range of a JSON number. Decoded numbers may lose integer precision unless represented as { "$plist_type": "integer", "decimal": "<exact digits>" }; the original archive bytes retain those literals.`],
					...exactIntegerCount === 0 ? [] : [`${String(exactIntegerCount)} unambiguous integer value(s) are reported with exact decimal text as { "$plist_type": "integer", "decimal": "<exact digits>" }.`],
					...ambiguousNumberCount === 0 ? [] : [`${String(ambiguousNumberCount)} number(s) beyond the exact integer range remain as decoded because their source integer/real type or reference marker cannot be associated unambiguously; integer precision loss remains possible.`]
				]
			};
		};
	})))();
}

//#endregion
//#region dist/domain/apple/interfaceBuilderKeyedArchive.js
var recordSchema, objectNode, connection, isUIKitRuntimeConnectionClass, isInterfaceBuilderConnectionClass, interfaceBuilderConnectionFieldNames, parseInterfaceBuilderRecords, archiveUid, HIERARCHY_KEY, keyedArchiveTable, parseKeyedArchive, record, firstString, archivedObjectReference, firstObjectReference, classifyObject, classifyConnection, jsonSafeRecord;
function init_interfaceBuilderKeyedArchive() {
	return (init_interfaceBuilderKeyedArchive = __esmMin((() => {
		init_jsonValue();
		recordSchema = z.record(z.string(), z.unknown());
		objectNode = z.strictObject({
			id: z.string().min(1),
			kind: z.enum([
				"view_controller",
				"view",
				"control",
				"constraint",
				"layout_guide",
				"resource",
				"placeholder",
				"external_object",
				"other"
			]),
			class_name: z.string().nullable(),
			name: z.string().min(1),
			attributes: z.record(z.string(), jsonValueSchema)
		});
		connection = z.strictObject({
			id: z.string().min(1),
			kind: z.enum([
				"outlet",
				"action",
				"segue",
				"other"
			]),
			source_id: z.string().min(1),
			destination_id: z.string().nullable(),
			label: z.string().nullable(),
			attributes: z.record(z.string(), jsonValueSchema)
		});
		isUIKitRuntimeConnectionClass = (className) => /^UIRuntime\w*Connection$/u.test(className);
		isInterfaceBuilderConnectionClass = (className) => isUIKitRuntimeConnectionClass(className) || /^NSNib(?:Connector|BindingConnector|ControlConnector|OutletConnector)$/u.test(className);
		interfaceBuilderConnectionFieldNames = (className) => isUIKitRuntimeConnectionClass(className) ? {
			source: "UISource",
			destination: "UIDestination",
			label: "UILabel"
		} : {
			source: "NSSource",
			destination: "NSDestination",
			label: "NSLabel"
		};
		parseInterfaceBuilderRecords = (value) => {
			const root = record(value);
			const keyed = parseKeyedArchive(root);
			if (keyed !== null) return keyed;
			const objectsRaw = record(root["com.apple.ibtool.document.objects"]);
			const connectionsRaw = record(root["com.apple.ibtool.document.connections"]);
			const hierarchyRaw = root["com.apple.ibtool.document.hierarchy"];
			const classesRaw = record(root["com.apple.ibtool.document.classes"]);
			const objects = [];
			const connections = [];
			let omittedConnections = 0;
			const objectEntries = Object.entries(objectsRaw);
			for (const [id, raw] of objectEntries.slice(0, 2e4)) {
				const attributes = record(raw);
				const className = firstString(attributes["customClass"], attributes["class"], attributes["isa"]);
				const label = firstString(attributes["label"], attributes["title"], attributes["name"], className);
				const carried = new Set();
				if (attributes["customClass"] === className) carried.add("customClass");
				if (attributes["label"] === label) carried.add("label");
				if (attributes["objectID"] === id) carried.add("objectID");
				objects.push(objectNode.parse({
					id,
					kind: classifyObject(className),
					class_name: className,
					name: label ?? id,
					attributes: jsonSafeRecord(Object.fromEntries(Object.entries(attributes).filter(([key]) => !carried.has(key))))
				}));
			}
			for (const [sourceId, rawConnections] of Object.entries(connectionsRaw)) {
				if (!Array.isArray(rawConnections)) continue;
				for (const [index, raw] of rawConnections.entries()) {
					if (connections.length >= 4e4) {
						omittedConnections += rawConnections.length - index;
						break;
					}
					const item = record(raw);
					const type = firstString(item.type, item.connectionType) ?? "unknown";
					const destination = firstString(item["destination-id"], item.destinationId);
					const label = firstString(item.label, item.selector, item.identifier);
					connections.push(connection.parse({
						id: `${sourceId}:connection:${index}`,
						kind: classifyConnection(type),
						source_id: sourceId,
						destination_id: destination,
						label,
						attributes: jsonSafeRecord(item)
					}));
				}
			}
			return {
				objects,
				connections,
				hierarchy: Array.isArray(hierarchyRaw) ? hierarchyRaw : [],
				classes: classesRaw,
				objectCount: objectEntries.length,
				omittedObjects: Math.max(0, objectEntries.length - 2e4),
				omittedConnections,
				unresolvedConnections: 0,
				omittedHierarchyReferences: 0
			};
		};
		archiveUid = (value) => {
			if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
			if (Object.keys(value).length !== 1) return undefined;
			const item = record(value);
			const marker = Object.hasOwn(item, "UID") ? item.UID : item["CF$UID"];
			return typeof marker === "number" && Number.isInteger(marker) ? marker : undefined;
		};
		HIERARCHY_KEY = /(?:subviews|contentview|childviewcontrollers|children|views)$/iu;
		keyedArchiveTable = (objectTable) => {
			const classFactsByUid = new Map();
			const parseClassFacts = (value) => {
				const descriptor = record(value);
				const rawSuperclasses = Array.isArray(descriptor.$classes) ? descriptor.$classes : [];
				if (!Object.hasOwn(descriptor, "$classname") && rawSuperclasses.length === 0) return null;
				return {
					name: firstString(descriptor.$classname),
					rawSuperclasses,
					superclasses: rawSuperclasses.filter((name) => typeof name === "string")
				};
			};
			const classFactsForUid = (uid) => {
				const cached = classFactsByUid.get(uid);
				if (cached !== undefined) return cached;
				if (!Number.isInteger(uid) || uid < 0 || uid >= objectTable.length) return null;
				const facts = parseClassFacts(objectTable[uid]);
				if (facts !== null) classFactsByUid.set(uid, facts);
				return facts;
			};
			const classFactsOfReference = (reference) => {
				const uid = archiveUid(reference);
				return uid === undefined ? parseClassFacts(reference) : classFactsForUid(uid);
			};
			const classFactsOfObject = (value) => classFactsOfReference(record(value).$class);
			const classNameOf = (value) => classFactsOfObject(value)?.name ?? null;
			const hasClassSuperclass = (value, superclass) => classFactsOfObject(value)?.superclasses.includes(superclass) ?? false;
			/** The string an archived string object holds, if it is one. */
			const archivedString = (target) => {
				if (typeof target === "string") return target;
				const text = record(target)["NS.string"];
				return typeof text === "string" && /^NS(?:Mutable)?String$/u.test(classNameOf(target) ?? "") ? text : undefined;
			};
			const text = (value) => {
				const uid = archiveUid(value);
				return firstString(uid === undefined ? value : archivedString(objectTable[uid]));
			};
			const authoredId = (item) => firstString(text(item.objectID), text(item["object-id"]));
			const reference = (uid) => {
				const target = uid === 0 ? null : objectTable[uid];
				if (target === undefined || target === null) return null;
				if (typeof target !== "object") return target;
				const string = archivedString(target);
				if (string !== undefined) return string;
				const objectId = authoredId(record(target));
				return {
					archiveUID: uid,
					...objectId === null ? {} : { objectID: objectId },
					className: classNameOf(target)
				};
			};
			/** Resolve one object's own fields, leaving references to other objects as stubs. */
			const resolve = (value) => {
				const uid = archiveUid(value);
				if (uid !== undefined) return reference(uid);
				if (Array.isArray(value)) return value.map(resolve);
				if (typeof value !== "object" || value === null) return value;
				const output = {};
				for (const [key, child] of Object.entries(value)) {
					if (key === "$class") output.className = classNameOf(value);
					else output[key] = resolve(child);
				}
				return output;
			};
			const hierarchy = (start) => {
				let omittedReferences = 0;
				const visited = new Set();
				const root = [];
				const pending = [{
					value: start,
					output: root
				}];
				const appendNode = (item, uid, output) => {
					const objectId = firstString(authoredId(item), text(item.id), uid === undefined ? null : String(uid));
					if (objectId === null) {
						for (const [key, child] of Object.entries(item).reverse()) if (HIERARCHY_KEY.test(key)) pending.push({
							value: child,
							output
						});
						return;
					}
					const children = [];
					output.push({
						objectID: objectId,
						children
					});
					for (const [key, child] of Object.entries(item).reverse()) if (HIERARCHY_KEY.test(key)) pending.push({
						value: child,
						output: children
					});
				};
				while (pending.length > 0) {
					const entry = pending.pop();
					if (entry === undefined) break;
					const { value, output } = entry;
					const uid = archiveUid(value);
					if (uid !== undefined) {
						if (uid === 0) continue;
						const target = objectTable[uid];
						if (target === undefined) {
							omittedReferences += 1;
							continue;
						}
						if (visited.has(uid)) continue;
						visited.add(uid);
						if (Array.isArray(target)) {
							for (let index = target.length - 1; index >= 0; index -= 1) {
								const child = target[index];
								if (child !== undefined) pending.push({
									value: child,
									output
								});
							}
							continue;
						}
						if (typeof target !== "object" || target === null) continue;
						const item = record(target);
						if (archivedArrayClass(item.$class)) {
							const members = item["NS.objects"];
							if (Array.isArray(members)) for (let index = members.length - 1; index >= 0; index -= 1) {
								const child = members[index];
								if (child !== undefined) pending.push({
									value: child,
									output
								});
							}
							continue;
						}
						appendNode(item, uid, output);
						continue;
					}
					if (Array.isArray(value)) {
						for (let index = value.length - 1; index >= 0; index -= 1) {
							const child = value[index];
							if (child !== undefined) pending.push({
								value: child,
								output
							});
						}
					} else if (typeof value === "object" && value !== null) {
						appendNode(record(value), undefined, output);
					}
				}
				return {
					items: root,
					omittedReferences
				};
			};
			const archivedArrayClass = (classReference) => {
				const superclasses = classFactsOfReference(classReference)?.superclasses ?? [];
				return superclasses.includes("NSArray") || superclasses.includes("NSMutableArray");
			};
			const classTable = () => Object.fromEntries(objectTable.flatMap((_, uid) => {
				const facts = classFactsForUid(uid);
				return facts === null || facts.name === null ? [] : [[facts.name, { superclasses: facts.rawSuperclasses }]];
			}));
			return {
				resolve,
				hierarchy,
				hasClassSuperclass,
				classTable
			};
		};
		parseKeyedArchive = (root) => {
			if (root.$archiver !== "NSKeyedArchiver" || !Array.isArray(root.$objects)) return null;
			const objectTable = root.$objects;
			const { resolve, hierarchy: toHierarchy, hasClassSuperclass, classTable } = keyedArchiveTable(objectTable);
			const objects = [];
			const connections = [];
			let objectCount = 0;
			let omittedConnections = 0;
			let unresolvedConnections = 0;
			for (const [index, raw] of objectTable.entries()) {
				if (index === 0) continue;
				const resolved = record(resolve(raw));
				const className = firstString(resolved.className);
				if (className === null && !Object.hasOwn(record(raw), "$class")) continue;
				objectCount += 1;
				const fields = Object.fromEntries(Object.entries(resolved).filter(([key]) => key !== "className"));
				if (className === null) fields.$class = record(raw).$class;
				const authoredId = firstString(fields.objectID, fields["object-id"]);
				const objectId = authoredId ?? (typeof fields.archiveUID === "number" ? String(fields.archiveUID) : String(index));
				const kind = classifyObject(className);
				if (objects.length < 2e4) objects.push(objectNode.parse({
					id: objectId,
					kind,
					class_name: className,
					name: firstString(fields.label, fields.title, fields.identifier, fields.accessibilityLabel, className) ?? `object ${String(index)}`,
					attributes: jsonSafeRecord(fields)
				}));
				if (className !== null && (isInterfaceBuilderConnectionClass(className) || hasClassSuperclass(raw, "NSNibConnector"))) {
					const controlAction = /ControlConnector/iu.test(className);
					const uiKit = isUIKitRuntimeConnectionClass(className);
					const connectionFields = interfaceBuilderConnectionFieldNames(className);
					const source = uiKit ? archivedObjectReference(fields[connectionFields.source]) : firstObjectReference(controlAction ? fields.destination : fields.source, archivedObjectReference(fields[connectionFields.source]), controlAction ? fields.to : fields.from, controlAction ? fields.target : fields.owner);
					if (source === null) {
						unresolvedConnections += 1;
						continue;
					}
					const kind = controlAction ? "action" : classifyConnection(className);
					const parsedConnection = connection.parse({
						id: `archive:${objectId}`,
						kind,
						source_id: source,
						destination_id: uiKit ? archivedObjectReference(fields[connectionFields.destination]) : firstObjectReference(controlAction ? fields.source : fields.destination, archivedObjectReference(fields[connectionFields.destination]), controlAction ? fields.from : fields.to, controlAction ? fields.owner : fields.target),
						label: uiKit ? firstString(fields[connectionFields.label]) : firstString(fields.label, fields[connectionFields.label], fields.selector, fields.identifier, fields.action),
						attributes: jsonSafeRecord(fields)
					});
					if (connections.length < 4e4) connections.push(parsedConnection);
					else omittedConnections += 1;
				}
			}
			const top = record(root.$top);
			const hierarchy = toHierarchy(top.root ?? top.UITopLevelObjectsKey);
			const classes = classTable();
			return {
				objects,
				connections,
				hierarchy: hierarchy.items,
				classes,
				objectCount,
				omittedObjects: Math.max(0, objectCount - 2e4),
				omittedConnections,
				unresolvedConnections,
				omittedHierarchyReferences: hierarchy.omittedReferences
			};
		};
		record = (value) => recordSchema.safeParse(value).data ?? {};
		firstString = (...values) => {
			for (const value of values) if (typeof value === "string" && value.length > 0) return value;
			return null;
		};
		archivedObjectReference = (value) => {
			const item = record(value);
			if (typeof item.archiveUID !== "number") return null;
			return firstString(item.objectID, item["object-id"]) ?? String(item.archiveUID);
		};
		firstObjectReference = (...values) => {
			for (const value of values) {
				const direct = firstString(value);
				if (direct !== null) return direct;
				const item = record(value);
				const objectId = firstString(item.objectID, item["object-id"], item.id, item.identifier, typeof item.archiveUID === "number" ? String(item.archiveUID) : null);
				if (objectId !== null) return objectId;
			}
			return null;
		};
		classifyObject = (className) => {
			const value = className?.toLowerCase() ?? "";
			if (value.includes("constraint")) return "constraint";
			if (value.includes("layoutguide")) return "layout_guide";
			if (value.includes("placeholder") || value.includes("firstresponder") || value === "uiproxyobject") return "placeholder";
			if (value.includes("image") || value.includes("color") || value.includes("font")) return "resource";
			if (value.includes("external")) return "external_object";
			if (value.includes("viewcontroller") || value.includes("windowcontroller")) return "view_controller";
			if (value.includes("button") || value.includes("control") || value.includes("textfield") || value.includes("slider") || value.includes("menuitem")) return "control";
			if (value.includes("view") || value.includes("window") || value.includes("cell")) return "view";
			return "other";
		};
		classifyConnection = (type) => {
			const value = type.toLowerCase();
			if (value.includes("outlet")) return "outlet";
			if (value.includes("action") || value.includes("eventconnection")) return "action";
			if (value.includes("segue")) return "segue";
			return "other";
		};
		jsonSafeRecord = (value) => Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
			try {
				const serialized = JSON.stringify(item);
				if (serialized === undefined) return [];
				const parsed = jsonValueSchema.safeParse(JSON.parse(serialized));
				return parsed.success ? [[key, parsed.data]] : [];
			} catch (cause) {
				void cause;
				return [];
			}
		}));
	})))();
}

//#endregion
//#region dist/domain/native/nativeInvestigationGraph.js
var nativeInvestigationNodeKindSchema, nativeInvestigationNodeSchema, nativeInvestigationRelationSchema, nativeInvestigationEdgeSchema, nativeInvestigationCoverageSchema, nativeInvestigationProviderSchema, nativeInvestigationGraphSchema, nativeInvestigationTraceLimitsSchema, nativeInvestigationTraceSchema, traceNativeInvestigationGraph, joinInterfaceBuilderDispatch;
function init_nativeInvestigationGraph() {
	return (init_nativeInvestigationGraph = __esmMin((() => {
		init_objcSwiftMetadata();
		init_jsonValue();
		nativeInvestigationNodeKindSchema = z.enum([
			"storyboard",
			"scene",
			"view_controller",
			"view",
			"control",
			"constraint",
			"layout_guide",
			"resource",
			"placeholder",
			"external_object",
			"outlet",
			"action",
			"segue",
			"objc_class",
			"objc_selector",
			"swift_declaration",
			"swift_requirement",
			"dispatch_table",
			"dispatch_slot",
			"thunk",
			"function",
			"state_value",
			"global_value",
			"field",
			"branch_condition",
			"sink",
			"unknown"
		]);
		nativeInvestigationNodeSchema = z.strictObject({
			id: z.string().min(1),
			kind: nativeInvestigationNodeKindSchema,
			name: z.string().min(1),
			location: nativeMetadataLocationSchema.nullable(),
			attributes: z.record(z.string(), jsonValueSchema),
			evidence: z.array(nativeMetadataEvidenceSchema)
		});
		nativeInvestigationRelationSchema = z.enum([
			"contains",
			"outlet_to",
			"target_action",
			"segue_to",
			"objc_dispatch",
			"swift_witness_dispatch",
			"swift_vtable_dispatch",
			"thunk_to",
			"direct_call",
			"indirect_call",
			"provider_call",
			"reads",
			"writes",
			"flows_to",
			"controls"
		]);
		nativeInvestigationEdgeSchema = z.discriminatedUnion("resolution", [z.strictObject({
			id: z.string().min(1),
			from: z.string().min(1),
			to: z.string().min(1),
			relation: nativeInvestigationRelationSchema,
			resolution: z.enum([
				"observed",
				"inferred",
				"resolved",
				"ambiguous"
			]),
			evidence: z.array(nativeMetadataEvidenceSchema).min(1),
			limitations: z.array(z.string())
		}), z.strictObject({
			id: z.string().min(1),
			from: z.string().min(1),
			to: z.null(),
			relation: nativeInvestigationRelationSchema,
			resolution: z.literal("unresolved"),
			reason: z.string().min(1),
			evidence: z.array(nativeMetadataEvidenceSchema),
			limitations: z.array(z.string())
		})]);
		nativeInvestigationCoverageSchema = z.strictObject({
			facet: z.string().min(1),
			status: z.enum([
				"complete",
				"partial",
				"unsupported",
				"not_requested"
			]),
			reason: z.string().nullable(),
			examined: z.number().int().nonnegative(),
			omitted: z.number().int().nonnegative()
		});
		nativeInvestigationProviderSchema = z.strictObject({
			id: z.string().min(1),
			version: z.string().nullable(),
			tool_version: z.string().min(1)
		});
		nativeInvestigationGraphSchema = z.strictObject({
			target_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable(),
			provider: nativeInvestigationProviderSchema,
			nodes: z.array(nativeInvestigationNodeSchema),
			edges: z.array(nativeInvestigationEdgeSchema),
			coverage: z.array(nativeInvestigationCoverageSchema),
			truncated: z.boolean()
		});
		nativeInvestigationTraceLimitsSchema = z.strictObject({
			max_depth: z.number().int().min(0).max(32).default(8),
			max_nodes: z.number().int().min(1).max(2e3).default(250),
			max_edges: z.number().int().min(1).max(5e3).default(500)
		});
		nativeInvestigationTraceSchema = z.strictObject({
			target_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable(),
			provider: nativeInvestigationProviderSchema,
			start: z.string().min(1),
			direction: z.enum(["forward", "backward"]),
			nodes: z.array(nativeInvestigationNodeSchema),
			edges: z.array(nativeInvestigationEdgeSchema),
			unresolved: z.array(nativeInvestigationEdgeSchema),
			reached_depth: z.number().int().nonnegative(),
			truncated: z.boolean(),
			reason: z.string().nullable(),
			coverage: z.array(nativeInvestigationCoverageSchema),
			limitations: z.array(z.string().min(1))
		});
		traceNativeInvestigationGraph = (graph, input) => {
			const start = graph.nodes.find(({ id }) => id === input.start);
			if (start === undefined) return {
				target_sha256: graph.target_sha256,
				provider: graph.provider,
				start: input.start,
				direction: input.direction ?? "forward",
				nodes: [],
				edges: [],
				unresolved: [],
				reached_depth: 0,
				truncated: false,
				reason: "start_node_missing",
				coverage: graph.coverage,
				limitations: ["The requested start node is absent from the supplied graph."]
			};
			const limits = nativeInvestigationTraceLimitsSchema.parse(input.limits ?? {});
			const direction = input.direction ?? "forward";
			const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
			const visited = new Set([start.id]);
			const selectedEdges = new Map();
			const unresolved = new Map();
			const queue = [{
				id: start.id,
				depth: 0
			}];
			let reachedDepth = 0;
			let truncated = false;
			let reason = null;
			const adjacency = new Map();
			for (const edge of graph.edges) {
				const nodeId = direction === "forward" ? edge.from : edge.to;
				if (nodeId === null) continue;
				const entries = adjacency.get(nodeId);
				if (entries === undefined) adjacency.set(nodeId, [edge]);
				else entries.push(edge);
			}
			while (queue.length > 0) {
				const current = queue.shift();
				if (current === undefined) break;
				const adjacent = adjacency.get(current.id) ?? [];
				for (const edge of adjacent) {
					if (selectedEdges.size + unresolved.size >= limits.max_edges) {
						truncated = true;
						reason = "max_edges_reached";
						break;
					}
					if (edge.resolution === "unresolved") {
						unresolved.set(edge.id, edge);
						continue;
					}
					const nextId = direction === "forward" ? edge.to : edge.from;
					const alreadyVisited = visited.has(nextId);
					if (!alreadyVisited && current.depth >= limits.max_depth) {
						truncated = true;
						reason ??= "max_depth_reached";
						continue;
					}
					if (!alreadyVisited && visited.size >= limits.max_nodes) {
						truncated = true;
						reason = "max_nodes_reached";
						break;
					}
					selectedEdges.set(edge.id, edge);
					if (alreadyVisited) continue;
					if (!nodeById.has(nextId)) {
						truncated = true;
						reason ??= "edge_target_missing_from_graph";
						continue;
					}
					visited.add(nextId);
					reachedDepth = Math.max(reachedDepth, current.depth + 1);
					queue.push({
						id: nextId,
						depth: current.depth + 1
					});
				}
				if (reason === "max_edges_reached" || reason === "max_nodes_reached") break;
			}
			return {
				target_sha256: graph.target_sha256,
				provider: graph.provider,
				start: start.id,
				direction,
				nodes: [...visited].flatMap((id) => {
					const node = nodeById.get(id);
					return node === undefined ? [] : [node];
				}),
				edges: [...selectedEdges.values()],
				unresolved: [...unresolved.values()],
				reached_depth: reachedDepth,
				truncated,
				reason,
				coverage: graph.coverage,
				limitations: ["Static analysis does not prove that an authored UI action is reachable or executed at runtime.", "Provider call graphs may omit unresolved indirect dispatch."]
			};
		};
		joinInterfaceBuilderDispatch = (graph, metadata) => {
			const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
			const edges = [...graph.edges];
			const existingEdgeIds = new Set(edges.map(({ id }) => id));
			const selectorNodesByAction = new Map();
			for (const edge of edges) {
				if (edge.resolution === "observed" && edge.relation === "target_action" && nodes.get(edge.to)?.kind === "objc_selector") selectorNodesByAction.set(edge.from, edge.to);
			}
			let examined = 0;
			let resolved = 0;
			let inferredWithoutOwnerClass = 0;
			for (const action of nodes.values()) {
				if (action.kind !== "action") continue;
				const selector = action.attributes.selector;
				if (typeof selector !== "string" || selector.length === 0) continue;
				const selectorNodeId = selectorNodesByAction.get(action.id);
				if (selectorNodeId === undefined) continue;
				const destinationEdge = edges.find((edge) => edge.resolution === "observed" && edge.relation === "target_action" && edge.from === action.id && [
					"view_controller",
					"placeholder",
					"external_object"
				].includes(nodes.get(edge.to)?.kind ?? ""));
				if (destinationEdge === undefined || destinationEdge.resolution !== "observed") continue;
				const owner = nodes.get(destinationEdge.to);
				examined += 1;
				const declaredClass = owner?.attributes.class_name;
				const className = typeof declaredClass === "string" && declaredClass.length > 0 && owner?.kind === "view_controller" ? declaredClass : null;
				const candidates = metadata.objc_dispatch_implementations.filter((candidate) => candidate.method_type === "instance" && candidate.selector === selector && (className === null || candidate.class_name.replace(/\([^)]*\)$/u, "") === className));
				const implementation = candidates.length === 1 ? candidates[0] : undefined;
				const edgeId = `dispatch:${selectorNodeId}:${className ?? owner?.id ?? "unknown"}:${selector}`;
				if (existingEdgeIds.has(edgeId)) continue;
				existingEdgeIds.add(edgeId);
				if (implementation === undefined || implementation.implementation_address === null) {
					edges.push({
						id: edgeId,
						from: selectorNodeId,
						to: null,
						relation: "objc_dispatch",
						resolution: "unresolved",
						reason: candidates.length > 1 ? "selector_has_multiple_candidate_implementations" : "implementation_not_resolved_from_binary_metadata_or_provider_symbols",
						evidence: [...action.evidence, ...candidates.flatMap(({ evidence }) => evidence)],
						limitations: ["A missing or ambiguous symbol match does not prove that the runtime implementation is absent."]
					});
					continue;
				}
				const functionId = `native:function:${implementation.implementation_address}`;
				if (!nodes.has(functionId)) nodes.set(functionId, {
					id: functionId,
					kind: "function",
					name: `${implementation.class_name} ${selector}`,
					location: {
						address: implementation.implementation_address,
						file_offset: implementation.location.file_offset
					},
					attributes: {
						class_name: implementation.class_name,
						selector,
						method_type: implementation.method_type
					},
					evidence: implementation.evidence
				});
				edges.push({
					id: edgeId,
					from: selectorNodeId,
					to: functionId,
					relation: "objc_dispatch",
					resolution: className !== null && implementation.decode.status === "decoded" ? "resolved" : "inferred",
					evidence: [...action.evidence, ...implementation.evidence],
					limitations: className === null ? ["The selector uniquely matches a encoded or symbolized method, but the Interface Builder receiver is an unresolved placeholder; runtime dispatch was not observed."] : ["The Interface Builder target and encoded or symbolized method agree on class and selector; runtime dispatch and dynamically supplied targets were not observed."]
				});
				resolved += 1;
				if (className === null) inferredWithoutOwnerClass += 1;
			}
			return nativeInvestigationGraphSchema.parse({
				...graph,
				provider: {
					id: "rea-native-investigation",
					version: null,
					tool_version: "rea-native-investigation/1"
				},
				nodes: [...nodes.values()],
				edges,
				coverage: [...graph.coverage, {
					facet: "ui_to_objc_dispatch",
					status: examined === resolved && inferredWithoutOwnerClass === 0 ? "complete" : "partial",
					reason: examined === resolved && inferredWithoutOwnerClass === 0 ? null : inferredWithoutOwnerClass > 0 ? "some_action_receivers_remain_placeholders" : "some_action_implementations_not_resolved",
					examined,
					omitted: examined - resolved + inferredWithoutOwnerClass
				}]
			});
		};
	})))();
}

//#endregion
//#region dist/domain/apple/interfaceBuilderGraph.js
var interfaceBuilderDocumentSchema, interfaceBuilderAnalysisSchema, buildInterfaceBuilderAnalysis, interfaceBuilderLimitsSchema;
function init_interfaceBuilderGraph() {
	return (init_interfaceBuilderGraph = __esmMin((() => {
		init_bundleResourceRoot();
		init_plistNumbers();
		init_interfaceBuilderKeyedArchive();
		init_nativeInvestigationGraph();
		interfaceBuilderDocumentSchema = z.strictObject({
			relative_path: z.string().min(1),
			archive_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			document_kind: z.enum(["nib", "storyboard_scene"]),
			object_count: z.number().int().nonnegative(),
			connection_count: z.number().int().nonnegative(),
			hierarchy_complete: z.boolean()
		});
		interfaceBuilderAnalysisSchema = bundleResourceBoundResultSchema(z.string().regex(/^[a-f0-9]{64}$/u), {
			documents: z.array(interfaceBuilderDocumentSchema).max(64),
			graph: nativeInvestigationGraphSchema,
			limitations: z.array(z.string())
		});
		buildInterfaceBuilderAnalysis = (input) => {
			const nodes = new Map();
			const edges = [];
			const coverage = [];
			const summaries = [];
			const numberLimitations = [];
			let truncated = false;
			let omittedObjects = 0;
			let omittedConnections = 0;
			let omittedGraphNodes = 0;
			let omittedHierarchyReferences = 0;
			for (const document of input.documents.slice(0, input.limits.max_documents)) {
				const parsed = parseInterfaceBuilderRecords(document.raw);
				const numbers = document.numberLiterals === undefined ? undefined : createPlistNumberProjection(document.numberLiterals);
				const prefix = `ib:${JSON.stringify(document.relativePath)}:`;
				const graphId = (kind, parts = []) => `${prefix}${kind}:${JSON.stringify(parts)}`;
				const rootId = `${prefix}root`;
				const objectIds = new Set(parsed.objects.map(({ id }) => id));
				const evidenceFor = (description) => [{
					kind: "interface_builder_resource",
					description,
					location: {
						address: null,
						file_offset: null
					},
					artifact_path: document.relativePath,
					artifact_sha256: document.archiveSha256
				}];
				const addNode = (node) => {
					if (nodes.has(node.id)) return true;
					if (nodes.size >= input.limits.max_objects) {
						truncated = true;
						omittedGraphNodes += 1;
						return false;
					}
					nodes.set(node.id, numbers === undefined ? node : {
						...node,
						attributes: Object.fromEntries(Object.entries(node.attributes).map(([key, value]) => [key, numbers.project(value)]))
					});
					return true;
				};
				const rootNode = {
					id: rootId,
					kind: document.documentKind === "nib" ? "scene" : "storyboard",
					name: document.relativePath,
					location: null,
					attributes: { document_kind: document.documentKind },
					evidence: evidenceFor("compiled document")
				};
				addNode(rootNode);
				let documentObjectCount = 0;
				for (const object of parsed.objects.slice(0, input.limits.max_objects)) {
					const id = graphId("object", [object.id]);
					const kind = object.kind === "other" ? "unknown" : object.kind;
					if (!addNode({
						id,
						kind,
						name: object.name,
						location: null,
						attributes: {
							...object.attributes,
							interface_builder_object_id: object.id,
							class_name: object.class_name
						},
						evidence: evidenceFor(`object ${object.id}`)
					})) {
						break;
					}
					documentObjectCount += 1;
				}
				let connectionEdgeCount = 0;
				let hierarchyEdgeCount = 0;
				let documentOmittedConnections = 0;
				let documentOmittedHierarchyEdges = 0;
				let hierarchyTruncated = false;
				const objectNodeId = (objectId) => graphId("object", [objectId]);
				const addEdge = (edge, isHierarchy) => {
					if (isHierarchy ? hierarchyEdgeCount >= input.limits.max_objects : connectionEdgeCount >= input.limits.max_connections * 3) {
						truncated = true;
						if (isHierarchy) {
							hierarchyTruncated = true;
							documentOmittedHierarchyEdges += 1;
						} else {
							omittedConnections += 1;
							documentOmittedConnections += 1;
						}
						return;
					}
					edges.push(edge);
					if (isHierarchy) hierarchyEdgeCount += 1;
					else connectionEdgeCount += 1;
				};
				const connect = (id, from, to, relation, description, reason) => {
					const isHierarchy = relation === "contains" && id.includes(":hierarchy:");
					if (!nodes.has(from)) {
						truncated = true;
						if (isHierarchy) {
							hierarchyTruncated = true;
							documentOmittedHierarchyEdges += 1;
						} else {
							omittedConnections += 1;
							documentOmittedConnections += 1;
						}
						return;
					}
					const evidence = evidenceFor(description);
					const unresolvedEndpoint = to !== null && !nodes.has(to);
					if (unresolvedEndpoint) {
						truncated = true;
						if (isHierarchy) hierarchyTruncated = true;
					}
					const edgeTo = unresolvedEndpoint ? null : to;
					const edgeReason = unresolvedEndpoint ? "endpoint_omitted_by_object_limit" : reason ?? "destination_unresolved";
					addEdge(edgeTo === null ? {
						id,
						from,
						to: null,
						relation,
						resolution: "unresolved",
						reason: edgeReason,
						evidence,
						limitations: []
					} : {
						id,
						from,
						to: edgeTo,
						relation,
						resolution: "observed",
						evidence,
						limitations: []
					}, isHierarchy);
				};
				let hierarchyCount = 0;
				let documentOmittedHierarchyNodes = 0;
				const visitHierarchy = (initial, initialParentId) => {
					const pending = [{
						value: initial,
						parentId: initialParentId
					}];
					while (pending.length > 0) {
						const entry = pending.pop();
						if (entry === undefined) break;
						const { value, parentId } = entry;
						if (Array.isArray(value)) {
							for (let index = value.length - 1; index >= 0; index -= 1) {
								const child = value[index];
								if (child !== undefined) pending.push({
									value: child,
									parentId
								});
							}
							continue;
						}
						if (typeof value !== "object" || value === null) continue;
						const item = record(value);
						const objectId = firstString(item.objectID, item["object-id"], item.id, typeof item.archiveUID === "number" ? String(item.archiveUID) : null);
						let nextParent = parentId;
						if (objectId !== null && hierarchyCount >= input.limits.max_objects) {
							truncated = true;
							hierarchyTruncated = true;
							documentOmittedHierarchyNodes += 1;
						} else if (objectId !== null) {
							const known = objectIds.has(objectId);
							const childId = known ? objectNodeId(objectId) : graphId("unknown", [objectId]);
							if (!known && !addNode({
								id: childId,
								kind: "unknown",
								name: firstString(item.label, item.name) ?? objectId,
								location: null,
								attributes: { interface_builder_object_id: objectId },
								evidence: evidenceFor(`hierarchy item ${objectId}`)
							})) hierarchyTruncated = true;
							connect(graphId("hierarchy", [parentId, childId]), parentId, childId, "contains", `hierarchy ${objectId}`);
							nextParent = childId;
							hierarchyCount += 1;
						}
						pending.push({
							value: item.children,
							parentId: nextParent
						});
					}
				};
				for (const hierarchy of parsed.hierarchy) visitHierarchy(hierarchy, rootId);
				for (const [index, item] of parsed.connections.slice(0, input.limits.max_connections).entries()) {
					const sourceId = objectNodeId(item.source_id);
					if (!nodes.has(sourceId)) addNode({
						id: sourceId,
						kind: "unknown",
						name: item.source_id,
						location: null,
						attributes: { interface_builder_object_id: item.source_id },
						evidence: evidenceFor(`connection source ${item.source_id}`)
					});
					const destinationId = item.destination_id === null ? null : objectNodeId(item.destination_id);
					if (item.kind === "action") {
						const actionId = graphId("action", [item.id]);
						const selectorId = item.label === null ? null : graphId("selector", [item.destination_id, item.label]);
						addNode({
							id: actionId,
							kind: "action",
							name: item.label ?? "unlabeled action",
							location: null,
							attributes: {
								selector: item.label,
								destination_id: item.destination_id,
								...item.attributes
							},
							evidence: evidenceFor(`action ${item.id}`)
						});
						connect(graphId("action-edge", [item.id, "source"]), sourceId, actionId, "target_action", `action source ${item.source_id}`);
						if (selectorId !== null) {
							addNode({
								id: selectorId,
								kind: "objc_selector",
								name: item.label ?? "unknown selector",
								location: null,
								attributes: { destination_id: item.destination_id },
								evidence: evidenceFor(`selector ${item.label}`)
							});
							connect(graphId("action-edge", [item.id, "selector"]), actionId, selectorId, "target_action", `selector ${item.label}`);
						}
						if (destinationId === null || !nodes.has(destinationId)) connect(graphId("action-edge", [item.id, "destination"]), actionId, null, "target_action", `action destination ${item.destination_id ?? "missing"}`, "destination_object_missing_or_external");
						else connect(graphId("action-edge", [item.id, "destination"]), actionId, destinationId, "target_action", `action destination ${item.destination_id}`);
					} else if (item.kind === "outlet") {
						const outletId = graphId("outlet", [item.id]);
						addNode({
							id: outletId,
							kind: "outlet",
							name: item.label ?? item.id,
							location: null,
							attributes: item.attributes,
							evidence: evidenceFor(`outlet ${item.id}`)
						});
						connect(graphId("outlet-edge", [item.id, "source"]), sourceId, outletId, "contains", `outlet source ${item.source_id}`);
						if (destinationId === null || !nodes.has(destinationId)) connect(graphId("outlet-edge", [item.id, "destination"]), outletId, null, "outlet_to", `outlet ${item.label ?? item.id}`, "destination_object_missing_or_external");
						else connect(graphId("outlet-edge", [item.id, "destination"]), outletId, destinationId, "outlet_to", `outlet ${item.label ?? item.id}`);
					} else if (item.kind === "segue") {
						if (destinationId === null || !nodes.has(destinationId)) connect(graphId("segue", [index]), sourceId, null, "segue_to", `segue ${item.label ?? item.id}`, "destination_scene_missing");
						else connect(graphId("segue", [index]), sourceId, destinationId, "segue_to", `segue ${item.label ?? item.id}`);
					} else {
						connect(graphId("unknown-connection", [index]), sourceId, null, "contains", `connection type ${item.kind}`, "unsupported_connection_type");
					}
				}
				const objectsTruncated = parsed.omittedObjects > 0 || parsed.objects.length > documentObjectCount;
				const parserOmittedHierarchyReferences = parsed.omittedHierarchyReferences;
				const omittedSerializedHierarchyReferences = document.omittedSerializedHierarchyReferences ?? 0;
				omittedHierarchyReferences += parserOmittedHierarchyReferences + omittedSerializedHierarchyReferences;
				const parserOmittedConnections = parsed.omittedConnections;
				const connectionsTruncated = parserOmittedConnections > 0 || parsed.connections.length > input.limits.max_connections;
				const connectionsUnresolved = parsed.unresolvedConnections > 0;
				const unsupportedConnections = parsed.connections.some(({ kind }) => kind === "other");
				omittedObjects += parsed.omittedObjects + Math.max(0, parsed.objects.length - documentObjectCount);
				omittedConnections += Math.max(0, parsed.connections.length - input.limits.max_connections) + parserOmittedConnections + parsed.unresolvedConnections;
				const hierarchyStatus = parserOmittedHierarchyReferences > 0 || omittedSerializedHierarchyReferences > 0 ? "partial" : parsed.hierarchy.length === 0 ? "unsupported" : hierarchyTruncated ? "partial" : "complete";
				numberLimitations.push(...(numbers?.limitations() ?? []).map((note) => `${document.relativePath}: ${note}`));
				summaries.push({
					relative_path: document.relativePath,
					archive_sha256: document.archiveSha256,
					document_kind: document.documentKind,
					object_count: parsed.objectCount,
					connection_count: parsed.connections.length + parserOmittedConnections + parsed.unresolvedConnections,
					hierarchy_complete: hierarchyStatus === "complete"
				});
				coverage.push({
					facet: `objects:${document.relativePath}`,
					status: objectsTruncated ? "partial" : "complete",
					reason: objectsTruncated ? "object_limit_reached" : null,
					examined: documentObjectCount,
					omitted: parsed.omittedObjects + Math.max(0, parsed.objects.length - documentObjectCount)
				}, {
					facet: `connections:${document.relativePath}`,
					status: connectionsTruncated || documentOmittedConnections > 0 || connectionsUnresolved || unsupportedConnections ? "partial" : "complete",
					reason: connectionsTruncated || documentOmittedConnections > 0 ? "connection_limit_reached" : connectionsUnresolved ? "connection_unresolved" : unsupportedConnections ? "unsupported_connection_type" : null,
					examined: Math.min(parsed.connections.length, input.limits.max_connections),
					omitted: Math.max(0, parsed.connections.length - input.limits.max_connections) + documentOmittedConnections + parserOmittedConnections + parsed.unresolvedConnections
				}, {
					facet: `hierarchy:${document.relativePath}`,
					status: hierarchyStatus,
					reason: parserOmittedHierarchyReferences > 0 ? "archive_hierarchy_references_missing" : omittedSerializedHierarchyReferences > 0 ? "serialized_view_hierarchy_incomplete" : parsed.hierarchy.length === 0 ? "archive_hierarchy_not_decoded" : hierarchyTruncated ? "graph_limit_reached" : null,
					examined: hierarchyCount,
					omitted: documentOmittedHierarchyNodes + documentOmittedHierarchyEdges + parserOmittedHierarchyReferences + omittedSerializedHierarchyReferences
				}, {
					facet: `classes:${document.relativePath}`,
					status: Object.keys(parsed.classes).length > 0 ? "complete" : "unsupported",
					reason: Object.keys(parsed.classes).length > 0 ? null : "archive_class_table_not_decoded",
					examined: Object.keys(parsed.classes).length,
					omitted: 0
				});
			}
			if (input.documents.length > input.limits.max_documents) {
				truncated = true;
				coverage.push({
					facet: "documents",
					status: "partial",
					reason: "document_limit_reached",
					examined: input.limits.max_documents,
					omitted: input.documents.length - input.limits.max_documents
				});
			}
			if (omittedGraphNodes > 0) coverage.push({
				facet: "graph_nodes",
				status: "partial",
				reason: "max_objects_reached",
				examined: nodes.size,
				omitted: omittedGraphNodes
			});
			return interfaceBuilderAnalysisSchema.parse({
				target_sha256: input.targetSha256,
				...input.resourceRoot === undefined ? {} : { resource_root: input.resourceRoot },
				documents: summaries,
				graph: {
					target_sha256: input.targetSha256,
					provider: {
						id: "rea-artifact-graph",
						version: "1",
						tool_version: input.toolVersion
					},
					nodes: [...nodes.values()],
					edges,
					coverage,
					truncated: truncated || omittedObjects > 0 || omittedConnections > 0 || omittedHierarchyReferences > 0
				},
				limitations: [
					...numberLimitations,
					"The graph reflects recognized Interface Builder archive fields and connections; omitted private or unrecognized archive fields remain unknown.",
					"A target-action selector is an Interface Builder observation and does not prove that the binary contains a matching implementation.",
					"Decoded constraints, runtime visibility, dynamic UI creation, and pixel geometry are not inferred from these archives."
				]
			});
		};
		interfaceBuilderLimitsSchema = z.strictObject({
			max_documents: z.number().int().min(1).max(64).default(64),
			max_objects: z.number().int().min(1).max(2e4).default(2e4),
			max_connections: z.number().int().min(1).max(4e4).default(4e4),
			trace: nativeInvestigationTraceLimitsSchema.default({
				max_depth: 8,
				max_nodes: 250,
				max_edges: 500
			})
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeValueTrace.js
var nativeValueTraceInputSchema, nativeValueTraceSchema;
function init_nativeValueTrace() {
	return (init_nativeValueTrace = __esmMin((() => {
		init_nativeValueFlow();
		nativeValueTraceInputSchema = z.strictObject({
			procedure: z.string().min(1),
			max_depth: z.number().int().min(0).max(16).default(3),
			max_functions: z.number().int().min(1).max(64).default(16),
			max_call_sites: z.number().int().min(1).max(4096).default(256),
			max_nodes: z.number().int().min(1).max(2e4).default(5e3),
			max_edges: z.number().int().min(1).max(4e4).default(1e4),
			offset: z.number().int().min(0).default(0),
			limit: z.number().int().min(1).max(5e3).default(1e3)
		});
		nativeValueTraceSchema = z.strictObject({
			seed: z.string(),
			target_sha256: z.string(),
			nodes: z.array(z.strictObject({
				id: z.string(),
				procedure: z.string(),
				evidence_id: z.string(),
				kind: z.enum(["operation", "parameter"]),
				operation: nativePcodeOperationSchema.nullable(),
				parameter: z.strictObject({
					ordinal: z.number().int().nonnegative(),
					name: z.string(),
					data_type: z.string()
				}).nullable()
			})),
			edges: z.array(z.strictObject({
				source: z.string(),
				target: z.string(),
				input_index: z.number().int().nonnegative().nullable(),
				kind: z.enum([
					"def-use",
					"call",
					"parameter-use",
					"argument-binding",
					"return-binding"
				]),
				status: z.enum([
					"derived",
					"direct",
					"resolved-indirect",
					"candidate"
				]),
				evidence_id: z.string()
			})),
			procedures: z.array(z.strictObject({
				address: z.string(),
				depth: z.number().int().nonnegative(),
				evidence_id: z.string(),
				provider: z.string(),
				analysis_profile_digest: z.string().nullable()
			})),
			unknowns: z.array(z.strictObject({
				procedure: z.string(),
				address: z.string().nullable(),
				reason: z.string()
			})),
			total_nodes: z.number().int().nonnegative(),
			total_edges: z.number().int().nonnegative(),
			decompilations: z.number().int().nonnegative(),
			next_offset: z.number().int().nonnegative().nullable(),
			truncated: z.boolean(),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
export { procedureIdentitySchema as $, RAW_ONLY_ARCHITECTURES as $t, addressedValueSchema as A, evidenceLocationSchema as At, analysisStringSchema as B, init_relationshipCoverage as Bt, createPlistNumberProjection as C, init_nativeCallReference as Ct, bundleResourceRootSchema as D, isSwiftMangledSymbolName as Dt, bundleResourceBoundResultSchema as E, init_swiftSymbolClassification as Et, init_nativeInstruction as F, parseEvidence as Ft, init_hopperValues as G, analysisProfileSchema as Gt, functionBodySchema as H, relationshipCoverageSchema as Ht, nativeCallTargetsSchema as I, providerSchema as It, parseFunctionDossier as J, createAnalysisProfile as Jt, localVariableSchema as K, analysisProfilesEqual as Kt, nativeInstructionInputSchema as L, rebindEvidenceSubjectTargetPath as Lt, isNativeInventoryOperation as M, immutableEvidence as Mt, nativeInventoryOperationSchema as N, init_evidence as Nt, init_bundleResourceRoot as O, createEvidence as Ot, nativeInventoryRowsSchemas as P, isImmutableEvidence as Pt, procedureClassificationSchema as Q, BINARY_ARCHITECTURES as Qt, nativeInstructionSchema as R, rebindEvidenceToTargetPath as Rt, createPlistNumberCollector as S, sameMachoTargetSelection as St, init_plistNumbers as T, classifySwiftSymbol as Tt, functionDossierSchema as U, fixedTupleSchema as Ut, functionBodyEntryAgrees as V, relationshipCoverageLimitations as Vt, functionInstructionWindowSchema as W, init_fixedTupleSchema as Wt, parseRelatedAddresses as X, canonicalJsonDigestSteps as Xt, parseListCount as Y, init_analysisProfile as Yt, parseSegments as Z, init_canonicalJsonDigestSteps as Zt, traceNativeInvestigationGraph as _, init_machoTargetSelection as _t, init_interfaceBuilderGraph as a, nativeValueFlowSchema as at, isInterfaceBuilderConnectionClass as b, machoTargetSelectionSchema as bt, interfaceBuilderLimitsSchema as c, nativeApiInspectionResultSchema as ct, nativeInvestigationCoverageSchema as d, init_objcSwiftMetadata as dt, init_binaryTargetTypes as en, projectBinaryOverview as et, nativeInvestigationEdgeSchema as f, inspectNativeDispatchMetadata as ft, nativeInvestigationTraceSchema as g, objcSwiftMetadataSchema as gt, nativeInvestigationProviderSchema as h, objcClassImportIdentitySchema as ht, buildInterfaceBuilderAnalysis as i, init_nativeValueFlow as it, init_nativeInventory as j, evidenceSchema as jt, NATIVE_INVENTORY_OPERATIONS as k, createImmutableEvidenceSteps as kt, init_nativeInvestigationGraph as l, addressCoordinate as lt, nativeInvestigationNodeSchema as m, nativeDispatchMetadataResultSchema as mt, nativeValueTraceInputSchema as n, isMachOFormat as nn, referenceKindSchema as nt, interfaceBuilderAnalysisSchema as o, init_nativeApiBoundary as ot, nativeInvestigationGraphSchema as p, isAppleDispatchMetadataTarget as pt, parseDocuments as q, committedProviderSchema as qt, nativeValueTraceSchema as r, unresolvedCallSchema as rt, interfaceBuilderDocumentSchema as s, nativeApiBoundarySchema as st, init_nativeValueTrace as t, isElfMetadataArchitecture as tn, referenceEdgeSchema as tt, joinInterfaceBuilderDispatch as u, init_addressCoordinate as ut, init_interfaceBuilderKeyedArchive as v, machoTargetSelectionMatchesArchitecture as vt, incompletePlistNumberLimitation as w, nativeCallClassificationSchema as wt, isUIKitRuntimeConnectionClass as x, profileMachoTargetSelection as xt, interfaceBuilderConnectionFieldNames as y, machoTargetSelectionMatchesFormat as yt, analysisBookmarkSchema as z, validateAnalysisProfileProvider as zt };