import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisInputError, AnalysisResourceConstraintError, AnalysisUnsupportedTargetError, MAX_JSON_DEPTH, canBorrowParsedJsonSnapshot, init_analysisErrorCore, init_immutableJson, init_jsonValue, isImmutableJsonSnapshot, jsonObjectSchema, jsonValueSchema } from "./errorSchemas-BjJIu7zO.js";
import { BINARY_ARCHITECTURES, NATIVE_INVENTORY_OPERATIONS, WEB_NETWORK_CAPTURE_FORMATS, WEB_NETWORK_CAPTURE_LIMITS, absoluteLocalPathStringSchema, addressedValueSchema, analysisInputErrorFromIssues, analysisStringSchema, applicationCoverageSchema, applicationGraphEvidenceSchema, applicationNodeIdentitySchema, applicationNodeObservationSchema, applicationNodeSchema, artifactEdgeSchema, artifactFormatMetadataSchema, artifactGraphManifestSchema, artifactInspectionResultSchema, artifactInventoryCoverageSchema, artifactNodeSchema, artifactOccurrenceSchema, artifactTraversalOmissionKindSchema, browserScenarioCaptureSchema, bundleResourceRootSchema, canonicalBase64Schema, canonicalJson, compareUnicodeCodePoints, compositeKey, digestCanonicalValue, digestSchema, err, evidenceSchema, fixedAllowanceOptions, functionDossierSchema, init_artifactFormatMetadata, init_artifactGraph, init_artifactInspection, init_artifactInventoryEvidence, init_binaryTargetTypes, init_browserScenarioCapture, init_bundleResourceRoot, init_canonicalDigest, init_canonicalOrdering, init_comparisonSemantics, init_digests, init_evidence, init_evidenceReference, init_fixedAllowanceRemediation, init_hopperValues, init_inputIssueProjection, init_interfaceBuilderGraph, init_javascriptApplicationAnalysis, init_javascriptApplicationEvidenceSchemas, init_javascriptApplicationGraphSchemas, init_javascriptSemanticGraphSchemas, init_javascriptSourceSelection, init_jsonShape, init_localPath, init_managedArtifact, init_nativeInventory, init_nativeInvestigationGraph, init_protobufWire, init_qlogCapture, init_recordedTransportUrl, init_result, init_safeJson, init_stringPatterns, init_unicodeCodePointOrder, init_webNetworkCapture, integrityContradictionSchema, interfaceBuilderAnalysisSchema, interfaceBuilderDocumentSchema, isMachOFormat, isNativeInventoryOperation, javaScriptSemanticGraphInputSchema, javaScriptSourceSelectionSchema, jsonValueType, localPathStringSchema, managedArtifactInspectionSchema, managedMemberInspectionSchema, nativeInventoryOperationSchema, nativeInventoryRowsSchemas, nativeInvestigationCoverageSchema, nativeInvestigationEdgeSchema, nativeInvestigationNodeSchema, nativeInvestigationProviderSchema, ok, parseArtifactInspectionInventoryResult, parseArtifactInventoryResult, parseJsonObject, parseOwnedJavaScriptApplicationAnalysisSteps, parseRecordedTransportUrl, parseUrlQueryParameterNames, prefixedDigestSchema, protobufCaptureCoverageSchema, protobufDecodingObjectSchema, protobufDecodingSchema, protobufFieldSchema, protobufFrameSchema, providerSchema, qlogCaptureFactsSchema, retainedEvidenceReferenceSchema, safeParseJson, safeParseOwnedWebNetworkCapture, uniqueSorted, validateArtifactInventorySubject, webNetworkCaptureArtifactSchema, webNetworkCaptureBinaryDescriptorSchema, webNetworkCaptureDecoderSchema, webNetworkCaptureRecordSchema } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { createHash } from "node:crypto";
import { z } from "zod";
import { isProxy } from "node:util/types";
import { isSafeNumber } from "lossless-json";

//#region dist/domain/native/functionMatching.js
var evidenceId, nativeMatchStateSchema, nativeFunctionMatchMemberSchema, nativeFunctionMatchSchema, nativeFunctionMatchingSummarySchema, nativeFunctionMatchingContextSchema, nativeFunctionMatchingSchema;
function init_functionMatching() {
	return (init_functionMatching = __esmMin((() => {
		init_canonicalDigest();
		init_digests();
		init_evidenceReference();
		evidenceId = prefixedDigestSchema("ev");
		nativeMatchStateSchema = z.enum([
			"matched",
			"only_left",
			"only_right",
			"unresolved"
		]);
		nativeFunctionMatchMemberSchema = z.strictObject({
			function_id: z.string().min(1),
			inventory_evidence_id: evidenceId,
			source_index: z.number().int().nonnegative(),
			address: z.string(),
			name: z.string(),
			body_sha256: digestSchema.nullable(),
			structural_candidate_sha256: digestSchema.nullable(),
			body_bytes: z.number().int().nonnegative().nullable(),
			dossier_evidence_id: evidenceId.nullable(),
			evidence_links: z.array(evidenceId).min(1),
			limitations: z.array(z.string())
		});
		nativeFunctionMatchSchema = z.strictObject({
			match_id: prefixedDigestSchema("match"),
			state: nativeMatchStateSchema,
			basis: z.enum(["exact-symbol", "identical-bytes"]).nullable(),
			left: z.array(nativeFunctionMatchMemberSchema),
			right: z.array(nativeFunctionMatchMemberSchema),
			reason: z.string(),
			compare_functions_input: z.strictObject({
				left: retainedEvidenceReferenceSchema,
				right: retainedEvidenceReferenceSchema
			}).nullable()
		});
		nativeFunctionMatchingSummarySchema = z.strictObject({
			matched: z.number().int().nonnegative(),
			only_left: z.number().int().nonnegative(),
			only_right: z.number().int().nonnegative(),
			unresolved: z.number().int().nonnegative()
		});
		nativeFunctionMatchingContextSchema = z.strictObject({
			left: z.strictObject({
				evidence_id: evidenceId,
				sha256: digestSchema,
				functions: z.number().int().nonnegative()
			}),
			right: z.strictObject({
				evidence_id: evidenceId,
				sha256: digestSchema,
				functions: z.number().int().nonnegative()
			}),
			scope: z.literal("provider-observed-inputs"),
			source_coverage: z.strictObject({
				status: z.enum(["complete-within-inputs", "partial"]),
				left_inventory_completeness: z.literal("unknown"),
				right_inventory_completeness: z.literal("unknown"),
				left_byte_fingerprints: z.number().int().nonnegative(),
				right_byte_fingerprints: z.number().int().nonnegative(),
				left_structural_candidates: z.number().int().nonnegative(),
				right_structural_candidates: z.number().int().nonnegative()
			}),
			summary: nativeFunctionMatchingSummarySchema
		});
		nativeFunctionMatchingSchema = nativeFunctionMatchingContextSchema.extend({
			matches: z.array(nativeFunctionMatchSchema),
			limitations: z.array(z.string())
		}).superRefine((report, context) => {
			const seen = new Set();
			const members = {
				left: new Set(),
				right: new Set()
			};
			const fingerprints = {
				left: 0,
				right: 0
			};
			const candidates = {
				left: 0,
				right: 0
			};
			const counts = {
				matched: 0,
				only_left: 0,
				only_right: 0,
				unresolved: 0
			};
			let left = 0, right = 0;
			for (const match of report.matches) {
				counts[match.state]++;
				left += match.left.length;
				right += match.right.length;
				if (seen.has(match.match_id)) context.addIssue({
					code: "custom",
					message: "Repeated match identity"
				});
				seen.add(match.match_id);
				if (match.match_id !== `match_${digestCanonicalValue({
					state: match.state,
					basis: match.basis,
					left: match.left.map((x) => x.function_id),
					right: match.right.map((x) => x.function_id)
				})}`) context.addIssue({
					code: "custom",
					message: "Match identity does not bind its selected occurrences and basis"
				});
				for (const side of ["left", "right"]) for (const member of match[side]) {
					if (member.inventory_evidence_id !== report[side].evidence_id || member.source_index >= report[side].functions || member.function_id !== `${report[side].evidence_id}/${member.source_index}` || members[side].has(member.function_id) || !member.evidence_links.includes(member.inventory_evidence_id) || member.dossier_evidence_id !== null && !member.evidence_links.includes(member.dossier_evidence_id)) context.addIssue({
						code: "custom",
						message: "Function occurrence identity, provenance or uniqueness disagrees with its selected inventory"
					});
					members[side].add(member.function_id);
					if (member.body_sha256 !== null) fingerprints[side]++;
					if (member.structural_candidate_sha256 !== null) candidates[side]++;
				}
				if (match.left.length + match.right.length === 0 || match.state !== "matched" && (match.basis !== null || match.compare_functions_input !== null)) context.addIssue({
					code: "custom",
					message: "Unresolved/unpaired group cannot contain a definitive basis or comparison input"
				});
				if (match.basis === "identical-bytes" && (match.left[0]?.body_sha256 == null || match.left[0]?.body_sha256 !== match.right[0]?.body_sha256 || match.left[0]?.body_bytes !== match.right[0]?.body_bytes)) context.addIssue({
					code: "custom",
					message: "Identical-byte match disagrees with its complete body digests and sizes"
				});
				if (match.compare_functions_input !== null && (match.compare_functions_input.left.evidence_id !== match.left[0]?.dossier_evidence_id || match.compare_functions_input.right.evidence_id !== match.right[0]?.dossier_evidence_id)) context.addIssue({
					code: "custom",
					message: "Comparison input does not identify this pair's dossiers"
				});
				if (match.state === "matched" && (match.left.length !== 1 || match.right.length !== 1 || match.basis === null) || match.state === "only_left" && (match.left.length !== 1 || match.right.length !== 0) || match.state === "only_right" && (match.right.length !== 1 || match.left.length !== 0)) context.addIssue({
					code: "custom",
					message: "Match state contradicts its occurrences"
				});
			}
			if (report.source_coverage.status !== (counts.only_left + counts.only_right + counts.unresolved > 0 ? "partial" : "complete-within-inputs") || report.source_coverage.left_byte_fingerprints !== fingerprints.left || report.source_coverage.right_byte_fingerprints !== fingerprints.right || report.source_coverage.left_structural_candidates !== candidates.left || report.source_coverage.right_structural_candidates !== candidates.right) context.addIssue({
				code: "custom",
				message: "Source/matching coverage contradicts examined facts"
			});
			if (left !== report.left.functions || right !== report.right.functions || Object.keys(counts).some((key) => counts[key] !== report.summary[key])) context.addIssue({
				code: "custom",
				message: "Matching summary or examined inventory coverage disagrees"
			});
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisViewErrors.js
var INSPECT_ANALYSIS_VIEW_OPERATION, analysisViewInputError;
function init_analysisViewErrors() {
	return (init_analysisViewErrors = __esmMin((() => {
		init_analysisErrorCore();
		INSPECT_ANALYSIS_VIEW_OPERATION = "inspect_analysis_view";
		analysisViewInputError = (issues) => new AnalysisInputError(INSPECT_ANALYSIS_VIEW_OPERATION, undefined, issues);
	})))();
}

//#endregion
//#region dist/domain/model/modelArtifact.js
var count$3, decimal, modelSourceSchema, location, modelMetadataSchema, modelTensorSchema, modelArtifactObjectSchema, modelArtifactPartialTensorSchema, modelArtifactPartialSchema, modelArtifactSchema;
function init_modelArtifact() {
	return (init_modelArtifact = __esmMin((() => {
		init_localPath();
		init_digests();
		init_jsonValue();
		count$3 = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
		decimal = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
		modelSourceSchema = z.strictObject({
			path: localPathStringSchema,
			file_size: count$3,
			header_sha256: digestSchema,
			header_length: count$3,
			sha256: digestSchema.nullable(),
			bytes_read: count$3,
			read_scope: z.enum(["header", "full-file"])
		});
		location = {
			source_offset: count$3,
			source_length: count$3,
			json_pointer: z.string().nullable()
		};
		modelMetadataSchema = z.strictObject({
			index: count$3,
			key: z.string(),
			type: z.string(),
			value: jsonValueSchema,
			element_type: z.string().nullable(),
			element_count: count$3.nullable(),
			preview_complete: z.boolean(),
			...location
		});
		modelTensorSchema = z.strictObject({
			index: count$3,
			name: z.string(),
			type: z.string(),
			type_id: count$3.nullable(),
			shape: z.array(decimal),
			data_offset: count$3,
			file_offset: count$3,
			byte_length: count$3.nullable(),
			parameter_count: decimal,
			byte_length_state: z.enum([
				"derived",
				"declared",
				"unknown"
			]),
			storage_validation: z.enum(["consistent", "unknown"]),
			...location
		});
		modelArtifactObjectSchema = z.strictObject({
			artifact: modelSourceSchema,
			format: z.enum(["gguf", "safetensors"]),
			version: count$3.nullable(),
			byte_order: z.enum(["little", "big"]),
			alignment: count$3.nullable(),
			tensor_data_offset: count$3,
			metadata: z.array(modelMetadataSchema),
			tensors: z.array(modelTensorSchema),
			totals: z.strictObject({
				confidence: z.literal("derived"),
				parameter_count: decimal,
				tensor_bytes: count$3.nullable(),
				by_type: z.array(z.strictObject({
					type: z.string(),
					tensors: count$3,
					parameter_count: decimal,
					bytes: count$3.nullable()
				}))
			}),
			coverage: z.strictObject({
				header: z.literal("complete"),
				tensor_data: z.literal("not-interpreted"),
				array_values: z.enum(["complete", "preview"]),
				tensor_ranges: z.enum(["complete", "partial"]),
				storage_sizes: z.enum(["complete", "partial"])
			}),
			limitations: z.array(z.string())
		});
		modelArtifactPartialTensorSchema = z.strictObject({
			index: count$3,
			name: z.string(),
			type: z.string(),
			type_id: count$3.nullable(),
			shape: z.array(decimal),
			data_offset: count$3,
			file_offset: count$3.nullable(),
			byte_length: count$3.nullable(),
			parameter_count: decimal,
			byte_length_state: z.enum([
				"derived",
				"declared",
				"unknown"
			]),
			storage_validation: z.enum([
				"consistent",
				"unknown",
				"not-established"
			]),
			...location
		});
		modelArtifactPartialSchema = z.strictObject({
			kind: z.literal("model-artifact-partial"),
			artifact: z.strictObject({
				path: localPathStringSchema,
				observed_file_size: count$3,
				header_sha256: z.null(),
				sha256: z.null(),
				file_identity: z.literal("unverified")
			}),
			format: z.literal("gguf"),
			version: count$3.nullable(),
			byte_order: z.enum(["little", "big"]).nullable(),
			alignment: count$3.nullable(),
			declared_metadata_count: count$3.nullable(),
			declared_tensor_count: count$3.nullable(),
			metadata: z.array(modelMetadataSchema),
			tensor_declarations: z.array(modelArtifactPartialTensorSchema),
			tensors: z.array(modelTensorSchema),
			coverage: z.strictObject({
				header: z.enum(["partial", "complete"]),
				metadata: z.enum([
					"not-started",
					"partial",
					"complete"
				]),
				tensors: z.enum([
					"not-started",
					"partial",
					"complete"
				])
			}),
			limitations: z.array(z.string())
		});
		modelArtifactSchema = modelArtifactObjectSchema.superRefine((report, context) => {
			const collections = [
				{
					name: "metadata",
					rows: report.metadata,
					identity: "key"
				},
				{
					name: "tensors",
					rows: report.tensors,
					identity: "name"
				},
				{
					name: "totals.by_type",
					rows: report.totals.by_type,
					identity: "type"
				}
			];
			for (const { name, rows, identity } of collections) {
				const seen = new Set();
				const prefix = name.split(".");
				for (let index = 0; index < rows.length; index++) {
					const row = rows[index];
					if ("index" in row && row.index !== index) {
						context.addIssue({
							code: "custom",
							path: [
								...prefix,
								index,
								"index"
							],
							message: "Model row index must equal its source position"
						});
						return;
					}
					const value = identity === "key" && "key" in row ? row.key : identity === "name" && "name" in row ? row.name : row.type;
					if (seen.has(value)) {
						context.addIssue({
							code: "custom",
							path: [
								...prefix,
								index,
								identity
							],
							message: "Model collection identities must be unique"
						});
						return;
					}
					seen.add(value);
				}
			}
		});
	})))();
}

//#endregion
//#region dist/domain/model/modelArtifactQuery.js
var modelTypeRowSchema, page$8, tensorSelectionSchema, typeSelectionSchema, metadataSelectionSchema, modelArtifactSelectionSchema, modelArtifactViewRequestSchema, inspectModelArtifactInputSchema;
function init_modelArtifactQuery() {
	return (init_modelArtifactQuery = __esmMin((() => {
		init_localPath();
		init_modelArtifact();
		modelTypeRowSchema = modelArtifactObjectSchema.shape.totals.shape.by_type.element.extend({ index: z.number().int().nonnegative() });
		page$8 = {
			indices: z.array(z.number().int().nonnegative()).optional(),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(32)
		};
		tensorSelectionSchema = z.strictObject({
			...page$8,
			collection: z.literal("tensors"),
			names: z.array(z.string()).optional(),
			storage_validation: z.array(modelTensorSchema.shape.storage_validation).optional(),
			types: z.array(z.string()).optional(),
			fields: z.array(modelTensorSchema.keyof()).optional()
		});
		typeSelectionSchema = z.strictObject({
			...page$8,
			collection: z.literal("types"),
			types: z.array(z.string()).optional(),
			fields: z.array(modelTypeRowSchema.keyof()).optional()
		});
		metadataSelectionSchema = z.strictObject({
			...page$8,
			collection: z.literal("metadata"),
			keys: z.array(z.string()).optional(),
			fields: z.array(modelMetadataSchema.keyof()).optional()
		});
		modelArtifactSelectionSchema = z.discriminatedUnion("collection", [
			tensorSelectionSchema,
			typeSelectionSchema,
			metadataSelectionSchema
		]);
		modelArtifactViewRequestSchema = z.discriminatedUnion("collection", [
			tensorSelectionSchema.extend({ kind: z.literal("model-artifact") }),
			typeSelectionSchema.extend({ kind: z.literal("model-artifact") }),
			metadataSelectionSchema.extend({ kind: z.literal("model-artifact") })
		]);
		inspectModelArtifactInputSchema = z.strictObject({
			path: absoluteLocalPathStringSchema,
			hash: z.enum(["header", "full"]).default("header").describe("header reads declarations only; full streams all bytes for SHA-256"),
			detail: z.enum(["summary", "complete"]).default("summary"),
			view: modelArtifactSelectionSchema.optional().describe("Return this selected page with compact model context, retaining complete Evidence; requires summary detail")
		}).superRefine((value, context) => {
			if (value.view !== undefined && value.detail === "complete") context.addIssue({
				code: "custom",
				path: ["view"],
				message: "view selects summary delivery; omit view to request complete Evidence"
			});
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisViewParent.js
var parseAnalysisViewResult;
function init_analysisViewParent() {
	return (init_analysisViewParent = __esmMin((() => {
		init_inputIssueProjection();
		init_result();
		parseAnalysisViewResult = (schema, parent) => {
			const parsed = schema.safeParse(parent.normalizedResult);
			if (parsed.success) return ok(parsed.data);
			return err(analysisInputErrorFromIssues("inspect_analysis_view", parsed.error.issues.map((issue) => ({
				...issue,
				path: [
					"source",
					"normalized_result",
					...issue.path
				]
			})), { source: { normalized_result: parent.normalizedResult } }, { cause: parsed.error }));
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisViewCoverage.js
var completeWithinViewCoverage, pageViewCoverage, ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT, messageWireBytes, boundedViewMessages;
function init_analysisViewCoverage() {
	return (init_analysisViewCoverage = __esmMin((() => {
		init_canonicalOrdering();
		completeWithinViewCoverage = (examined, total) => ({
			status: "complete-within-view",
			examined,
			total,
			next_offset: null,
			exhausted: true
		});
		pageViewCoverage = (offset, examined, total) => {
			const exhausted = offset >= total || offset + examined >= total;
			return {
				status: examined === 0 ? "empty" : "page",
				examined,
				total,
				next_offset: exhausted ? null : offset + examined,
				exhausted
			};
		};
		ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT = 256 * 1024;
		messageWireBytes = (value) => (value.length * 18 + 6) * 3;
		boundedViewMessages = (values, parentEvidenceId, field, required = []) => {
			const priority = uniqueSorted(required);
			const unique = uniqueSorted([...priority, ...values]);
			const notice = (omitted) => `${String(omitted)} additional ${field} omitted from this view; consult source parent Evidence ${parentEvidenceId} for the complete list (the caller-supplied record, or its retaining session).`;
			const totalBytes = unique.reduce((total, value) => total + messageWireBytes(value), 0);
			if (totalBytes <= 262144) return unique;
			let remaining = ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT - messageWireBytes(notice(unique.length));
			const retained = new Set();
			for (const value of [...priority, ...unique]) {
				if (retained.has(value)) continue;
				const bytes = messageWireBytes(value);
				if (bytes > remaining) continue;
				retained.add(value);
				remaining -= bytes;
			}
			const omitted = unique.length - retained.size;
			return omitted === 0 ? unique : [...uniqueSorted([...retained]), notice(omitted)];
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/modelArtifactView.js
var HEADLINE_TEXT_LIMIT, modelArtifactSummarySchema, summarizeModel, modelContextSchema, modelArtifactViewItemsSchema, modelArtifactViewContextSchema, checked$1, read, projectModelArtifactView;
function init_modelArtifactView() {
	return (init_modelArtifactView = __esmMin((() => {
		init_modelArtifactQuery();
		init_modelArtifact();
		init_analysisViewErrors();
		init_analysisViewParent();
		init_immutableJson();
		init_result();
		init_analysisViewCoverage();
		HEADLINE_TEXT_LIMIT = 512;
		modelArtifactSummarySchema = modelArtifactObjectSchema.omit({
			metadata: true,
			tensors: true,
			totals: true
		}).extend({
			totals: modelArtifactObjectSchema.shape.totals.omit({ by_type: true }),
			counts: z.strictObject({
				metadata: z.number().int().nonnegative(),
				tensors: z.number().int().nonnegative(),
				types: z.number().int().nonnegative()
			}),
			headlines: z.array(modelMetadataSchema.omit({
				source_offset: true,
				source_length: true,
				json_pointer: true
			})),
			chat_template_present: z.boolean()
		});
		summarizeModel = (report) => {
			const { tensors, metadata, totals: { by_type, ...totals }, ...identity } = report;
			const headlineKeys = new Set([
				"general.architecture",
				"general.name",
				"general.file_type",
				"tokenizer.ggml.model",
				"format"
			]);
			const architecture = metadata.find((row) => row.key === "general.architecture")?.value;
			if (typeof architecture === "string" && architecture.length <= HEADLINE_TEXT_LIMIT - ".context_length".length) headlineKeys.add(`${architecture}.context_length`);
			return {
				...identity,
				totals,
				counts: {
					tensors: tensors.length,
					metadata: metadata.length,
					types: by_type.length
				},
				headlines: metadata.filter((row) => headlineKeys.has(row.key) && row.element_count === null && row.element_type === null && row.type.length <= HEADLINE_TEXT_LIMIT && (row.value === null || typeof row.value === "boolean" || typeof row.value === "number" || typeof row.value === "string" && row.value.length <= HEADLINE_TEXT_LIMIT)).map(({ source_offset: _offset, source_length: _length, json_pointer: _pointer, ...row }) => row),
				chat_template_present: metadata.some((row) => row.key === "tokenizer.chat_template")
			};
		};
		modelContextSchema = modelArtifactSummarySchema.omit({
			artifact: true,
			coverage: true,
			limitations: true
		});
		modelArtifactViewItemsSchema = z.union([
			z.array(modelTypeRowSchema.partial().required({ index: true })),
			z.array(modelTensorSchema.partial().required({ index: true })),
			z.array(modelMetadataSchema.partial().required({ index: true }))
		]);
		modelArtifactViewContextSchema = z.strictObject({
			source: modelSourceSchema,
			model: modelContextSchema,
			source_coverage: modelArtifactObjectSchema.shape.coverage
		});
		checked$1 = new WeakMap();
		read = (parent) => {
			const key = parent.normalizedResult;
			const reusable = parent.sealedResult === true && key !== null && typeof key === "object" && isImmutableJsonSnapshot(key);
			const cached = reusable ? checked$1.get(key) : undefined;
			if (cached !== undefined) return ok(cached);
			const parsed = parseAnalysisViewResult(modelArtifactSchema, parent);
			if (!parsed.ok) return parsed;
			const report = reusable ? key : parsed.value;
			if (parent.subject != null && (parent.subject.local_path !== report.artifact.path || parent.subject.digest.sha256 !== report.artifact.sha256)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Model full-file subject does not match its recorded artifact"
			}]));
			const summary = summarizeModel(report);
			const { artifact: _artifact, coverage: _coverage, limitations: _limitations, ...model } = summary;
			const value = {
				report,
				summary,
				model,
				typeRows: report.totals.by_type.map((row, index) => ({
					index,
					...row
				})),
				types: new Map(report.totals.by_type.map((row, index) => [row.type, index])),
				names: new Map(report.tensors.map((row) => [row.name, row.index])),
				keys: new Map(report.metadata.map((row) => [row.key, row.index]))
			};
			if (reusable) checked$1.set(key, value);
			return ok(value);
		};
		projectModelArtifactView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "model-artifact") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Model Evidence supports summary and model-artifact metadata/tensor pages"
			}]));
			const parsed = read(parent);
			if (!parsed.ok) return parsed;
			const { report, summary, model, names, keys, types: typeIndices, typeRows } = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_model_artifact",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: boundedViewMessages(parent.limitations, parent.evidenceId, "limitations"),
				unknowns: ["Tensor values, runtime execution and inference quality were not inspected.", ...report.artifact.sha256 === null ? ["Full-file content identity is unknown; header_sha256 commits only to declarations."] : []]
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: {
					...summary,
					limitations: boundedViewMessages(summary.limitations, parent.evidenceId, "limitations")
				},
				coverage: completeWithinViewCoverage(1, 1)
			});
			const rows = view.collection === "tensors" ? report.tensors : view.collection === "metadata" ? report.metadata : typeRows;
			const selectedNames = view.collection === "tensors" ? view.names : view.collection === "metadata" ? view.keys : view.types;
			const lookup = view.collection === "tensors" ? names : view.collection === "metadata" ? keys : typeIndices;
			const indices = view.indices === undefined ? undefined : new Set(view.indices);
			const types = view.collection === "tensors" && view.types !== undefined ? new Set(view.types) : undefined;
			const storageStates = view.collection === "tensors" && view.storage_validation !== undefined ? new Set(view.storage_validation) : undefined;
			let selected;
			if (selectedNames !== undefined) selected = [...new Set(selectedNames.flatMap((name) => {
				const index = lookup.get(name);
				return index === undefined ? [] : [index];
			}))].sort((a, b) => a - b);
			else if (indices !== undefined) selected = [...indices].filter((index) => index < rows.length).sort((a, b) => a - b);
			if (indices !== undefined || types !== undefined || storageStates !== undefined) selected = (selected ?? rows.map((row) => row.index)).filter((index) => {
				const row = rows[index];
				return (indices === undefined || indices.has(index)) && (types === undefined || types.has(row.type)) && (storageStates === undefined || "storage_validation" in row && storageStates.has(row.storage_validation));
			});
			const total = selected?.length ?? rows.length;
			const pageIndices = selected === undefined ? Array.from({ length: Math.max(0, Math.min(view.limit, rows.length - view.offset)) }, (_, index) => view.offset + index) : selected.slice(view.offset, view.offset + view.limit);
			const fields = view.fields === undefined ? undefined : new Set(view.fields);
			const items = pageIndices.map((index) => {
				const row = rows[index];
				const result = { index };
				for (const [name, value] of Object.entries(row)) if (fields === undefined || fields.has(name)) result[name] = value;
				return result;
			});
			return ok({
				kind: "model-artifact",
				view,
				...shared,
				source: report.artifact,
				model,
				source_coverage: report.coverage,
				items: modelArtifactViewItemsSchema.parse(items),
				coverage: pageViewCoverage(view.offset, items.length, total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/commandObservation.js
var commandObservationSchema, gdbCommandResultSchema, commandEvidenceDetailSchema;
function init_commandObservation() {
	return (init_commandObservation = __esmMin((() => {
		commandObservationSchema = z.strictObject({
			stdout: z.string(),
			stderr: z.string(),
			exit_code: z.union([
				z.string(),
				z.number(),
				z.null()
			]),
			signal: z.string().nullable(),
			output_truncated: z.boolean(),
			completion_status: z.enum(["complete", "unknown"]),
			artifact_sha256_after: z.string().regex(/^[a-f0-9]{64}$/u).nullable(),
			artifact_changed: z.boolean().nullable()
		});
		gdbCommandResultSchema = z.strictObject({
			command: z.string(),
			mi: z.string(),
			records: z.array(z.string()),
			console: z.string(),
			target: z.string(),
			log: z.string(),
			process_exit_observed: z.boolean().exactOptional(),
			process_exit_code: z.number().int().nullable().exactOptional(),
			process_exit_signal: z.string().nullable().exactOptional(),
			output_truncated: z.boolean(),
			output_invalid_utf8: z.literal(true).exactOptional(),
			completion_status: z.enum(["complete", "unknown"])
		});
		commandEvidenceDetailSchema = z.enum(["complete", "summary"]).default("complete").describe("complete returns the original Evidence; summary retains that complete parent and returns command output once with completion and source context.");
	})))();
}

//#endregion
//#region dist/domain/analysisView/commandObservationView.js
var commandSummaryContext, gdbCommandSummarySchema, projectCommandObservationView;
function init_commandObservationView() {
	return (init_commandObservationView = __esmMin((() => {
		init_commandObservation();
		init_digests();
		init_evidence();
		init_inputIssueProjection();
		init_jsonValue();
		init_result();
		init_analysisViewCoverage();
		init_analysisViewErrors();
		init_analysisViewParent();
		commandSummaryContext = {
			source_provider: providerSchema.nullable(),
			source_analysis_profile_digest: digestSchema.nullable(),
			source_parameters: jsonValueSchema
		};
		gdbCommandSummarySchema = gdbCommandResultSchema.omit({
			console: true,
			target: true,
			log: true
		}).extend({ available_counts: z.strictObject({
			records: z.number().int().nonnegative(),
			console_utf16_units: z.number().int().nonnegative(),
			target_utf16_units: z.number().int().nonnegative(),
			log_utf16_units: z.number().int().nonnegative()
		}) });
		projectCommandObservationView = (parent, view) => {
			if (view.kind !== "summary") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Command observations support summary views."
			}]));
			if (parent.operation !== "gdb_console" && parent.operation !== "inspect_with_objdump") return err(analysisViewInputError([{
				path: ["source", "operation"],
				reason: "invalid_value",
				message: "Unsupported command-observation operation."
			}]));
			const parameters = jsonValueSchema.safeParse(parent.parameters ?? null);
			if (!parameters.success) return err(analysisInputErrorFromIssues("inspect_analysis_view", parameters.error.issues.map((issue) => ({
				...issue,
				path: [
					"source",
					"parameters",
					...issue.path
				]
			})), { source: { parameters: parent.parameters } }, { cause: parameters.error }));
			const artifact = parent.subject === null ? null : parent.subject === undefined ? parent.artifact ?? null : {
				path: parent.subject.local_path,
				sha256: parent.subject.digest.sha256
			};
			const shared = {
				kind: "summary",
				view,
				parent_evidence_id: parent.evidenceId,
				parent_digest: parent.evidenceId.slice(3),
				artifact,
				source_provider: parent.provider ?? null,
				source_analysis_profile_digest: parent.analysisProfileDigest ?? null,
				source_parameters: parameters.data,
				coverage: completeWithinViewCoverage(1, 1),
				limitations: boundedViewMessages(parent.limitations, parent.evidenceId, "limitations"),
				unknowns: boundedViewMessages(["This retained command observation does not establish current target state or global analysis coverage."], parent.evidenceId, "unknowns")
			};
			if (parent.operation === "gdb_console") {
				const parsed = parseAnalysisViewResult(gdbCommandResultSchema, parent);
				if (!parsed.ok) return parsed;
				const selection = parameters.data;
				if (typeof selection === "object" && selection !== null && !Array.isArray(selection) && typeof selection.command === "string" && selection.command !== parsed.value.command) return err(analysisViewInputError([{
					path: [
						"source",
						"parameters",
						"command"
					],
					reason: "invalid_value",
					message: "The captured command conflicts with its source parameters."
				}]));
				const { console, target, log, ...records } = parsed.value;
				return ok({
					...shared,
					parent_operation: "gdb_console",
					summary: {
						...records,
						available_counts: {
							records: records.records.length,
							console_utf16_units: console.length,
							target_utf16_units: target.length,
							log_utf16_units: log.length
						}
					}
				});
			}
			const parsed = parseAnalysisViewResult(commandObservationSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			if (artifact !== null && report.artifact_sha256_after !== null && report.artifact_changed !== null && report.artifact_changed !== (artifact.sha256 !== report.artifact_sha256_after)) return err(analysisViewInputError([{
				path: [
					"source",
					"normalized_result",
					"artifact_changed"
				],
				reason: "invalid_value",
				message: "The recorded artifact-change flag conflicts with the observed digests."
			}]));
			return ok({
				...shared,
				parent_operation: "inspect_with_objdump",
				summary: report
			});
		};
	})))();
}

//#endregion
//#region dist/domain/fridaSessionStatus.js
var fridaSessionStatusInputSchema, fridaSessionObservationSchema, fridaSessionStatusSchema;
function init_fridaSessionStatus() {
	return (init_fridaSessionStatus = __esmMin((() => {
		fridaSessionStatusInputSchema = z.strictObject({
			session_id: z.string().uuid(),
			detail: z.enum(["complete", "summary"]).optional()
		});
		fridaSessionObservationSchema = z.strictObject({
			session_id: z.string().uuid(),
			device_id: z.string(),
			state: z.enum([
				"paused",
				"running",
				"detached"
			]),
			target: z.string(),
			pid: z.number().int().nonnegative(),
			mode: z.enum(["attach", "spawn"])
		});
		fridaSessionStatusSchema = fridaSessionObservationSchema.extend({
			scripts: z.array(z.strictObject({
				script_id: z.string().uuid(),
				name: z.string()
			})),
			messages: z.array(z.unknown()),
			messages_truncated: z.boolean()
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/fridaSessionStatusView.js
var fridaSessionStatusSummarySchema, fridaSessionStatusViewContext, projectFridaSessionStatusView;
function init_fridaSessionStatusView() {
	return (init_fridaSessionStatusView = __esmMin((() => {
		init_evidence();
		init_fridaSessionStatus();
		init_result();
		init_analysisViewCoverage();
		init_analysisViewErrors();
		init_analysisViewParent();
		fridaSessionStatusSummarySchema = fridaSessionStatusSchema.omit({ messages: true }).extend({ messages_retained: z.number().int().nonnegative() });
		fridaSessionStatusViewContext = {
			source_provider: providerSchema.nullable(),
			source_parameters: z.strictObject({ session_id: z.string().uuid() })
		};
		projectFridaSessionStatusView = (parent, view) => {
			if (view.kind !== "summary") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Frida session status supports summary views."
			}]));
			const report = parseAnalysisViewResult(fridaSessionStatusSchema, parent);
			if (!report.ok) return report;
			const parameters = fridaSessionStatusViewContext.source_parameters.safeParse(parent.parameters);
			if (!parameters.success || parameters.data.session_id !== report.value.session_id) return err(analysisViewInputError([{
				path: [
					"source",
					"parameters",
					"session_id"
				],
				reason: "invalid_value",
				message: "The Frida status must identify the session selected by its source parameters."
			}]));
			const { messages, ...status } = report.value;
			return ok({
				kind: "summary",
				view,
				parent_evidence_id: parent.evidenceId,
				parent_digest: parent.evidenceId.slice(3),
				parent_operation: "frida_session_status",
				artifact: null,
				source_provider: parent.provider ?? null,
				source_parameters: parameters.data,
				summary: {
					...status,
					messages_retained: messages.length
				},
				coverage: completeWithinViewCoverage(1, 1),
				limitations: boundedViewMessages([...parent.limitations, `Message payloads remain in complete parent Evidence ${parent.evidenceId}; export_evidence_bundle preserves them.`], parent.evidenceId, "limitations"),
				unknowns: ["This is a captured session observation; querying retained Evidence does not refresh live state or establish target process identity after exit or reuse.", "messages_retained counts queued messages, not all target events. messages_truncated preserves the provider's capture limitation; payload meanings and global event coverage are unknown."]
			});
		};
	})))();
}

//#endregion
//#region dist/domain/go/goBinary.js
var goArchitectureForSubject, sourceRangeSchema, moduleIdentitySchema, goModuleSchema, goModuleMetadataSchema, inspectGoBinaryInputSchema, goBuildInfoSchema, goBinarySchema;
function init_goBinary() {
	return (init_goBinary = __esmMin((() => {
		init_binaryTargetTypes();
		init_digests();
		init_localPath();
		init_stringPatterns();
		goArchitectureForSubject = (architecture) => {
			switch (architecture) {
				case "386": return "x86";
				case "amd64": return "x86_64";
				default: return BINARY_ARCHITECTURES.find((supported) => supported === architecture);
			}
		};
		sourceRangeSchema = z.strictObject({
			offset: z.number().int().nonnegative(),
			bytes: z.number().int().nonnegative()
		});
		moduleIdentitySchema = z.strictObject({
			path: z.string(),
			version: z.string(),
			sum: z.string().nullable()
		});
		goModuleSchema = moduleIdentitySchema.extend({ replacement: moduleIdentitySchema.nullable() });
		goModuleMetadataSchema = z.strictObject({
			path: z.string().nullable(),
			main: goModuleSchema.nullable(),
			dependencies: z.array(goModuleSchema),
			settings: z.array(z.strictObject({
				key: z.string(),
				value: z.string()
			})),
			unparsed_lines: z.array(z.string()),
			unparsed_line_bytes_base64: z.array(canonicalBase64Schema),
			complete: z.boolean()
		});
		inspectGoBinaryInputSchema = z.strictObject({
			path: localPathStringSchema.describe("Absolute filesystem path to the selected executable or library"),
			detail: z.enum(["complete", "summary"]).default("complete").describe("complete returns all metadata inline; summary retains complete Evidence and returns build identity and counts for subsequent retained Go views.")
		});
		goBuildInfoSchema = z.strictObject({
			header_offset: z.number().int().nonnegative(),
			encoding: z.enum(["inline", "pointer"]),
			go_version: z.string().nullable(),
			go_version_bytes_base64: canonicalBase64Schema,
			module_text: z.string().nullable(),
			module_bytes_base64: canonicalBase64Schema,
			version_location: sourceRangeSchema,
			module_location: sourceRangeSchema,
			module: goModuleMetadataSchema
		});
		goBinarySchema = z.strictObject({
			artifact: z.strictObject({
				path: localPathStringSchema,
				sha256: digestSchema,
				bytes: z.number().int().nonnegative()
			}),
			format: z.enum([
				"elf",
				"pe",
				"macho"
			]),
			architecture: z.string(),
			bits: z.union([z.literal(32), z.literal(64)]),
			byte_order: z.enum(["little", "big"]),
			build_info: goBuildInfoSchema.nullable(),
			limitations: z.array(z.string())
		}).superRefine((report, context) => {
			const info = report.build_info;
			if (info === null) return;
			if (info.header_offset > report.artifact.bytes - 32) context.addIssue({
				code: "custom",
				path: ["build_info", "header_offset"],
				message: "Build-info header is outside the selected artifact."
			});
			for (const field of ["version_location", "module_location"]) {
				const range = info[field];
				if (range.offset > report.artifact.bytes || range.bytes > report.artifact.bytes - range.offset) context.addIssue({
					code: "custom",
					path: ["build_info", field],
					message: "Build-info source range is outside the selected artifact."
				});
			}
			for (const [field, range, description] of [[
				"go_version_bytes_base64",
				info.version_location,
				"compiler"
			], [
				"module_bytes_base64",
				info.module_location,
				"module"
			]]) {
				const encoded = info[field];
				const padding = encoded.endsWith("==") ? 2 : encoded.endsWith("=") ? 1 : 0;
				if (encoded.length / 4 * 3 - padding !== range.bytes) context.addIssue({
					code: "custom",
					path: ["build_info", field],
					message: `Encoded ${description} bytes do not match their reported source length.`
				});
			}
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/selectViewRows.js
var selectViewRows;
function init_selectViewRows() {
	return (init_selectViewRows = __esmMin((() => {
		selectViewRows = (rows, view, matches, project) => {
			const selected = [];
			let total = 0;
			for (const [index, row] of rows.entries()) {
				if (!matches(row, index)) continue;
				if (total >= view.offset && selected.length < view.limit) selected.push(project(row, index));
				total++;
			}
			return {
				rows: selected,
				total
			};
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/goBinaryView.js
var indexSchema$1, count$2, settingSchema, page$7, goBinaryViewRequestSchema, goBinaryViewPageSchema, goBinaryViewContextSchema, goBinarySummarySchema, checkedReports$2, parseReport$1, projectGoBinaryView;
function init_goBinaryView() {
	return (init_goBinaryView = __esmMin((() => {
		init_goBinary();
		init_immutableJson();
		init_result();
		init_analysisViewCoverage();
		init_analysisViewErrors();
		init_analysisViewParent();
		init_selectViewRows();
		indexSchema$1 = z.number().int().nonnegative();
		count$2 = z.number().int().nonnegative();
		settingSchema = goModuleMetadataSchema.shape.settings.element;
		page$7 = {
			kind: z.literal("go"),
			indices: z.array(indexSchema$1).optional(),
			offset: indexSchema$1.default(0),
			limit: z.number().int().positive().default(64)
		};
		goBinaryViewRequestSchema = z.discriminatedUnion("collection", [z.strictObject({
			...page$7,
			collection: z.literal("dependencies"),
			paths: z.array(z.string()).optional(),
			fields: z.array(goModuleSchema.keyof()).optional()
		}), z.strictObject({
			...page$7,
			collection: z.literal("settings"),
			keys: z.array(z.string()).optional(),
			fields: z.array(settingSchema.keyof()).optional()
		})]);
		goBinaryViewPageSchema = z.discriminatedUnion("collection", [z.strictObject({
			collection: z.literal("dependencies"),
			rows: z.array(goModuleSchema.partial().extend({ index: indexSchema$1 }))
		}), z.strictObject({
			collection: z.literal("settings"),
			rows: z.array(settingSchema.partial().extend({ index: indexSchema$1 }))
		})]);
		goBinaryViewContextSchema = z.strictObject({ source_coverage: z.strictObject({
			build_info_available: z.boolean(),
			module_parse_complete: z.boolean().nullable(),
			runtime_dependencies: z.literal("unknown")
		}) });
		goBinarySummarySchema = z.strictObject({
			bytes: count$2,
			format: goBinarySchema.shape.format,
			architecture: goBinarySchema.shape.architecture,
			bits: goBinarySchema.shape.bits,
			byte_order: goBinarySchema.shape.byte_order,
			build_info: goBuildInfoSchema.omit({
				go_version_bytes_base64: true,
				module_text: true,
				module_bytes_base64: true,
				module: true
			}).extend({ module: goModuleMetadataSchema.omit({
				dependencies: true,
				settings: true,
				unparsed_lines: true,
				unparsed_line_bytes_base64: true
			}).extend({ available_counts: z.strictObject({
				dependencies: count$2,
				settings: count$2,
				unparsed_lines: count$2,
				unparsed_line_bytes_base64: count$2
			}) }) }).nullable()
		});
		checkedReports$2 = new WeakMap();
		parseReport$1 = (parent) => {
			const key = parent.normalizedResult;
			const reusable = parent.sealedResult === true && typeof key === "object" && key !== null && isImmutableJsonSnapshot(key);
			const existing = reusable ? checkedReports$2.get(key) : undefined;
			if (existing !== undefined) return ok(existing);
			const parsed = parseAnalysisViewResult(goBinarySchema, parent);
			if (!parsed.ok) return parsed;
			const report = reusable ? key : parsed.value;
			if (reusable) checkedReports$2.set(key, report);
			return ok(report);
		};
		projectGoBinaryView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "go") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Go build Evidence supports summary and go views."
			}]));
			const parsed = parseReport$1(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			if (parent.subject?.local_path !== report.artifact.path || parent.subject.digest.sha256 !== report.artifact.sha256 || parent.subject.format !== (report.format === "macho" ? "mach-o" : report.format) || parent.subject.architecture !== (goArchitectureForSubject(report.architecture) ?? null)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Go parent subject must identify the report's exact artifact."
			}]));
			const info = report.build_info;
			const runtimeUnknown = "Embedded build records do not establish complete runtime dependencies or target behavior.";
			const unknowns = [runtimeUnknown, ...info === null ? ["Build information is unavailable; language and dependencies remain unknown."] : [...info.module.complete ? [] : ["Some module records were not parsed; consult the complete parent Evidence for original lines and bytes."], ...info.module.main === null ? ["No main module was decoded; embedded dependency coverage remains unknown."] : []]];
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_go_binary",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				source_coverage: {
					build_info_available: info !== null,
					module_parse_complete: info?.module.complete ?? null,
					runtime_dependencies: "unknown"
				},
				limitations: boundedViewMessages([...parent.limitations, ...report.limitations], parent.evidenceId, "limitations"),
				unknowns: boundedViewMessages(unknowns, parent.evidenceId, "unknowns", [runtimeUnknown])
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: {
					bytes: report.artifact.bytes,
					format: report.format,
					architecture: report.architecture,
					bits: report.bits,
					byte_order: report.byte_order,
					build_info: info === null ? null : {
						header_offset: info.header_offset,
						encoding: info.encoding,
						go_version: info.go_version,
						version_location: info.version_location,
						module_location: info.module_location,
						module: {
							path: info.module.path,
							main: info.module.main,
							complete: info.module.complete,
							available_counts: {
								dependencies: info.module.dependencies.length,
								settings: info.module.settings.length,
								unparsed_lines: info.module.unparsed_lines.length,
								unparsed_line_bytes_base64: info.module.unparsed_line_bytes_base64.length
							}
						}
					}
				},
				coverage: completeWithinViewCoverage(1, 1)
			});
			const indices = view.indices === undefined ? undefined : new Set(view.indices);
			const fields = view.fields === undefined ? undefined : new Set(view.fields);
			if (view.collection === "dependencies") {
				const paths = view.paths === undefined ? undefined : new Set(view.paths);
				const selected = selectViewRows(info?.module.dependencies ?? [], view, (row, index) => (indices?.has(index) ?? true) && (paths?.has(row.path) ?? true), (row, index) => ({
					index,
					...(fields?.has("path") ?? true) && { path: row.path },
					...(fields?.has("version") ?? true) && { version: row.version },
					...(fields?.has("sum") ?? true) && { sum: row.sum },
					...(fields?.has("replacement") ?? true) && { replacement: row.replacement }
				}));
				return ok({
					kind: "go",
					view,
					...shared,
					page: {
						collection: "dependencies",
						rows: selected.rows
					},
					coverage: pageViewCoverage(view.offset, selected.rows.length, selected.total)
				});
			}
			const keys = view.keys === undefined ? undefined : new Set(view.keys);
			const selected = selectViewRows(info?.module.settings ?? [], view, (row, index) => (indices?.has(index) ?? true) && (keys?.has(row.key) ?? true), (row, index) => ({
				index,
				...(fields?.has("key") ?? true) && { key: row.key },
				...(fields?.has("value") ?? true) && { value: row.value }
			}));
			return ok({
				kind: "go",
				view,
				...shared,
				page: {
					collection: "settings",
					rows: selected.rows
				},
				coverage: pageViewCoverage(view.offset, selected.rows.length, selected.total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/rust/rustBinary.js
var rustArchitectureForSubject, RUST_AUDITABLE_FORMAT_VERSIONS, index$2, rustcHash, rustPackageSchema, dependencyEdgeSchema, rustAuditableMetadataSchema, rustcCommitSchema, inspectRustBinaryInputSchema, rustBinarySchema, issue, inside, checkSection, checkPackages, cyclicDependencyIndices, dependencyPostorder, reversedDependencyEdges, dependencyComponent, dependencyComponentInCycle, checkRustc;
function init_rustBinary() {
	return (init_rustBinary = __esmMin((() => {
		init_digests();
		init_localPath();
		init_binaryTargetTypes();
		rustArchitectureForSubject = (architecture) => {
			switch (architecture) {
				case "386": return "x86";
				case "amd64": return "x86_64";
				default: return BINARY_ARCHITECTURES.find((supported) => supported === architecture);
			}
		};
		RUST_AUDITABLE_FORMAT_VERSIONS = [
			0,
			1,
			8
		];
		index$2 = z.number().int().nonnegative();
		rustcHash = z.string().regex(/^[0-9a-f]{40}$/u);
		rustPackageSchema = z.strictObject({
			name: z.string().min(1),
			version: z.string().min(1),
			source: z.string().min(1),
			kind: z.enum(["runtime", "build"]).nullable(),
			dependencies: z.array(index$2),
			root: z.boolean()
		});
		dependencyEdgeSchema = z.strictObject({
			from_index: index$2,
			to_index: index$2
		});
		rustAuditableMetadataSchema = z.strictObject({
			section_name: z.enum([".dep-v0", "__DATA,.dep-v0"]),
			file_offset: index$2,
			section_bytes: z.number().int().positive(),
			compressed_bytes: z.number().int().positive(),
			uncompressed_bytes: z.number().int().positive(),
			/** Original embedded revision; null means the source omitted the field. */
			format_version: z.number().int().nonnegative().max(4294967295).nullable(),
			packages: z.array(rustPackageSchema),
			root_package_index: index$2.nullable(),
			dependency_edges: z.array(dependencyEdgeSchema),
			cyclic_dependency_indices: z.array(index$2)
		});
		rustcCommitSchema = z.strictObject({
			evidence_kind: z.literal("inferred"),
			hashes: z.array(z.strictObject({
				hash: rustcHash,
				file_offset: index$2
			})).min(1)
		});
		inspectRustBinaryInputSchema = z.strictObject({ path: localPathStringSchema.describe("Absolute filesystem path to the selected executable or library") });
		rustBinarySchema = z.strictObject({
			artifact: z.strictObject({
				path: localPathStringSchema,
				sha256: digestSchema,
				bytes: index$2
			}),
			format: z.enum([
				"elf",
				"pe",
				"macho"
			]),
			architecture: z.string(),
			bits: z.union([z.literal(32), z.literal(64)]),
			byte_order: z.enum(["little", "big"]),
			auditable_metadata: rustAuditableMetadataSchema.nullable(),
			rustc_commit: rustcCommitSchema.nullable(),
			limitations: z.array(z.string())
		}).superRefine((report, context) => {
			const metadata = report.auditable_metadata;
			if (metadata !== null) {
				checkSection(report.artifact.bytes, metadata, context);
				checkPackages(metadata, context);
			}
			checkRustc(report.artifact.bytes, report.rustc_commit, context);
		});
		issue = (context, path, message) => {
			context.addIssue({
				code: "custom",
				path,
				message
			});
		};
		inside = (fileBytes, offset, size) => offset <= fileBytes && size <= fileBytes - offset;
		checkSection = (fileBytes, metadata, context) => {
			if (!inside(fileBytes, metadata.file_offset, metadata.section_bytes) || metadata.compressed_bytes !== metadata.section_bytes) issue(context, ["auditable_metadata", "file_offset"], "Dependency section range is outside the selected artifact or disagrees with its compressed size.");
		};
		checkPackages = (metadata, context) => {
			const roots = [];
			const edgesByPackage = new Map();
			for (const [position, edge] of metadata.dependency_edges.entries()) {
				if (edge.from_index >= metadata.packages.length || edge.to_index >= metadata.packages.length) {
					issue(context, [
						"auditable_metadata",
						"dependency_edges",
						position
					], "Dependency edge index is outside the package list.");
					continue;
				}
				const grouped = edgesByPackage.get(edge.from_index);
				if (grouped === undefined) edgesByPackage.set(edge.from_index, [edge]);
				else grouped.push(edge);
			}
			for (const [packageIndex, pkg] of metadata.packages.entries()) {
				if (pkg.root) roots.push(packageIndex);
				const edges = edgesByPackage.get(packageIndex) ?? [];
				if (edges.length !== pkg.dependencies.length || edges.some((edge, index) => edge.to_index !== pkg.dependencies[index])) issue(context, ["auditable_metadata", "dependency_edges"], "Dependency edges do not match package dependency indices.");
				if (pkg.dependencies.some((target) => target >= metadata.packages.length)) issue(context, [
					"auditable_metadata",
					"packages",
					packageIndex,
					"dependencies"
				], "Dependency index is outside the package list.");
			}
			const root = metadata.root_package_index;
			if (root === null ? roots.length !== 0 : roots.length !== 1 || roots[0] !== root) issue(context, ["auditable_metadata", "root_package_index"], "Root package index does not match packages marked root.");
			const cycles = cyclicDependencyIndices(metadata.packages);
			if (cycles.length !== metadata.cyclic_dependency_indices.length || cycles.some((index, position) => metadata.cyclic_dependency_indices[position] !== index)) issue(context, ["auditable_metadata", "cyclic_dependency_indices"], "Cyclic dependency indices do not match the cycles in package dependencies.");
		};
		cyclicDependencyIndices = (packages) => {
			const edges = packages.map((pkg) => pkg.dependencies);
			const order = dependencyPostorder(edges);
			const reversed = reversedDependencyEdges(edges);
			const seen = new Uint8Array(edges.length);
			const cyclic = new Set();
			for (let cursor = order.length - 1; cursor >= 0; cursor -= 1) {
				const start = order[cursor];
				if (start === undefined || seen[start] === 1) continue;
				const component = dependencyComponent(start, reversed, seen);
				if (dependencyComponentInCycle(component, edges)) for (const index of component) cyclic.add(index);
			}
			return [...cyclic].sort((left, right) => left - right);
		};
		dependencyPostorder = (edges) => {
			const seen = new Uint8Array(edges.length);
			const order = [];
			for (let start = 0; start < edges.length; start += 1) {
				if (seen[start] === 1) continue;
				const stack = [{
					index: start,
					edge: 0
				}];
				seen[start] = 1;
				while (stack.length > 0) {
					const frame = stack[stack.length - 1];
					if (frame === undefined) break;
					const next = edges[frame.index]?.[frame.edge];
					if (next === undefined) {
						stack.pop();
						order.push(frame.index);
						continue;
					}
					frame.edge += 1;
					if (seen[next] === 0) {
						seen[next] = 1;
						stack.push({
							index: next,
							edge: 0
						});
					}
				}
			}
			return order;
		};
		reversedDependencyEdges = (edges) => {
			const reversed = Array.from({ length: edges.length }, () => []);
			for (let from = 0; from < edges.length; from += 1) for (const to of edges[from] ?? []) reversed[to]?.push(from);
			return reversed;
		};
		dependencyComponent = (start, reversed, seen) => {
			const component = [];
			const stack = [start];
			seen[start] = 1;
			while (stack.length > 0) {
				const index = stack.pop();
				if (index === undefined) break;
				component.push(index);
				for (const next of reversed[index] ?? []) {
					if (seen[next] === 0) {
						seen[next] = 1;
						stack.push(next);
					}
				}
			}
			return component;
		};
		dependencyComponentInCycle = (component, edges) => {
			if (component.length > 1) return true;
			const only = component[0];
			return only !== undefined && (edges[only]?.includes(only) ?? false);
		};
		checkRustc = (fileBytes, commit, context) => {
			if (commit === null) return;
			const seen = new Set();
			for (const [position, entry] of commit.hashes.entries()) {
				if (seen.has(entry.hash) || !inside(fileBytes, entry.file_offset, 48)) issue(context, [
					"rustc_commit",
					"hashes",
					position
				], "rustc path hash is duplicated or its file offset is outside the artifact.");
				seen.add(entry.hash);
			}
		};
	})))();
}

//#endregion
//#region dist/domain/rust/rustBinaryQuery.js
var edgeSchema, index$1, page$6, packages, edges, rustBinarySelectionSchema, rustBinaryViewRequestSchema, rustBinaryViewPageSchema, inspectRustBinaryRequestSchema;
function init_rustBinaryQuery() {
	return (init_rustBinaryQuery = __esmMin((() => {
		init_rustBinary();
		edgeSchema = rustAuditableMetadataSchema.shape.dependency_edges.element;
		index$1 = z.number().int().nonnegative();
		page$6 = {
			indices: z.array(index$1).optional(),
			offset: index$1.default(0),
			limit: z.number().int().positive().default(64)
		};
		packages = z.strictObject({
			...page$6,
			collection: z.literal("packages"),
			names: z.array(z.string()).optional(),
			versions: z.array(z.string()).optional(),
			fields: z.array(rustPackageSchema.keyof()).optional().describe("Original index always retained. Default attributes omit dependency vectors; select dependencies explicitly for direct index references.")
		});
		edges = z.strictObject({
			...page$6,
			collection: z.literal("edges"),
			from_indices: z.array(index$1).optional(),
			to_indices: z.array(index$1).optional(),
			fields: z.array(edgeSchema.keyof()).optional()
		});
		rustBinarySelectionSchema = z.discriminatedUnion("collection", [packages, edges]);
		rustBinaryViewRequestSchema = z.discriminatedUnion("collection", [packages.extend({ kind: z.literal("rust") }), edges.extend({ kind: z.literal("rust") })]);
		rustBinaryViewPageSchema = z.discriminatedUnion("collection", [z.strictObject({
			collection: z.literal("packages"),
			rows: z.array(rustPackageSchema.partial().extend({ index: index$1 }))
		}), z.strictObject({
			collection: z.literal("edges"),
			rows: z.array(edgeSchema.partial().extend({ index: index$1 }))
		})]);
		inspectRustBinaryRequestSchema = inspectRustBinaryInputSchema.extend({
			detail: z.enum(["complete", "summary"]).optional(),
			view: rustBinarySelectionSchema.optional()
		}).superRefine((value, context) => {
			if (value.view !== undefined && value.detail === "complete") context.addIssue({
				code: "custom",
				path: ["view"],
				message: "view selects compact delivery; omit view for complete Evidence"
			});
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/rustBinaryView.js
var count$1, rustBinarySummarySchema, rustBinaryViewContextSchema, checkedReports$1, parseReport, summarize$1, projectRustBinaryView;
function init_rustBinaryView() {
	return (init_rustBinaryView = __esmMin((() => {
		init_rustBinary();
		init_rustBinaryQuery();
		init_immutableJson();
		init_result();
		init_analysisViewCoverage();
		init_analysisViewErrors();
		init_analysisViewParent();
		init_selectViewRows();
		count$1 = z.number().int().nonnegative();
		rustBinarySummarySchema = z.strictObject({
			bytes: count$1,
			format: rustBinarySchema.shape.format,
			architecture: rustBinarySchema.shape.architecture,
			bits: rustBinarySchema.shape.bits,
			byte_order: rustBinarySchema.shape.byte_order,
			auditable_metadata: rustAuditableMetadataSchema.omit({
				packages: true,
				dependency_edges: true,
				cyclic_dependency_indices: true
			}).extend({ counts: z.strictObject({
				packages: count$1,
				edges: count$1,
				cyclic_packages: count$1
			}) }).nullable(),
			rustc_commit: rustcCommitSchema.omit({ hashes: true }).extend({ hashes_count: count$1 }).nullable()
		});
		rustBinaryViewContextSchema = z.strictObject({ source_coverage: z.strictObject({
			auditable_metadata_available: z.boolean(),
			embedded_records: z.enum(["complete", "unknown"]),
			runtime_dependencies: z.literal("unknown")
		}) });
		checkedReports$1 = new WeakMap();
		parseReport = (parent) => {
			const key = parent.normalizedResult;
			const reusable = parent.sealedResult === true && typeof key === "object" && key !== null && isImmutableJsonSnapshot(key);
			const known = reusable ? checkedReports$1.get(key) : undefined;
			if (known !== undefined) return ok(known);
			const parsed = parseAnalysisViewResult(rustBinarySchema, parent);
			if (!parsed.ok) return parsed;
			const report = reusable ? key : parsed.value;
			if (reusable) checkedReports$1.set(key, report);
			return ok(report);
		};
		summarize$1 = (report) => {
			const { artifact, auditable_metadata: metadata, rustc_commit: compiler } = report;
			const section = metadata === null ? null : {
				section_name: metadata.section_name,
				file_offset: metadata.file_offset,
				section_bytes: metadata.section_bytes,
				compressed_bytes: metadata.compressed_bytes,
				uncompressed_bytes: metadata.uncompressed_bytes,
				format_version: metadata.format_version,
				root_package_index: metadata.root_package_index,
				counts: {
					packages: metadata.packages.length,
					edges: metadata.dependency_edges.length,
					cyclic_packages: metadata.cyclic_dependency_indices.length
				}
			};
			return {
				format: report.format,
				architecture: report.architecture,
				bits: report.bits,
				byte_order: report.byte_order,
				bytes: artifact.bytes,
				auditable_metadata: section,
				rustc_commit: compiler === null ? null : {
					evidence_kind: compiler.evidence_kind,
					hashes_count: compiler.hashes.length
				}
			};
		};
		projectRustBinaryView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "rust") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Rust Evidence supports summary and rust views."
			}]));
			const parsed = parseReport(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const subject = parent.subject;
			if (subject == null || subject.local_path !== report.artifact.path || subject.digest.sha256 !== report.artifact.sha256 || subject.format !== (report.format === "macho" ? "mach-o" : report.format) || subject.architecture !== (rustArchitectureForSubject(report.architecture) ?? null)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Rust parent subject must identify the report's exact artifact."
			}]));
			const metadata = report.auditable_metadata;
			const unknown = "Embedded dependency records do not authenticate build provenance or establish complete runtime dependencies or target behavior.";
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_rust_binary",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				source_coverage: {
					auditable_metadata_available: metadata !== null,
					embedded_records: metadata === null ? "unknown" : "complete",
					runtime_dependencies: "unknown"
				},
				limitations: boundedViewMessages([...parent.limitations, ...report.limitations], parent.evidenceId, "limitations"),
				unknowns: boundedViewMessages([unknown, ...metadata === null ? ["No cargo-auditable metadata was observed; missing metadata does not establish an empty dependency set."] : []], parent.evidenceId, "unknowns", [unknown])
			};
			const summary = summarize$1(report);
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary,
				coverage: completeWithinViewCoverage(1, 1)
			});
			const indices = view.indices === undefined ? undefined : new Set(view.indices);
			const fields = view.fields === undefined ? undefined : new Set(view.fields);
			if (view.collection === "packages") {
				const names = view.names === undefined ? undefined : new Set(view.names);
				const versions = view.versions === undefined ? undefined : new Set(view.versions);
				const selected = selectViewRows(metadata?.packages ?? [], view, (row, index) => (indices?.has(index) ?? true) && (names?.has(row.name) ?? true) && (versions?.has(row.version) ?? true), (row, index) => ({
					index,
					...(fields?.has("name") ?? true) && { name: row.name },
					...(fields?.has("version") ?? true) && { version: row.version },
					...(fields?.has("source") ?? true) && { source: row.source },
					...(fields?.has("kind") ?? true) && { kind: row.kind },
					...(fields?.has("root") ?? true) && { root: row.root },
					...fields?.has("dependencies") === true && { dependencies: row.dependencies }
				}));
				return ok({
					kind: "rust",
					view,
					...shared,
					rust: summary,
					page: {
						collection: "packages",
						rows: selected.rows
					},
					coverage: pageViewCoverage(view.offset, selected.rows.length, selected.total)
				});
			}
			const from = view.from_indices === undefined ? undefined : new Set(view.from_indices);
			const to = view.to_indices === undefined ? undefined : new Set(view.to_indices);
			const selected = selectViewRows(metadata?.dependency_edges ?? [], view, (row, index) => (indices?.has(index) ?? true) && (from?.has(row.from_index) ?? true) && (to?.has(row.to_index) ?? true), (row, index) => ({
				index,
				...(fields?.has("from_index") ?? true) && { from_index: row.from_index },
				...(fields?.has("to_index") ?? true) && { to_index: row.to_index }
			}));
			return ok({
				kind: "rust",
				view,
				...shared,
				rust: summary,
				page: {
					collection: "edges",
					rows: selected.rows
				},
				coverage: pageViewCoverage(view.offset, selected.rows.length, selected.total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/nativeFunctionMatchingView.js
var matchRow, functionRow, page$5, nativeFunctionMatchingViewRequestSchema, nativeFunctionMatchingViewItemsSchema, nativeFunctionMatchingViewContextSchema, checked, checkedReport, functionRows, sharedContext, selected, filterRows, selectedItems, projectNativeFunctionMatchingView;
function init_nativeFunctionMatchingView() {
	return (init_nativeFunctionMatchingView = __esmMin((() => {
		init_functionMatching();
		init_immutableJson();
		init_analysisViewParent();
		init_analysisViewErrors();
		init_analysisViewCoverage();
		init_result();
		matchRow = nativeFunctionMatchSchema.extend({
			left_count: z.number().int().nonnegative(),
			right_count: z.number().int().nonnegative()
		});
		functionRow = nativeFunctionMatchMemberSchema.extend({
			match_id: nativeFunctionMatchSchema.shape.match_id,
			state: nativeMatchStateSchema,
			side: z.enum(["left", "right"])
		});
		page$5 = {
			kind: z.literal("function-matches"),
			states: z.array(nativeMatchStateSchema).optional(),
			match_ids: z.array(z.string()).optional(),
			function_ids: z.array(z.string()).optional(),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		nativeFunctionMatchingViewRequestSchema = z.discriminatedUnion("collection", [z.strictObject({
			...page$5,
			collection: z.literal("matches"),
			fields: z.array(matchRow.keyof()).optional()
		}), z.strictObject({
			...page$5,
			collection: z.literal("functions"),
			sides: z.array(z.enum(["left", "right"])).optional(),
			names: z.array(z.string()).optional(),
			fields: z.array(functionRow.keyof()).optional()
		})]);
		nativeFunctionMatchingViewItemsSchema = z.union([z.array(matchRow.partial().required({
			match_id: true,
			state: true,
			left_count: true,
			right_count: true
		})), z.array(functionRow.partial().required({
			function_id: true,
			match_id: true,
			state: true,
			side: true,
			inventory_evidence_id: true,
			source_index: true,
			address: true,
			evidence_links: true
		}))]);
		nativeFunctionMatchingViewContextSchema = nativeFunctionMatchingContextSchema;
		checked = new WeakMap();
		checkedReport = (parent) => {
			const source = parent.normalizedResult;
			const reusable = typeof source === "object" && source !== null && parent.sealedResult === true && isImmutableJsonSnapshot(source);
			const cached = reusable ? checked.get(source) : undefined;
			if (cached !== undefined) return ok(cached);
			const parsed = parseAnalysisViewResult(nativeFunctionMatchingSchema, parent);
			if (!parsed.ok) return parsed;
			const entry = { report: reusable ? source : parsed.value };
			if (reusable) checked.set(source, entry);
			return ok(entry);
		};
		functionRows = (entry) => {
			if (entry.functions !== undefined) return entry.functions;
			const functions = [];
			for (const match of entry.report.matches) for (const side of ["left", "right"]) for (const member of match[side]) functions.push({
				member,
				match_id: match.match_id,
				state: match.state,
				side
			});
			entry.functions = functions;
			return functions;
		};
		sharedContext = (parent, report) => ({
			parent_evidence_id: parent.evidenceId,
			parent_operation: "match_native_functions",
			parent_digest: parent.evidenceId.slice(3),
			artifact: null,
			limitations: boundedViewMessages([...parent.limitations, ...report.limitations], parent.evidenceId, "limitations"),
			unknowns: ["Unpaired observations and page exhaustion do not establish binary-wide function absence or behavioral equivalence."]
		});
		selected = (values) => values === undefined ? undefined : new Set(values);
		filterRows = (entry, view) => {
			const key = JSON.stringify([
				view.collection,
				view.states,
				view.match_ids,
				view.function_ids,
				view.collection === "functions" ? view.sides : null,
				view.collection === "functions" ? view.names : null
			]);
			if (entry.recent?.key === key) return entry.recent.rows;
			const states = selected(view.states), ids = selected(view.match_ids), functions = selected(view.function_ids), sides = selected(view.collection === "functions" ? view.sides : undefined), names = selected(view.collection === "functions" ? view.names : undefined);
			const matchesIdentity = (row) => (states === undefined || states.has(row.state)) && (ids === undefined || ids.has(row.match_id));
			const rows = [];
			if (view.collection === "matches") entry.report.matches.forEach((row, index) => {
				if (matchesIdentity(row) && (functions === undefined || [...row.left, ...row.right].some((member) => functions.has(member.function_id)))) rows.push(index);
			});
			else functionRows(entry).forEach((row, index) => {
				if (matchesIdentity(row) && (functions === undefined || functions.has(row.member.function_id)) && (sides === undefined || sides.has(row.side)) && (names === undefined || names.has(row.member.name))) rows.push(index);
			});
			const count = entry.report.left.functions + entry.report.right.functions;
			if (key.length <= Math.max(256, count * 8)) entry.recent = {
				key,
				rows
			};
			return rows;
		};
		selectedItems = (entry, view, rows) => {
			const indices = rows.slice(view.offset, view.offset + view.limit);
			const defaults = view.collection === "matches" ? [
				"match_id",
				"state",
				"basis",
				"reason",
				"left_count",
				"right_count",
				"compare_functions_input"
			] : [
				"function_id",
				"match_id",
				"state",
				"side",
				"inventory_evidence_id",
				"source_index",
				"address",
				"name",
				"body_sha256",
				"structural_candidate_sha256",
				"body_bytes",
				"dossier_evidence_id",
				"evidence_links"
			];
			const fields = new Set(view.fields ?? defaults);
			const columns = (row) => Object.fromEntries([...fields].map((field) => [field, row[field]]));
			if (view.collection === "matches") return indices.map((index) => {
				const row = entry.report.matches[index], left_count = row.left.length, right_count = row.right.length;
				return {
					...columns({
						...row,
						left_count,
						right_count
					}),
					match_id: row.match_id,
					state: row.state,
					left_count,
					right_count
				};
			});
			const functions = functionRows(entry);
			return indices.map((index) => {
				const row = functions[index], member = row.member;
				return {
					...columns({
						...member,
						match_id: row.match_id,
						state: row.state,
						side: row.side
					}),
					function_id: member.function_id,
					match_id: row.match_id,
					state: row.state,
					side: row.side,
					inventory_evidence_id: member.inventory_evidence_id,
					source_index: member.source_index,
					address: member.address,
					evidence_links: member.evidence_links
				};
			});
		};
		projectNativeFunctionMatchingView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "function-matches") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Native matching supports summary and function-matches pages"
			}]));
			const parsed = checkedReport(parent);
			if (!parsed.ok) return parsed;
			const entry = parsed.value;
			const { matches: _matches, limitations: _limitations, ...context } = entry.report;
			const shared = sharedContext(parent, entry.report);
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: context,
				coverage: completeWithinViewCoverage(1, 1)
			});
			const rows = filterRows(entry, view), items = selectedItems(entry, view, rows);
			return ok({
				kind: "function-matches",
				view,
				...shared,
				...context,
				items,
				coverage: pageViewCoverage(view.offset, items.length, rows.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/protobufCaptureView.js
var body, bodyRow, frameRow, fieldRow, page$4, protobufViewRequestSchema, protobufViewItemsSchema, protobufViewContextSchema, checkedBodies, fieldQueries, fieldSelection, selectFields$2, projectProtobufCapturePage;
function init_protobufCaptureView() {
	return (init_protobufCaptureView = __esmMin((() => {
		init_immutableJson();
		init_protobufWire();
		init_analysisViewCoverage();
		body = {
			record_ordinal: z.number().int().nonnegative(),
			body_pointer: z.string(),
			body_sha256: z.string(),
			body_status: protobufDecodingSchema.shape.status,
			offset_basis: protobufDecodingSchema.shape.offset_basis
		};
		bodyRow = protobufDecodingObjectSchema.omit({
			pointer: true,
			body_sha256: true,
			offset_basis: true,
			frames: true,
			fields: true
		}).extend({
			...body,
			frame_count: z.number().int().nonnegative(),
			field_count: z.number().int().nonnegative()
		});
		frameRow = protobufFrameSchema.extend(body);
		fieldRow = protobufFieldSchema.extend(body);
		page$4 = {
			kind: z.literal("protobuf"),
			record_ordinals: z.array(z.number().int().nonnegative()).optional(),
			body_pointers: z.array(z.string()).optional(),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		protobufViewRequestSchema = z.discriminatedUnion("collection", [
			z.strictObject({
				...page$4,
				collection: z.literal("bodies"),
				fields: z.array(bodyRow.keyof()).optional()
			}),
			z.strictObject({
				...page$4,
				collection: z.literal("frames"),
				frame_indices: z.array(z.number().int().nonnegative()).optional(),
				fields: z.array(frameRow.keyof()).optional()
			}),
			z.strictObject({
				...page$4,
				collection: z.literal("fields"),
				frame_indices: z.array(z.number().int().nonnegative()).optional(),
				field_ids: z.array(z.string()).optional(),
				field_numbers: z.array(z.number().int().positive()).optional(),
				schema_names: z.array(z.string()).optional(),
				fields: z.array(fieldRow.keyof()).optional()
			})
		]);
		protobufViewItemsSchema = z.union([
			z.array(bodyRow.partial().required({
				record_ordinal: true,
				body_pointer: true,
				body_sha256: true,
				body_status: true,
				offset_basis: true
			})),
			z.array(frameRow.partial().required({
				record_ordinal: true,
				body_pointer: true,
				body_sha256: true,
				body_status: true,
				offset_basis: true,
				index: true,
				offset: true
			})),
			z.array(fieldRow.partial().required({
				record_ordinal: true,
				body_pointer: true,
				body_sha256: true,
				body_status: true,
				offset_basis: true,
				index: true,
				frame_index: true,
				field_id: true,
				parent_field_id: true,
				offset: true,
				payload_offset: true,
				payload_bytes: true
			}))
		]);
		protobufViewContextSchema = z.strictObject({
			source_status: z.enum([
				"complete",
				"partial",
				"unknown"
			]),
			retained_decoded_bodies: z.number().int().nonnegative()
		});
		checkedBodies = new WeakMap();
		fieldQueries = new WeakMap();
		fieldSelection = (report, bodies, view, reusable) => {
			if (view.frame_indices === undefined && view.field_ids === undefined && view.field_numbers === undefined && view.schema_names === undefined) return undefined;
			const key = JSON.stringify([
				view.frame_indices,
				view.field_ids,
				view.field_numbers,
				view.schema_names
			]);
			const cached = reusable ? fieldQueries.get(report) : undefined;
			if (cached?.key === key) return cached;
			const referenceBytes = bodies.reduce((sum, body) => sum + body.decoding.fields.length * 8, 0);
			const cache = reusable && key.length * 2 <= referenceBytes;
			const selection = {
				key,
				frames: view.frame_indices === undefined ? undefined : new Set(view.frame_indices),
				ids: view.field_ids === undefined ? undefined : new Set(view.field_ids),
				numbers: view.field_numbers === undefined ? undefined : new Set(view.field_numbers),
				names: view.schema_names === undefined ? undefined : new Set(view.schema_names),
				rows: cache ? new WeakMap() : undefined
			};
			if (cache) fieldQueries.set(report, selection);
			return selection;
		};
		selectFields$2 = (decoding, selection) => {
			if (selection === undefined) return decoding.fields;
			const cached = selection.rows?.get(decoding);
			if (cached !== undefined) return cached;
			const { frames, ids, numbers, names } = selection;
			const rows = decoding.fields.filter((field) => (frames === undefined || frames.has(field.frame_index)) && (ids === undefined || ids.has(field.field_id)) && (numbers === undefined || numbers.has(field.number)) && (names === undefined || field.schema_name !== undefined && names.has(field.schema_name)));
			selection.rows?.set(decoding, rows);
			return rows;
		};
		projectProtobufCapturePage = (report, view) => {
			const reusable = isImmutableJsonSnapshot(report);
			let bodies = reusable ? checkedBodies.get(report) : undefined;
			if (bodies === undefined) {
				bodies = report.records.flatMap((record) => (record.protobuf ?? []).map((decoding) => ({
					recordOrdinal: record.ordinal,
					decoding
				})));
				if (reusable) checkedBodies.set(report, bodies);
			}
			const selection = view.collection === "fields" ? fieldSelection(report, bodies, view, reusable) : undefined;
			const ordinals = view.record_ordinals === undefined ? undefined : new Set(view.record_ordinals);
			const pointers = view.body_pointers === undefined ? undefined : new Set(view.body_pointers);
			const frames = "frame_indices" in view && view.frame_indices !== undefined ? new Set(view.frame_indices) : undefined;
			let total = 0;
			const items = [];
			let sourceStatus = report.protobuf_coverage?.status === "partial" ? "partial" : bodies.length === 0 ? "unknown" : "complete";
			for (const entry of bodies) {
				const { recordOrdinal, decoding } = entry;
				if (ordinals !== undefined && !ordinals.has(recordOrdinal) || pointers !== undefined && !pointers.has(decoding.pointer)) continue;
				if (decoding.status !== "complete") sourceStatus = "partial";
				const rows = view.collection === "bodies" ? [decoding] : view.collection === "frames" ? frames === undefined ? decoding.frames : decoding.frames.filter((frame) => frames.has(frame.index)) : selectFields$2(decoding, selection);
				const from = Math.max(0, view.offset - total);
				const to = Math.min(rows.length, view.offset + view.limit - total);
				for (let index = from; index < to; index++) {
					const source = rows[index];
					const row = view.collection === "bodies" ? {
						...decoding,
						frame_count: decoding.frames.length,
						field_count: decoding.fields.length
					} : source;
					const mandatory = [
						"record_ordinal",
						"body_pointer",
						"body_sha256",
						"body_status",
						"offset_basis",
						...view.collection === "fields" ? [
							"index",
							"frame_index",
							"field_id",
							"parent_field_id",
							"offset",
							"payload_offset",
							"payload_bytes"
						] : view.collection === "frames" ? ["index", "offset"] : []
					];
					const keys = view.fields ?? Object.keys(row).filter((key) => ![
						"frames",
						"fields",
						"pointer",
						"text",
						"schema_value",
						"schema_enum_values"
					].includes(key));
					const chosen = new Set([...mandatory, ...keys]);
					const projected = {
						record_ordinal: recordOrdinal,
						body_pointer: decoding.pointer,
						body_sha256: decoding.body_sha256,
						body_status: decoding.status,
						offset_basis: decoding.offset_basis
					};
					for (const key of keys) if (chosen.has(key) && Object.hasOwn(row, key) && ![
						"frames",
						"fields",
						"pointer"
					].includes(key)) projected[key] = row[key];
					for (const key of mandatory) if (Object.hasOwn(row, key)) projected[key] = row[key];
					items.push(projected);
				}
				total += rows.length;
			}
			return {
				kind: "protobuf",
				view,
				items: protobufViewItemsSchema.parse(items),
				source_status: sourceStatus,
				retained_decoded_bodies: bodies.length,
				coverage: pageViewCoverage(view.offset, items.length, total)
			};
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/nativeInventoryView.js
var inventoryRecordSchema, fieldSchema, nativeInventoryViewRequestSchema, nativeInventoryViewRowSchema, nativeInventoryViewContext, nativeInventorySummarySchema, checkedNames, checkedStrings, readRows, projectNativeInventoryView;
function init_nativeInventoryView() {
	return (init_nativeInventoryView = __esmMin((() => {
		init_hopperValues();
		init_immutableJson();
		init_jsonValue();
		init_nativeInventory();
		init_digests();
		init_evidence();
		init_result();
		init_analysisViewErrors();
		init_analysisViewParent();
		init_analysisViewCoverage();
		inventoryRecordSchema = addressedValueSchema.extend({
			provider_value: analysisStringSchema.shape.provider_value,
			decoding: analysisStringSchema.shape.decoding,
			string: z.union([analysisStringSchema.shape.string, addressedValueSchema.shape.string])
		});
		fieldSchema = inventoryRecordSchema.keyof();
		nativeInventoryViewRequestSchema = z.strictObject({
			kind: z.literal("native-inventory"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64),
			fields: z.array(fieldSchema).exactOptional().describe("Select record fields; address and source_index preserve identity. Selecting value also retains its string and decoding qualifications. Omit for every recorded field. Search tools filter before retention.")
		});
		nativeInventoryViewRowSchema = z.strictObject({
			source_index: z.number().int().nonnegative(),
			record: inventoryRecordSchema.partial().required({ address: true })
		});
		nativeInventoryViewContext = {
			source_provider: providerSchema.nullable(),
			source_analysis_profile_digest: digestSchema.nullable(),
			source_parameters: jsonValueSchema
		};
		nativeInventorySummarySchema = z.strictObject({
			collection: z.enum([
				"procedures",
				"strings",
				"names"
			]),
			row_count: z.number().int().nonnegative(),
			discovery_coverage: z.literal("unknown"),
			selectable_fields: z.array(fieldSchema)
		});
		checkedNames = new WeakSet();
		checkedStrings = new WeakSet();
		readRows = (parent, strings) => {
			const checked = strings ? checkedStrings : checkedNames;
			const source = parent.normalizedResult;
			if (Array.isArray(source) && checked.has(source)) return ok(source);
			const parsed = strings ? parseAnalysisViewResult(nativeInventoryRowsSchemas.strings, parent) : parseAnalysisViewResult(nativeInventoryRowsSchemas.names, parent);
			if (!parsed.ok) return parsed;
			if (Array.isArray(source) && parent.sealedResult === true && canBorrowParsedJsonSnapshot(source, parsed.value)) {
				checked.add(source);
				return ok(source);
			}
			return parsed;
		};
		projectNativeInventoryView = (parent, view) => {
			if (!isNativeInventoryOperation(parent.operation) || view.kind !== "summary" && view.kind !== "native-inventory") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Native inventory Evidence supports summary and native-inventory views."
			}]));
			const strings = parent.operation === "list_strings" || parent.operation === "search_strings";
			const parsed = readRows(parent, strings);
			if (!parsed.ok) return parsed;
			const rows = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: parent.operation,
				parent_digest: parent.evidenceId.slice(3),
				artifact: parent.artifact ?? null,
				source_provider: parent.provider ?? null,
				source_analysis_profile_digest: parent.analysisProfileDigest ?? null,
				source_parameters: jsonValueSchema.parse(parent.parameters ?? null),
				limitations: boundedViewMessages(parent.limitations, parent.evidenceId, "limitations"),
				unknowns: ["Counts and paging describe the retained provider-reported rows, not complete discovery of every program object. Missing matches do not establish absence outside that observation.", ...parent.artifact == null ? ["No artifact identity was bound to the source Evidence."] : []]
			};
			if (view.kind === "summary") return ok({
				...shared,
				kind: "summary",
				view,
				summary: {
					collection: strings ? "strings" : parent.operation === "list_names" ? "names" : "procedures",
					row_count: rows.length,
					discovery_coverage: "unknown",
					selectable_fields: fieldSchema.options
				},
				coverage: completeWithinViewCoverage(rows.length, rows.length)
			});
			const fields = view.fields === undefined ? undefined : [...new Set(view.fields)].filter((field) => field !== "address");
			const selectingValue = fields?.includes("value") === true;
			const selected = rows.slice(view.offset, view.offset + view.limit);
			return ok({
				...shared,
				kind: "native-inventory",
				view,
				rows: selected.map((record, index) => ({
					source_index: view.offset + index,
					record: fields === undefined ? record : {
						address: record.address,
						...selectingValue && record.string !== undefined ? { string: record.string } : {},
						...selectingValue && record.decoding !== undefined ? { decoding: record.decoding } : {},
						...Object.fromEntries(fields.filter((field) => Object.hasOwn(record, field)).map((field) => [field, record[field]]))
					}
				})),
				coverage: pageViewCoverage(view.offset, selected.length, rows.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/desktopApplication.js
var desktopFamilySchema, inspectDesktopApplicationInputSchema, byteOffset$1, fact, desktopFactSchema, desktopFileSchema, desktopOmissionSchema, desktopCandidateSchema, desktopComponentSchema, desktopProbeSchema, desktopCoverageSchema, desktopApplicationSchema;
function init_desktopApplication() {
	return (init_desktopApplication = __esmMin((() => {
		init_digests();
		init_localPath();
		init_artifactGraph();
		desktopFamilySchema = z.enum([
			"dotnet",
			"unity-mono",
			"unity-il2cpp",
			"unreal",
			"godot",
			"gamemaker",
			"electron"
		]);
		inspectDesktopApplicationInputSchema = z.strictObject({
			path: localPathStringSchema,
			max_entries: z.number().int().positive().max(1e5).default(2e4),
			max_probe_bytes: z.number().int().min(4096).max(64 * 1024 * 1024).default(8 * 1024 * 1024)
		});
		byteOffset$1 = z.number().int().nonnegative();
		fact = (kind, value) => z.strictObject({
			kind: z.literal(kind),
			offset: byteOffset$1,
			value
		});
		desktopFactSchema = z.discriminatedUnion("kind", [
			fact("pe-cli-directory", z.strictObject({
				rva: byteOffset$1,
				bytes: byteOffset$1
			})),
			fact("unity-assembly-reference", z.strictObject({
				name: z.string(),
				token: z.string(),
				managed_directory: z.string()
			})),
			fact("native-image-header", z.union([z.strictObject({
				format: z.literal("pe"),
				machine: byteOffset$1
			}), z.strictObject({
				format: z.enum(["elf", "mach-o"]),
				signature: z.string()
			})])),
			fact("il2cpp-metadata-header", z.strictObject({
				magic: z.literal("0xfab11baf"),
				raw_version: byteOffset$1.nullable()
			})),
			fact("godot-pck-header", z.strictObject({
				pack_version: byteOffset$1,
				engine_version: z.array(byteOffset$1).length(3),
				placement: z.enum(["standalone", "embedded-trailer"])
			})),
			fact("gamemaker-form-header", z.strictObject({
				container: z.literal("FORM"),
				first_chunk: z.literal("GEN8")
			})),
			z.strictObject({
				kind: z.literal("il2cpp-library-convention"),
				offset: z.null(),
				value: z.string()
			}),
			z.strictObject({
				kind: z.literal("electron-asar-convention"),
				offset: z.null(),
				value: z.string()
			}),
			z.strictObject({
				kind: z.literal("unreal-container-convention"),
				offset: byteOffset$1.nullable(),
				value: z.union([z.string(), z.strictObject({ format: z.literal("IoStore TOC") })])
			})
		]);
		desktopFileSchema = z.strictObject({
			file_id: prefixedDigestSchema("dsf"),
			path: z.string(),
			local_path: localPathStringSchema,
			kind: z.enum([
				"file",
				"directory",
				"symlink"
			]),
			bytes: z.number().int().nonnegative().nullable(),
			identity: z.strictObject({
				device: z.string(),
				inode: z.string(),
				size: z.string(),
				mode: z.string(),
				mtime_ns: z.string(),
				ctime_ns: z.string()
			}).nullable(),
			read_status: z.enum([
				"not-selected",
				"examined",
				"partial",
				"unavailable"
			]),
			ranges: z.array(z.strictObject({
				offset: z.number().int().nonnegative(),
				bytes: z.number().int().nonnegative(),
				sha256: digestSchema
			})),
			facts: z.array(desktopFactSchema),
			issues: z.array(z.string())
		});
		desktopOmissionSchema = z.strictObject({
			omission_id: prefixedDigestSchema("dso"),
			path: z.string(),
			kind: artifactTraversalOmissionKindSchema
		});
		desktopCandidateSchema = z.strictObject({
			candidate_id: prefixedDigestSchema("dsc"),
			family: desktopFamilySchema,
			confidence: z.enum(["derived", "inferred"]),
			basis_file_ids: z.array(prefixedDigestSchema("dsf")).min(1),
			rationale: z.string()
		});
		desktopComponentSchema = z.strictObject({
			component_id: prefixedDigestSchema("dsm"),
			name: z.string(),
			category: z.enum(["mod-loader", "protection"]),
			basis_file_ids: z.array(prefixedDigestSchema("dsf")).min(1),
			confidence: z.literal("inferred"),
			runtime_presence: z.literal("unknown")
		});
		desktopProbeSchema = z.strictObject({
			probe_id: prefixedDigestSchema("dsp"),
			operation: z.enum([
				"inspect_managed_artifact",
				"inspect_il2cpp_metadata",
				"open_binary",
				"analyze_javascript_application"
			]),
			path: localPathStringSchema,
			file_id: prefixedDigestSchema("dsf"),
			rationale: z.string(),
			confidence: z.literal("inferred")
		});
		desktopCoverageSchema = z.strictObject({
			status: z.enum(["complete-within-scan", "partial"]),
			entries_examined: z.number().int().nonnegative(),
			files_probed: z.number().int().nonnegative(),
			bytes_read: z.number().int().nonnegative(),
			symlinks_not_followed: z.number().int().nonnegative(),
			special_entries_omitted: z.number().int().nonnegative(),
			limits: z.strictObject({
				max_entries: inspectDesktopApplicationInputSchema.shape.max_entries.removeDefault(),
				max_probe_bytes: inspectDesktopApplicationInputSchema.shape.max_probe_bytes.removeDefault()
			})
		});
		desktopApplicationSchema = z.strictObject({
			root: z.strictObject({
				path: localPathStringSchema,
				canonical_path: localPathStringSchema,
				namespace_id: prefixedDigestSchema("dsr"),
				identity: z.strictObject({
					device: z.string(),
					inode: z.string()
				}),
				snapshot_sha256: digestSchema,
				identity_scope: z.literal("examined-metadata-and-read-ranges")
			}),
			files: z.array(desktopFileSchema),
			omissions: z.array(desktopOmissionSchema),
			candidates: z.array(desktopCandidateSchema),
			components: z.array(desktopComponentSchema),
			next_probes: z.array(desktopProbeSchema),
			coverage: desktopCoverageSchema,
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/desktopApplicationView.js
var DIAGNOSTIC_PREVIEW_FILES, DIAGNOSTIC_PREVIEW_UNITS, hasProbeIssues, diagnosticTextPreview, page$3, desktopViewRequestSchema, desktopViewItemsSchema, desktopSummarySchema, validatedParents, projectDesktopApplicationView;
function init_desktopApplicationView() {
	return (init_desktopApplicationView = __esmMin((() => {
		init_desktopApplication();
		init_analysisViewErrors();
		init_analysisViewParent();
		init_analysisViewCoverage();
		init_result();
		DIAGNOSTIC_PREVIEW_FILES = 2;
		DIAGNOSTIC_PREVIEW_UNITS = 256;
		hasProbeIssues = (file) => file.issues.length > 0;
		diagnosticTextPreview = (value) => {
			let end = Math.min(value.length, DIAGNOSTIC_PREVIEW_UNITS);
			const last = value.charCodeAt(end - 1);
			if (end < value.length && last >= 55296 && last <= 56319) end--;
			return {
				text: value.slice(0, end),
				truncated: end < value.length
			};
		};
		page$3 = {
			kind: z.literal("desktop-application"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		desktopViewRequestSchema = z.discriminatedUnion("collection", [
			z.strictObject({
				...page$3,
				collection: z.literal("files"),
				paths: z.array(z.string()).optional(),
				file_ids: z.array(desktopFileSchema.shape.file_id).optional(),
				has_issues: z.boolean().optional(),
				fields: z.array(desktopFileSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$3,
				collection: z.literal("candidates"),
				families: z.array(desktopFamilySchema).optional(),
				fields: z.array(desktopCandidateSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$3,
				collection: z.literal("omissions"),
				paths: z.array(z.string()).optional(),
				omission_ids: z.array(desktopOmissionSchema.shape.omission_id).optional(),
				fields: z.array(desktopOmissionSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$3,
				collection: z.literal("components"),
				fields: z.array(desktopComponentSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$3,
				collection: z.literal("next_probes"),
				fields: z.array(desktopProbeSchema.keyof()).optional()
			})
		]);
		desktopViewItemsSchema = z.array(z.union([
			desktopFileSchema.partial(),
			desktopOmissionSchema.partial(),
			desktopCandidateSchema.partial(),
			desktopComponentSchema.partial(),
			desktopProbeSchema.partial()
		]));
		desktopSummarySchema = z.strictObject({
			root: desktopApplicationSchema.shape.root,
			source_coverage: desktopCoverageSchema,
			available_counts: z.strictObject({
				files: z.number().int().nonnegative(),
				omissions: z.number().int().nonnegative(),
				candidates: z.number().int().nonnegative(),
				components: z.number().int().nonnegative(),
				next_probes: z.number().int().nonnegative()
			}),
			probe_issues: z.strictObject({
				file_count: z.number().int().nonnegative(),
				issue_count: z.number().int().nonnegative(),
				preview: z.array(z.strictObject({
					file_id: desktopFileSchema.shape.file_id,
					path_preview: z.string(),
					read_status: desktopFileSchema.shape.read_status,
					issue_count: z.number().int().positive(),
					first_issue_preview: z.string(),
					text_truncated: z.boolean()
				})).max(DIAGNOSTIC_PREVIEW_FILES),
				preview_truncated: z.boolean().describe("More retained files have probe issues than fit in the preview.")
			}),
			candidates: z.array(desktopCandidateSchema.omit({ basis_file_ids: true }).extend({
				basis_file_count: z.number().int().positive(),
				basis_path_preview: z.array(z.string())
			})),
			components: z.array(desktopComponentSchema.omit({ basis_file_ids: true }).extend({
				basis_file_count: z.number().int().positive(),
				basis_path_preview: z.array(z.string())
			})),
			next_probe_groups: z.array(z.strictObject({
				operation: desktopProbeSchema.shape.operation,
				count: z.number().int().positive(),
				example: desktopProbeSchema
			}))
		});
		validatedParents = new WeakSet();
		projectDesktopApplicationView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "desktop-application") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Desktop directory Evidence supports summary and desktop-application views."
			}]));
			const key = typeof parent.normalizedResult === "object" && parent.normalizedResult !== null ? parent.normalizedResult : undefined;
			const reusable = parent.sealedResult === true && key !== undefined && Object.isFrozen(key);
			let report = reusable && validatedParents.has(key) ? key : undefined;
			if (report === undefined) {
				const parsed = parseAnalysisViewResult(desktopApplicationSchema, parent);
				if (!parsed.ok) return parsed;
				report = parsed.value;
				if (reusable) {
					report = key;
					validatedParents.add(key);
				}
			}
			if (parent.subject === undefined || parent.subject === null || parent.subject.format !== "directory" || parent.subject.local_path !== report.root.path || parent.subject.digest.sha256 !== report.root.snapshot_sha256) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Parent must identify the same examined directory snapshot."
			}]));
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_desktop_application",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.root.path,
					sha256: report.root.snapshot_sha256
				},
				limitations: [...new Set([...parent.limitations, ...report.limitations])],
				unknowns: ["Runtime behavior and unread bytes remain unknown.", ...report.coverage.status === "partial" ? ["Source inspection is partial; an exhausted page does not establish absence."] : []]
			};
			if (view.kind === "summary") {
				const byId = new Map();
				const probeIssues = {
					file_count: 0,
					issue_count: 0,
					preview: [],
					preview_truncated: false
				};
				for (const file of report.files) {
					byId.set(file.file_id, file.path);
					if (!hasProbeIssues(file)) continue;
					probeIssues.file_count++;
					probeIssues.issue_count += file.issues.length;
					if (probeIssues.preview.length === DIAGNOSTIC_PREVIEW_FILES) continue;
					const firstIssue = file.issues[0];
					if (firstIssue === undefined) continue;
					const path = diagnosticTextPreview(file.path);
					const issue = diagnosticTextPreview(firstIssue);
					probeIssues.preview.push({
						file_id: file.file_id,
						path_preview: path.text,
						read_status: file.read_status,
						issue_count: file.issues.length,
						first_issue_preview: issue.text,
						text_truncated: path.truncated || issue.truncated
					});
				}
				probeIssues.preview_truncated = probeIssues.file_count > probeIssues.preview.length;
				const summarizeBasis = (row) => {
					const { basis_file_ids, ...value } = row;
					return {
						...value,
						basis_file_count: basis_file_ids.length,
						basis_path_preview: basis_file_ids.slice(0, 2).map((id) => byId.get(id) ?? id)
					};
				};
				const groups = new Map();
				for (const probe of report.next_probes) {
					const group = groups.get(probe.operation);
					if (group === undefined) groups.set(probe.operation, {
						operation: probe.operation,
						count: 1,
						example: probe
					});
					else group.count++;
				}
				return ok({
					kind: "summary",
					view,
					...shared,
					summary: {
						root: report.root,
						source_coverage: report.coverage,
						available_counts: {
							files: report.files.length,
							omissions: report.omissions.length,
							candidates: report.candidates.length,
							components: report.components.length,
							next_probes: report.next_probes.length
						},
						probe_issues: probeIssues,
						candidates: report.candidates.map(summarizeBasis),
						components: report.components.map(summarizeBasis),
						next_probe_groups: [...groups.values()]
					},
					coverage: completeWithinViewCoverage(report.files.length, report.files.length)
				});
			}
			let rows = report[view.collection];
			if (view.collection === "files" || view.collection === "omissions") {
				const paths = view.paths === undefined ? undefined : new Set(view.paths);
				const ids = view.collection === "files" ? view.file_ids : view.omission_ids;
				const selected = ids === undefined ? undefined : new Set(ids);
				const withIssues = view.collection === "files" ? view.has_issues : undefined;
				if (paths !== undefined || selected !== undefined || withIssues !== undefined) rows = report[view.collection].filter((row) => (paths === undefined || paths.has(row.path)) && (selected === undefined || selected.has("file_id" in row ? row.file_id : row.omission_id)) && (withIssues === undefined || "issues" in row && hasProbeIssues(row) === withIssues));
			}
			if (view.collection === "candidates" && view.families !== undefined) {
				const selected = new Set(view.families);
				rows = report.candidates.filter((row) => selected.has(row.family));
			}
			const idField = {
				files: "file_id",
				omissions: "omission_id",
				candidates: "candidate_id",
				components: "component_id",
				next_probes: "probe_id"
			}[view.collection];
			const fields = view.fields === undefined ? undefined : new Set([idField, ...view.fields]);
			const items = rows.slice(view.offset, view.offset + view.limit).map((row) => fields === undefined ? row : Object.fromEntries(Object.entries(row).filter(([field]) => fields.has(field))));
			return ok({
				kind: "desktop-application",
				view,
				...shared,
				source_coverage: report.coverage,
				items: desktopViewItemsSchema.parse(items),
				coverage: pageViewCoverage(view.offset, items.length, rows.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/javascriptModuleReferences.js
var moduleKindSchema, javascriptModuleReferencesRequestSchema, basisSchema, javascriptModuleReferenceSchema;
function init_javascriptModuleReferences() {
	return (init_javascriptModuleReferences = __esmMin((() => {
		init_digests();
		init_javascriptApplicationEvidenceSchemas();
		moduleKindSchema = z.enum([
			"javascript-asset",
			"javascript-module",
			"source-module"
		]);
		javascriptModuleReferencesRequestSchema = z.strictObject({
			kind: z.literal("javascript"),
			collection: z.literal("modules"),
			projection: z.literal("references"),
			where: z.strictObject({
				path: z.string().nullable().optional(),
				kind: moduleKindSchema.optional()
			}).default({}),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		basisSchema = z.strictObject({
			authority: applicationGraphEvidenceSchema.shape.authority,
			state: applicationGraphEvidenceSchema.shape.state,
			confidence: applicationGraphEvidenceSchema.shape.confidence
		});
		javascriptModuleReferenceSchema = z.strictObject({
			node_id: prefixedDigestSchema("jag_node"),
			kind: moduleKindSchema,
			path: z.string().nullable(),
			identity: applicationNodeIdentitySchema,
			retained_source_range_count: z.number().int().nonnegative(),
			basis: z.array(basisSchema).min(1)
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/javascriptApplicationCoverage.js
var javascriptApplicationSourceCoverageSchema, javascriptApplicationSourceCoverage;
function init_javascriptApplicationCoverage() {
	return (init_javascriptApplicationCoverage = __esmMin((() => {
		init_javascriptApplicationEvidenceSchemas();
		init_javascriptSemanticGraphSchemas();
		init_javascriptSourceSelection();
		javascriptApplicationSourceCoverageSchema = z.strictObject({
			source_selection: javaScriptSourceSelectionSchema.exactOptional(),
			application: applicationCoverageSchema,
			semantic: javaScriptSemanticGraphInputSchema.shape.coverage.omit({ families: true }),
			application_unknown_count: z.number().int().nonnegative(),
			semantic_unknown_count: z.number().int().nonnegative()
		});
		javascriptApplicationSourceCoverage = (analysis) => {
			const { families: _families, ...semantic } = analysis.semantic_graph.coverage;
			return {
				...analysis.source_selection === undefined ? {} : { source_selection: analysis.source_selection },
				application: analysis.graph.coverage,
				semantic,
				application_unknown_count: analysis.graph.nodes.reduce((count, node) => count + Number(node.kind === "unknown"), 0),
				semantic_unknown_count: analysis.semantic_graph.unknowns.length
			};
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/javascriptFactsView.js
var propertyKeySchema, javascriptFactsViewRequestSchema, javascriptFactRowSchema, observationPath, projectJavaScriptFacts;
function init_javascriptFactsView() {
	return (init_javascriptFactsView = __esmMin((() => {
		init_javascriptApplicationGraphSchemas();
		propertyKeySchema = applicationNodeObservationSchema.shape.properties.keyType;
		javascriptFactsViewRequestSchema = z.strictObject({
			kind: z.literal("javascript-facts"),
			where: z.strictObject({
				paths: z.array(z.string()).optional().describe("Exact Evidence artifact-path or source-range source strings. Omitted includes unknown locations; [] matches none. No filesystem lookup or path normalization."),
				kinds: z.array(applicationNodeSchema.shape.kind).optional()
			}).default({}),
			property_keys: z.array(propertyKeySchema).describe("Exact retained observation-property names to read; [] requests identities/provenance only. Missing properties remain omitted, distinct from retained null. No cross-observation merging or inferred values."),
			include_available_property_keys: z.boolean().default(false).describe("Opt into original property names for each returned observation, without unselected values. Use with property_keys: [] to discover fields before reading them."),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		javascriptFactRowSchema = applicationNodeSchema.pick({
			node_id: true,
			kind: true,
			identity: true
		}).extend(applicationNodeObservationSchema.pick({
			observation_id: true,
			source_map_reference: true,
			properties: true,
			evidence: true
		}).shape).extend({ available_property_keys: z.array(propertyKeySchema).exactOptional() });
		observationPath = (observation) => {
			const { location } = observation.evidence;
			if (!location.available) return null;
			if (location.value.kind === "artifact-path") return location.value.path;
			if (location.value.kind === "source-range") return location.value.source;
			return null;
		};
		projectJavaScriptFacts = (nodes, view) => {
			const paths = view.where.paths === undefined ? null : new Set(view.where.paths);
			const kinds = view.where.kinds === undefined ? null : new Set(view.where.kinds);
			if (paths?.size === 0 || kinds?.size === 0) return {
				rows: [],
				total: 0
			};
			const keys = [...new Set(view.property_keys)];
			const rows = [];
			let total = 0;
			for (const node of nodes) {
				if (kinds !== null && !kinds.has(node.kind)) continue;
				for (const observation of node.observations) {
					if (paths !== null) {
						const path = observationPath(observation);
						if (path === null || !paths.has(path)) continue;
					}
					total += 1;
					if (total <= view.offset || rows.length >= view.limit) continue;
					rows.push({
						node_id: node.node_id,
						kind: node.kind,
						identity: node.identity,
						observation_id: observation.observation_id,
						source_map_reference: observation.source_map_reference,
						...view.include_available_property_keys ? { available_property_keys: Object.keys(observation.properties).sort() } : {},
						properties: Object.fromEntries(keys.flatMap((key) => {
							const value = observation.properties[key];
							return value !== undefined && Object.hasOwn(observation.properties, key) ? [[key, value]] : [];
						})),
						evidence: observation.evidence
					});
				}
			}
			return {
				rows,
				total
			};
		};
	})))();
}

//#endregion
//#region dist/domain/native/binaryLayout.js
var unsignedHex, index, scalar, range, canonicalBase64, name, inspectBinaryLayoutInputSchema, binaryLayoutObjectSchema, binaryLayoutPayloadSchema, binaryLayoutSchema, validatedImmutableLayouts, safeParseOwnedBinaryLayout, validateRelocationReferences, validatePackedRelativeTables;
function init_binaryLayout() {
	return (init_binaryLayout = __esmMin((() => {
		init_immutableJson();
		init_localPath();
		init_stringPatterns();
		unsignedHex = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/);
		index = z.number().int().nonnegative();
		scalar = z.union([z.string(), z.number().int()]);
		range = z.strictObject({
			offset: unsignedHex,
			bytes: unsignedHex
		});
		canonicalBase64 = canonicalBase64Schema;
		name = z.strictObject({
			display: z.string(),
			bytes_base64: canonicalBase64.nullable(),
			location: range.nullable(),
			unknown_reason: z.string().nullable()
		});
		inspectBinaryLayoutInputSchema = z.strictObject({ path: localPathStringSchema.describe("Absolute filesystem path to the selected binary") });
		binaryLayoutObjectSchema = z.strictObject({
			artifact: z.strictObject({
				path: z.string().min(1),
				sha256: z.string().regex(/^[a-f0-9]{64}$/),
				bytes: index
			}),
			format: z.literal("elf"),
			architecture: z.strictObject({
				machine: z.literal("EM_X86_64"),
				bits: z.literal(64),
				byte_order: z.literal("little")
			}),
			image_type: z.enum([
				"ET_EXEC",
				"ET_DYN",
				"ET_REL"
			]),
			entry_point: z.strictObject({
				reported_value: unsignedHex,
				meaning: z.enum([
					"linked-virtual-address",
					"not-applicable",
					"absent"
				]),
				execution_status: z.literal("unknown")
			}),
			runtime_load_base: z.null(),
			sections: z.array(z.strictObject({
				index,
				name,
				name_offset: unsignedHex,
				type: scalar,
				header_location: range,
				address: unsignedHex,
				offset: unsignedHex,
				size: unsignedHex,
				alignment: unsignedHex,
				flags: unsignedHex,
				link: index,
				info: index,
				entry_size: unsignedHex,
				file_backing: z.enum(["file", "none"])
			})),
			segments: z.array(z.strictObject({
				index,
				type: scalar,
				header_location: range,
				offset: unsignedHex,
				file_size: unsignedHex,
				memory_size: unsignedHex,
				virtual_address: unsignedHex,
				physical_address: unsignedHex,
				alignment: unsignedHex,
				flags: unsignedHex,
				file_backing: z.enum(["file", "none"]),
				permissions: z.strictObject({
					read: z.boolean(),
					write: z.boolean(),
					execute: z.boolean()
				}).nullable()
			})),
			symbols: z.array(z.strictObject({
				table_index: index,
				entry_index: index,
				name,
				name_offset: unsignedHex,
				location: range,
				value: unsignedHex,
				value_meaning: z.enum([
					"undefined",
					"alignment",
					"absolute-value",
					"no-address",
					"unknown-section-index",
					"section-offset",
					"tls-offset",
					"linked-virtual-address"
				]),
				size: unsignedHex,
				binding: scalar,
				type: scalar,
				visibility: scalar,
				section_index: scalar
			})),
			relocations: z.array(z.strictObject({
				section_index: index,
				entry_index: index,
				reported_offset: unsignedHex,
				target: z.discriminatedUnion("kind", [
					z.strictObject({
						kind: z.literal("section-offset"),
						section_index: index,
						offset: unsignedHex
					}),
					z.strictObject({
						kind: z.literal("linked-virtual-address"),
						address: unsignedHex
					}),
					z.strictObject({
						kind: z.literal("unknown-section"),
						reported_section_index: index,
						offset: unsignedHex,
						unknown_reason: z.enum(["undefined-section-reference", "inactive-section-header"])
					})
				]),
				location: range,
				type: index,
				symbol_table_index: index,
				symbol_index: index,
				symbol_reference_meaning: z.enum(["zero-symbol-value", "symbol-table-entry"]),
				addend: z.string().regex(/^-?(?:0|[1-9][0-9]{0,18})$/).nullable()
			})),
			packed_relative_relocations: z.array(z.strictObject({
				section_index: index,
				location: range,
				encoded_bytes_base64: canonicalBase64,
				entries: z.array(z.strictObject({
					decoded_index: index,
					reported_offset: unsignedHex
				})),
				offset_meaning: z.enum(["linked-virtual-address", "unknown"]),
				evidence_kind: z.literal("derived"),
				entry_source_locations: z.null(),
				addends: z.null()
			})),
			relocation_inventory_completeness: z.literal("unknown"),
			linkage: z.strictObject({
				needed_libraries: z.array(name),
				interpreters: z.array(name),
				got: z.array(z.strictObject({
					display_name: z.string(),
					address: unsignedHex
				})),
				plt: z.array(z.strictObject({
					display_name: z.string(),
					address: unsignedHex
				})),
				convenience_maps_completeness: z.literal("unknown"),
				runtime_library_paths: z.null()
			}),
			mitigations: z.strictObject({
				evidence_kind: z.literal("inferred"),
				position_independent: z.boolean(),
				nx_indicator: z.boolean().nullable(),
				executable_stack_indicator: z.boolean(),
				stack_canary_indicator: z.boolean(),
				relro: z.enum(["Partial", "Full"]).nullable()
			}),
			diagnostics: z.strictObject({
				stdout: z.string(),
				stderr: z.string(),
				truncated: z.boolean()
			}),
			limitations: z.array(z.string())
		});
		binaryLayoutPayloadSchema = binaryLayoutObjectSchema.omit({
			artifact: true,
			diagnostics: true
		});
		binaryLayoutSchema = binaryLayoutObjectSchema.superRefine((value, context) => {
			const size = BigInt(value.artifact.bytes);
			const check = (offset, length, path) => {
				const start = BigInt(offset);
				const bytes = BigInt(length);
				if (start > size || bytes > size - start) context.addIssue({
					code: "custom",
					path,
					message: "Reported file-backed range lies outside the selected artifact."
				});
			};
			const checkLocation = (where, path) => check(where.offset, where.bytes, path);
			const checkName = (reported, path) => {
				if (reported.location !== null) checkLocation(reported.location, [...path, "location"]);
			};
			const expectedEntryMeaning = value.image_type === "ET_REL" ? "not-applicable" : value.entry_point.reported_value === "0x0" ? "absent" : "linked-virtual-address";
			if (value.entry_point.meaning !== expectedEntryMeaning) context.addIssue({
				code: "custom",
				path: ["entry_point", "meaning"],
				message: "Entry meaning must distinguish zero/unused fields from an actual linked address."
			});
			for (const [index, section] of value.sections.entries()) {
				if ((section.type === "SHT_SYMTAB" || section.type === "SHT_DYNSYM") && value.sections[section.link]?.type !== "SHT_STRTAB") context.addIssue({
					code: "custom",
					path: [
						"sections",
						index,
						"link"
					],
					message: "Symbol tables must link to an existing string-table section."
				});
				if (section.index !== index) context.addIssue({
					code: "custom",
					path: [
						"sections",
						index,
						"index"
					],
					message: "Complete section order must preserve original producer indices."
				});
				checkLocation(section.header_location, [
					"sections",
					index,
					"header_location"
				]);
				checkName(section.name, [
					"sections",
					index,
					"name"
				]);
				if (section.file_backing === "file") check(section.offset, section.size, ["sections", index]);
			}
			for (const [index, segment] of value.segments.entries()) {
				if (segment.index !== index) context.addIssue({
					code: "custom",
					path: [
						"segments",
						index,
						"index"
					],
					message: "Complete segment order must preserve original producer indices."
				});
				checkLocation(segment.header_location, [
					"segments",
					index,
					"header_location"
				]);
				const hasFileBytes = segment.type !== "PT_NULL" && BigInt(segment.file_size) !== 0n;
				if (segment.file_backing !== (hasFileBytes ? "file" : "none")) context.addIssue({
					code: "custom",
					path: [
						"segments",
						index,
						"file_backing"
					],
					message: "File backing must follow the reported segment type and file size."
				});
				if (segment.type === "PT_NULL" !== (segment.permissions === null)) context.addIssue({
					code: "custom",
					path: [
						"segments",
						index,
						"permissions"
					],
					message: "Unused PT_NULL flags have no permission meaning; other segment flags retain their interpretation."
				});
				if (hasFileBytes) check(segment.offset, segment.file_size, ["segments", index]);
			}
			for (const [index, symbol] of value.symbols.entries()) {
				checkLocation(symbol.location, [
					"symbols",
					index,
					"location"
				]);
				checkName(symbol.name, [
					"symbols",
					index,
					"name"
				]);
			}
			for (const [index, relocation] of value.relocations.entries()) checkLocation(relocation.location, [
				"relocations",
				index,
				"location"
			]);
			validateRelocationReferences(value, context);
			validatePackedRelativeTables(value, context, checkLocation);
			for (const facet of ["needed_libraries", "interpreters"]) for (const [index, reported] of value.linkage[facet].entries()) checkName(reported, [
				"linkage",
				facet,
				index
			]);
		});
		validatedImmutableLayouts = new WeakSet();
		safeParseOwnedBinaryLayout = (input) => {
			if (typeof input === "object" && input !== null && validatedImmutableLayouts.has(input)) return {
				success: true,
				data: input
			};
			const parsed = binaryLayoutSchema.safeParse(input);
			if (parsed.success && canBorrowParsedJsonSnapshot(input, parsed.data)) {
				validatedImmutableLayouts.add(input);
				return {
					success: true,
					data: input
				};
			}
			return parsed;
		};
		validateRelocationReferences = (value, context) => {
			const symbols = new Set(value.symbols.map((symbol) => `${symbol.table_index}:${symbol.entry_index}`));
			for (const [index, relocation] of value.relocations.entries()) {
				const owner = value.sections[relocation.section_index];
				const target = relocation.target;
				const targetMatches = value.image_type === "ET_REL" ? target.kind === "section-offset" ? target.section_index !== 0 && target.section_index === owner?.info && value.sections[target.section_index] !== undefined && value.sections[target.section_index]?.type !== "SHT_NULL" && target.offset === relocation.reported_offset : target.kind === "unknown-section" && target.reported_section_index === owner?.info && target.offset === relocation.reported_offset && (target.reported_section_index === 0 ? target.unknown_reason === "undefined-section-reference" : value.sections[target.reported_section_index]?.type === "SHT_NULL" && target.unknown_reason === "inactive-section-header") : target.kind === "linked-virtual-address" && target.address === relocation.reported_offset;
				if (!targetMatches) context.addIssue({
					code: "custom",
					path: [
						"relocations",
						index,
						"target"
					],
					message: "Relocation target must preserve its reported offset and owner reference; SHN_UNDEF and inactive headers remain unknown rather than resolved sections."
				});
				const table = value.sections[relocation.symbol_table_index];
				const tableExists = relocation.symbol_table_index !== 0 && (table?.type === "SHT_SYMTAB" || table?.type === "SHT_DYNSYM");
				const positiveReferenceExists = tableExists && BigInt(table.entry_size) >= 24n && BigInt(relocation.symbol_index) < BigInt(table.size) / BigInt(table.entry_size) && symbols.has(`${relocation.symbol_table_index}:${relocation.symbol_index}`);
				if (owner?.type !== "SHT_REL" && owner?.type !== "SHT_RELA" || owner.link !== relocation.symbol_table_index || relocation.symbol_table_index !== 0 && !tableExists || relocation.symbol_index !== 0 && !positiveReferenceExists || relocation.symbol_reference_meaning !== (relocation.symbol_index === 0 ? "zero-symbol-value" : "symbol-table-entry")) context.addIssue({
					code: "custom",
					path: ["relocations", index],
					message: "Relocation must preserve its REL/RELA owner and resolve positive symbol indices through the linked symbol table; index zero uses a zero symbol value."
				});
			}
		};
		validatePackedRelativeTables = (value, context, checkLocation) => {
			for (const [tableIndex, table] of value.packed_relative_relocations.entries()) {
				checkLocation(table.location, [
					"packed_relative_relocations",
					tableIndex,
					"location"
				]);
				const encodedBytes = table.encoded_bytes_base64.length * 3 / 4 - (table.encoded_bytes_base64.endsWith("==") ? 2 : table.encoded_bytes_base64.endsWith("=") ? 1 : 0);
				if (!Number.isInteger(encodedBytes) || BigInt(encodedBytes) !== BigInt(table.location.bytes)) context.addIssue({
					code: "custom",
					path: ["packed_relative_relocations", tableIndex],
					message: "Complete packed table bytes must match its original file range."
				});
				const section = value.sections[table.section_index];
				if (section?.type !== "SHT_RELR" || section.offset !== table.location.offset || section.size !== table.location.bytes) context.addIssue({
					code: "custom",
					path: [
						"packed_relative_relocations",
						tableIndex,
						"section_index"
					],
					message: "Packed relative evidence must retain its original RELR section identity and range."
				});
				for (const [decoded, entry] of table.entries.entries()) if (entry.decoded_index !== decoded) context.addIssue({
					code: "custom",
					path: [
						"packed_relative_relocations",
						tableIndex,
						"entries",
						decoded
					],
					message: "Decoded offsets must preserve upstream iterator order."
				});
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/binaryLayoutView.js
var OPERATION$1, inputError$2, layoutUnknowns, displayName, namedMatches, selectNamed, selectIndexed, pageRows, layoutIncompatible, parentFields$2, layoutSummary, projectBinaryLayoutView, selectLayoutItem;
function init_binaryLayoutView() {
	return (init_binaryLayoutView = __esmMin((() => {
		init_analysisErrorCore();
		init_result();
		init_analysisViewCoverage();
		OPERATION$1 = "inspect_analysis_view";
		inputError$2 = (issues) => new AnalysisInputError(OPERATION$1, undefined, issues);
		layoutUnknowns = (layout) => {
			const unknowns = [
				"runtime_load_base is unknown",
				"entry_point.execution_status is unknown",
				"relocation_inventory_completeness is unknown",
				"linkage.convenience_maps_completeness is unknown",
				"linkage.runtime_library_paths are unknown"
			];
			if (layout.mitigations.nx_indicator === null) unknowns.push("mitigations.nx_indicator is unknown");
			if (layout.mitigations.relro === null) unknowns.push("mitigations.relro is unknown");
			return unknowns;
		};
		displayName = (name) => name.display;
		namedMatches = (rows, name) => rows.flatMap((row, index) => row.name.unknown_reason === null && displayName(row.name) === name ? [{
			index,
			row
		}] : []);
		selectNamed = (collection, rows, name) => {
			const matches = namedMatches(rows, name);
			if (matches.length === 1) {
				const selected = matches[0];
				if (selected !== undefined) return ok(selected.row);
			}
			if (matches.length === 0) return err(inputError$2([{
				path: [
					"view",
					"selector",
					"name"
				],
				reason: "invalid_value",
				message: `No ${collection} named ${JSON.stringify(name)}. Collection has ${String(rows.length)} entries; page it to inspect exact indexes and names.`
			}]));
			return err(inputError$2([{
				path: [
					"view",
					"selector",
					"name"
				],
				reason: "invalid_value",
				message: `Multiple ${collection} named ${JSON.stringify(name)}; select one by index.`,
				expected: matches.map(({ index }) => ({ index }))
			}]));
		};
		selectIndexed = (collection, rows, index) => {
			const row = rows[index];
			if (row !== undefined) return ok(row);
			return err(inputError$2([{
				path: [
					"view",
					"selector",
					"index"
				],
				reason: "out_of_range",
				message: `${collection} index ${String(index)} is outside 0..${String(Math.max(0, rows.length - 1))} (${String(rows.length)} entries).`,
				minimum: 0,
				maximum: Math.max(0, rows.length - 1)
			}]));
		};
		pageRows = (rows, offset, limit) => rows.slice(offset, offset + limit);
		layoutIncompatible = (detail) => inputError$2([{
			path: ["view"],
			reason: "invalid_value",
			message: detail
		}]);
		parentFields$2 = (parent, layout) => ({
			parent_evidence_id: parent.evidenceId,
			parent_operation: "inspect_binary_layout",
			parent_digest: parent.evidenceId.slice(3),
			artifact: {
				path: layout.artifact.path,
				sha256: layout.artifact.sha256
			},
			limitations: boundedViewMessages([...parent.limitations, ...layout.limitations], parent.evidenceId, "limitations"),
			unknowns: boundedViewMessages(layoutUnknowns(layout), parent.evidenceId, "unknowns")
		});
		layoutSummary = (layout) => ({
			bytes: layout.artifact.bytes,
			format: layout.format,
			architecture: layout.architecture,
			image_type: layout.image_type,
			entry: layout.entry_point,
			counts: {
				sections: layout.sections.length,
				segments: layout.segments.length,
				symbols: layout.symbols.length,
				relocations: layout.relocations.length
			},
			limitation_count: layout.limitations.length
		});
		projectBinaryLayoutView = (parent, layout, view) => {
			const shared = parentFields$2(parent, layout);
			if (view.kind === "native") return err(layoutIncompatible("Native views require analyze_function Evidence."));
			if (view.kind === "inventory") return err(layoutIncompatible("Inventory views require artifact Evidence."));
			if (view.kind === "wasm") return err(layoutIncompatible("WASM views require inspect_wasm_artifact Evidence."));
			if (view.kind === "evm") return err(layoutIncompatible("EVM views require inspect_evm_interface Evidence."));
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				summary: layoutSummary(layout),
				coverage: completeWithinViewCoverage(layout.sections.length + layout.segments.length + layout.symbols.length + layout.relocations.length, layout.sections.length + layout.segments.length + layout.symbols.length + layout.relocations.length),
				...shared
			});
			if (view.kind === "facet") return ok({
				kind: "facet",
				view,
				facet: view.facet === "mitigations" ? layout.mitigations : layout.linkage,
				coverage: completeWithinViewCoverage(1, 1),
				...shared
			});
			if (view.kind === "item") {
				if (view.collection === "modules") return err(layoutIncompatible("modules collection applies to analyze_javascript_application Evidence."));
				const selected = view.collection === "sections" ? selectLayoutItem(view.collection, layout.sections, view.selector) : selectLayoutItem(view.collection, layout.symbols, view.selector);
				if (!selected.ok) return selected;
				return ok({
					kind: "item",
					view,
					item: selected.value,
					coverage: completeWithinViewCoverage(1, view.collection === "sections" ? layout.sections.length : layout.symbols.length),
					...shared
				});
			}
			if (view.kind !== "page") return err(layoutIncompatible("Layout views require summary, facet, item or page selections."));
			if (view.collection === "modules") return err(layoutIncompatible("modules collection applies to analyze_javascript_application Evidence."));
			const rows = view.collection === "sections" ? layout.sections : layout.symbols;
			const items = view.collection === "sections" ? pageRows(layout.sections, view.offset, view.limit) : pageRows(layout.symbols, view.offset, view.limit);
			return ok({
				kind: "page",
				view,
				items: [...items],
				coverage: pageViewCoverage(view.offset, items.length, rows.length),
				...shared
			});
		};
		selectLayoutItem = (collection, rows, selector) => {
			if ("index" in selector) return selectIndexed(collection, rows, selector.index);
			if ("name" in selector) return selectNamed(collection, rows, selector.name);
			return err(layoutIncompatible("Section and symbol items are selected by index or exact name."));
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/javascriptApplicationView.js
/** One owner for the module kinds and path semantics of every module view. */
function* moduleEntries(nodes) {
	for (const node of nodes) {
		if (isModuleNode(node)) yield {
			node,
			path: javascriptModulePath(node)
		};
	}
}
var OPERATION, inputError$1, jsIncompatible, javascriptModulePath, isModuleNode, modulePage, exportNames, nodeHashes, sourceRanges, moduleItem, moduleReference, javascriptCoverageUnknowns, parentFields$1, selectModule, projectJavaScriptApplicationView;
function init_javascriptApplicationView() {
	return (init_javascriptApplicationView = __esmMin((() => {
		init_analysisErrorCore();
		init_jsonValue();
		init_result();
		init_javascriptApplicationCoverage();
		init_javascriptFactsView();
		init_analysisViewCoverage();
		OPERATION = "inspect_analysis_view";
		inputError$1 = (issues) => new AnalysisInputError(OPERATION, undefined, issues);
		jsIncompatible = (detail) => inputError$1([{
			path: ["view"],
			reason: "invalid_value",
			message: detail
		}]);
		javascriptModulePath = (node) => {
			if (node.identity.strategy === "canonical-path") return node.identity.path;
			if (node.identity.strategy === "source-map-original") return node.identity.original_source;
			for (const observation of node.observations) {
				const path = observation.properties.path;
				if (typeof path === "string") return path;
				const location = observation.evidence.location;
				if (location.available && location.value.kind === "artifact-path") return location.value.path;
				if (location.available && location.value.kind === "source-range") return location.value.source;
			}
			return null;
		};
		isModuleNode = (node) => node.kind === "javascript-asset" || node.kind === "javascript-module" || node.kind === "source-module";
		modulePage = (nodes, view) => {
			const entries = [];
			let total = 0;
			for (const entry of moduleEntries(nodes)) {
				if (view.where?.kind !== undefined && entry.node.kind !== view.where.kind) continue;
				if (view.where?.path !== undefined && entry.path !== view.where.path) continue;
				if (total >= view.offset && entries.length < view.limit) entries.push(entry);
				total += 1;
			}
			return {
				entries,
				total
			};
		};
		exportNames = (node) => {
			const names = new Set();
			for (const observation of node.observations) {
				const value = observation.properties.export_names ?? observation.properties.exports;
				if (!Array.isArray(value)) continue;
				for (const entry of value) if (typeof entry === "string") names.add(entry);
			}
			return [...names];
		};
		nodeHashes = (node) => {
			const hashes = new Set();
			const { identity } = node;
			if (identity.strategy === "content-digest") hashes.add(identity.sha256);
			if (identity.strategy === "canonical-path") hashes.add(identity.artifact_sha256);
			if (identity.strategy === "source-map-original") {
				hashes.add(identity.source_map_sha256);
				if (identity.source_sha256 !== null) hashes.add(identity.source_sha256);
			}
			for (const observation of node.observations) {
				for (const key of [
					"sha256",
					"container_sha256",
					"entry_sha256",
					"source_sha256"
				]) {
					const value = observation.properties[key];
					if (typeof value === "string" && /^[a-f0-9]{64}$/u.test(value)) hashes.add(value);
				}
			}
			return [...hashes];
		};
		sourceRanges = (node) => node.observations.flatMap((observation) => {
			const location = observation.evidence.location;
			return location.available && location.value.kind === "source-range" ? [location.value] : [];
		});
		moduleItem = (node) => ({
			node_id: node.node_id,
			kind: node.kind,
			path: javascriptModulePath(node),
			identity: node.identity,
			hashes: [...nodeHashes(node)],
			exports: [...exportNames(node)],
			source_ranges: [...sourceRanges(node)],
			observations: node.observations.map((observation) => ({
				observation_id: observation.observation_id,
				label: observation.label,
				properties: observation.properties,
				evidence: {
					...observation.evidence,
					location: observation.evidence.location
				}
			}))
		});
		moduleReference = ({ node, path }) => {
			let ranges = 0;
			const support = new Map();
			for (const { evidence } of node.observations) {
				if (evidence.location.available && evidence.location.value.kind === "source-range") ranges += 1;
				const { authority, state, confidence } = evidence;
				support.set(`${authority}:${state}:${confidence}`, {
					authority,
					state,
					confidence
				});
			}
			return {
				node_id: node.node_id,
				kind: node.kind,
				path,
				identity: node.identity,
				retained_source_range_count: ranges,
				basis: [...support.values()]
			};
		};
		javascriptCoverageUnknowns = (coverage) => {
			const unknowns = [];
			if (coverage.application.status !== "complete") unknowns.push(`graph.coverage.status is ${coverage.application.status}`);
			if (coverage.semantic.status !== "complete") unknowns.push(`semantic_graph.coverage.status is ${coverage.semantic.status}`);
			const applicationUnknowns = coverage.application_unknown_count;
			if (applicationUnknowns > 0) unknowns.push(`${String(applicationUnknowns)} application graph unknowns remain in the parent Evidence.`);
			if (coverage.semantic_unknown_count > 0) unknowns.push(`${String(coverage.semantic_unknown_count)} semantic graph unknowns remain in the parent Evidence.`);
			return unknowns;
		};
		parentFields$1 = (parent, analysis, sourceCoverage) => {
			const limitations = [
				...analysis.limitations,
				...analysis.graph.limitations,
				...analysis.semantic_graph.limitations
			];
			return {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "analyze_javascript_application",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: analysis.input_path,
					sha256: analysis.root_artifact_sha256
				},
				limitations: boundedViewMessages([...parent.limitations, ...limitations], parent.evidenceId, "limitations"),
				unknowns: boundedViewMessages(limitations, parent.evidenceId, "unknowns", javascriptCoverageUnknowns(sourceCoverage))
			};
		};
		selectModule = (modules, selector) => {
			if ("node_id" in selector) {
				const matches = modules.filter(({ node }) => node.node_id === selector.node_id);
				if (matches.length === 1) {
					const selected = matches[0];
					if (selected !== undefined) return ok(selected.node);
				}
				return err(inputError$1([{
					path: [
						"view",
						"selector",
						"node_id"
					],
					reason: "invalid_value",
					message: `No module has node_id ${JSON.stringify(selector.node_id)}. Page the modules collection to inspect available identities.`
				}]));
			}
			if ("path" in selector) {
				const matches = modules.filter((entry) => entry.path === selector.path);
				if (matches.length === 1) {
					const selected = matches[0];
					if (selected !== undefined) return ok(selected.node);
				}
				if (matches.length === 0) return err(inputError$1([{
					path: [
						"view",
						"selector",
						"path"
					],
					reason: "invalid_value",
					message: `No module has path ${JSON.stringify(selector.path)}. Page the modules collection to inspect exact paths and node_id values.`
				}]));
				return err(inputError$1([{
					path: [
						"view",
						"selector",
						"path"
					],
					reason: "invalid_value",
					message: `Multiple modules have path ${JSON.stringify(selector.path)}; select one by node_id.`,
					expected: matches.map((entry) => ({ node_id: entry.node.node_id }))
				}]));
			}
			return err(jsIncompatible("Module items are selected by exact path or node_id."));
		};
		projectJavaScriptApplicationView = (parent, analysis, view) => {
			if (view.kind !== "summary" && view.kind !== "item" && view.kind !== "page" && view.kind !== "javascript" && view.kind !== "javascript-facts") return err(jsIncompatible("JavaScript application Evidence supports summary, module item/page, typed module references or selected JavaScript facts."));
			const sourceCoverage = javascriptApplicationSourceCoverage(analysis);
			const shared = parentFields$1(parent, analysis, sourceCoverage);
			if (view.kind === "javascript-facts") {
				const { rows, total } = projectJavaScriptFacts(analysis.graph.nodes, view);
				return ok({
					...shared,
					kind: "javascript-facts",
					view,
					rows,
					source_coverage: sourceCoverage,
					coverage: pageViewCoverage(view.offset, rows.length, total)
				});
			}
			if (view.kind === "javascript") {
				const { entries, total } = modulePage(analysis.graph.nodes, view);
				const rows = entries.map(moduleReference);
				return ok({
					...shared,
					kind: "javascript",
					view,
					rows,
					source_coverage: sourceCoverage,
					coverage: pageViewCoverage(view.offset, rows.length, total)
				});
			}
			if (view.kind === "summary") {
				const moduleCount = analysis.graph.nodes.reduce((count, node) => count + Number(isModuleNode(node)), 0);
				return ok({
					kind: "summary",
					view,
					summary: {
						input_path: analysis.input_path,
						format: analysis.format,
						root_artifact_sha256: analysis.root_artifact_sha256,
						...analysis.source_selection === undefined ? {} : { source_selection: analysis.source_selection },
						statistics: jsonObjectSchema.parse(analysis.statistics),
						electron: jsonObjectSchema.parse(analysis.summary),
						coverage: jsonObjectSchema.parse({
							application: analysis.graph.coverage,
							semantic: {
								...analysis.semantic_graph.coverage,
								families: analysis.semantic_graph.coverage.families.map(({ unknown_ids, ...family }) => ({
									...family,
									unknown_count: unknown_ids.length
								}))
							},
							application_unknowns: sourceCoverage.application_unknown_count,
							semantic_unknowns: sourceCoverage.semantic_unknown_count
						}),
						limitation_count: analysis.limitations.length
					},
					coverage: completeWithinViewCoverage(moduleCount, moduleCount),
					...shared
				});
			}
			if (view.kind === "item") {
				if (view.collection !== "modules") return err(jsIncompatible("Section and symbol collections apply to inspect_binary_layout Evidence."));
				const modules = [...moduleEntries(analysis.graph.nodes)];
				const selected = selectModule(modules, view.selector);
				if (!selected.ok) return selected;
				return ok({
					kind: "item",
					view,
					item: moduleItem(selected.value),
					coverage: completeWithinViewCoverage(1, modules.length),
					...shared
				});
			}
			if (view.kind !== "page" || view.collection !== "modules") return err(jsIncompatible("Section and symbol collections apply to inspect_binary_layout Evidence."));
			const { entries, total } = modulePage(analysis.graph.nodes, view);
			const items = entries.map(({ node, path }) => ({
				node_id: node.node_id,
				kind: node.kind,
				path
			}));
			return ok({
				kind: "page",
				view,
				items,
				coverage: pageViewCoverage(view.offset, items.length, total),
				...shared
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisViewDataAdmission.js
var MEMBER_BYTES, CONTAINER_BYTES, textBytes$1, admitAnalysisViewData;
function init_analysisViewDataAdmission() {
	return (init_analysisViewDataAdmission = __esmMin((() => {
		init_analysisErrorCore();
		init_jsonValue();
		init_result();
		MEMBER_BYTES = 256;
		CONTAINER_BYTES = 512;
		textBytes$1 = (length) => 32 + length * 14;
		admitAnalysisViewData = (value, inline, reserve) => {
			const ancestors = new Set();
			const path = inline ? ["source", "evidence"] : ["source"];
			const invalid = () => err(new AnalysisInputError("inspect_analysis_view", undefined, [{
				path: [...path],
				reason: "invalid_value",
				message: "Parent data must contain bounded ordinary JSON data without cycles or accessors."
			}]));
			const visit = (item, depth) => {
				if (isProxy(item) || typeof item === "function") return invalid();
				if (depth > 1e3 + (inline ? 4 : 3) || typeof item === "object" && item !== null && ancestors.has(item)) return invalid();
				const member = reserve?.(MEMBER_BYTES + (inline && typeof item === "string" ? textBytes$1(item.length) : 0) + (typeof item === "object" && item !== null ? CONTAINER_BYTES : 0));
				if (member !== undefined && !member.ok) return member;
				if (typeof item !== "object" || item === null) return ok(undefined);
				ancestors.add(item);
				const child = (key) => {
					path.push(key);
					const descriptor = Object.getOwnPropertyDescriptor(item, key);
					const admitted = descriptor === undefined || !Object.hasOwn(descriptor, "value") ? invalid() : visit(descriptor.value, depth + 1);
					path.pop();
					return admitted;
				};
				if (Array.isArray(item)) {
					if (Object.getPrototypeOf(item) !== Array.prototype || Object.hasOwn(item, Symbol.iterator) || Object.hasOwn(item, "map") || Object.hasOwn(item, "constructor")) return invalid();
					for (let index = 0; index < item.length; index += 1) {
						const admitted = child(index);
						if (!admitted.ok) return admitted;
					}
				} else {
					const prototype = Object.getPrototypeOf(item);
					if (prototype !== Object.prototype && prototype !== null) return invalid();
					for (const key of Object.getOwnPropertyNames(item)) {
						const keyAdmission = inline ? reserve?.(textBytes$1(key.length)) : undefined;
						if (keyAdmission !== undefined && !keyAdmission.ok) return keyAdmission;
						const admitted = child(key);
						if (!admitted.ok) return admitted;
					}
				}
				ancestors.delete(item);
				return ok(undefined);
			};
			return visit(value, 0);
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/webNetworkRouteTemplates.js
var ROUTE_RULES, requestSchema, responseSchema, contentSchema$1, MEDIA_TYPE_ESSENCE, GROUP_BYTES, SEGMENT_BYTES, ENTRY_BYTES, RECORD_SCRATCH_BYTES, CAPTURE_CONTAINER_BYTES, SEGMENT_SCRATCH_BYTES, textBytes, mediaTypeEssence, routePartCount, segmentRule, scanRouteTemplate, readRecordedRequestLine, readQueryParameterNames;
function init_webNetworkRouteTemplates() {
	return (init_webNetworkRouteTemplates = __esmMin((() => {
		init_recordedTransportUrl();
		ROUTE_RULES = [
			"numeric",
			"uuid",
			"hex",
			"iso-date"
		];
		requestSchema = z.object({ request: z.object({
			url: z.unknown(),
			method: z.unknown()
		}) });
		responseSchema = z.object({ response: z.object({
			status: z.unknown().optional(),
			content: z.unknown().optional()
		}) });
		contentSchema$1 = z.object({ mimeType: z.unknown().optional() });
		MEDIA_TYPE_ESSENCE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+\/[A-Za-z0-9!#$%&'*+.^_`|~-]+$/u;
		GROUP_BYTES = 2048;
		SEGMENT_BYTES = 1024;
		ENTRY_BYTES = 128;
		RECORD_SCRATCH_BYTES = 512;
		CAPTURE_CONTAINER_BYTES = 512;
		SEGMENT_SCRATCH_BYTES = 512;
		textBytes = (length) => 32 + length * 14;
		mediaTypeEssence = (reported) => {
			const separator = reported.indexOf(";");
			let start = 0;
			let end = separator < 0 ? reported.length : separator;
			while (start < end && (reported[start] === " " || reported[start] === "	")) start += 1;
			while (end > start && (reported[end - 1] === " " || reported[end - 1] === "	")) end -= 1;
			const essence = reported.slice(start, end);
			return MEDIA_TYPE_ESSENCE.test(essence) ? essence.toLowerCase() : null;
		};
		routePartCount = (template) => {
			let count = 1;
			for (const character of template) if (character === "/") count += 1;
			return count;
		};
		segmentRule = (value) => {
			if (/^[0-9]+$/u.test(value)) return "numeric";
			if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) return "uuid";
			if (/^[0-9a-f]{32,}$/iu.test(value)) return "hex";
			if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(value)) {
				const date = new Date(`${value}T00:00:00.000Z`);
				if (Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value) return "iso-date";
			}
			return null;
		};
		scanRouteTemplate = (path, temporary) => {
			const segments = [];
			const parts = [];
			const rules = [];
			let templateLength = path.length;
			let rulesLength = 0;
			let copied = 0;
			let index = 0;
			let start = 1;
			for (;;) {
				const slash = path.indexOf("/", start);
				const end = slash < 0 ? path.length : slash;
				const value = path.slice(start, end);
				const rule = segmentRule(value);
				if (rule !== null) {
					if (!temporary(SEGMENT_SCRATCH_BYTES)) return null;
					const placeholder = `{${rule}}`;
					const identity = `${index}:${rule};`;
					segments.push({
						segment_index: index,
						rule,
						value
					});
					parts.push(path.slice(copied, start), placeholder);
					rules.push(identity);
					templateLength += placeholder.length - value.length;
					rulesLength += identity.length;
					copied = end;
				}
				if (slash < 0) break;
				start = slash + 1;
				index += 1;
			}
			if (segments.length === 0) return {
				template: path,
				rules: "",
				segments
			};
			if (!temporary(textBytes(templateLength) + textBytes(rulesLength))) return null;
			parts.push(path.slice(copied));
			return {
				template: parts.join(""),
				rules: rules.join(""),
				segments
			};
		};
		readRecordedRequestLine = (reported, includeQuery, temporary) => {
			const excluded = (reason) => ({
				kind: "excluded",
				reason
			});
			const request = requestSchema.safeParse(reported);
			if (!request.success) return excluded("request-unavailable");
			const { url, method } = request.data.request;
			if (url === null) return excluded("url-redacted");
			if (typeof url !== "string") return excluded("url-unparseable");
			if (!temporary(512 + textBytes(url.length))) return null;
			const parsed = parseRecordedTransportUrl(url, { includeQuery });
			if (parsed.origin === null) return excluded("url-unparseable");
			if (typeof method !== "string" || method.length === 0) return excluded("method-unavailable");
			if (parsed.path === null) return excluded("url-unparseable");
			const response = responseSchema.safeParse(reported);
			const status = response.success ? response.data.response.status : undefined;
			const content = contentSchema$1.safeParse(response.success ? response.data.response.content : undefined);
			const mime = content.success ? content.data.mimeType : undefined;
			const rawMime = typeof mime === "string" ? mime : "";
			if (!temporary(textBytes(rawMime.length))) return null;
			return {
				kind: "line",
				method,
				origin: parsed.origin,
				path: parsed.path,
				query: parsed.query,
				status: typeof status === "number" && status !== 0 ? status : null,
				rawMime
			};
		};
		readQueryParameterNames = (query, temporary) => {
			if (query === undefined) return undefined;
			let pairs = query.length > 1 ? 1 : 0;
			for (const character of query) if (character === "&") pairs += 1;
			if (!temporary(512 + textBytes(query.length) + pairs * 128 * 4)) return null;
			return new Set(parseUrlQueryParameterNames(query));
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/WebNetworkProjectionAccumulator.js
var WebNetworkProjectionAccumulator, admitHarCaptureParent;
function init_WebNetworkProjectionAccumulator() {
	return (init_WebNetworkProjectionAccumulator = __esmMin((() => {
		init_fixedAllowanceRemediation();
		init_analysisErrorCore();
		init_unicodeCodePointOrder();
		init_result();
		init_webNetworkCapture();
		init_analysisViewDataAdmission();
		init_analysisViewErrors();
		init_webNetworkRouteTemplates();
		WebNetworkProjectionAccumulator = class {
			maximumBytes;
			budgetSubject;
			#limitations = new Set();
			#retainedBytes = 0;
			#temporaryBytes = 0;
			/** Per-record scratch reservation handed to the shared record readers. */
			scratch = (bytes) => this.temporary(bytes);
			constructor(maximumBytes, budgetSubject) {
				this.maximumBytes = maximumBytes;
				this.budgetSubject = budgetSubject;
			}
			retain(bytes) {
				if (this.#retainedBytes + this.#temporaryBytes + bytes > this.maximumBytes) return false;
				this.#retainedBytes += bytes;
				return true;
			}
			temporary(bytes) {
				if (this.#retainedBytes + this.#temporaryBytes + bytes > this.maximumBytes) return false;
				this.#temporaryBytes += bytes;
				return true;
			}
			/** Per-record strings and descriptors never become cumulative scratch. */
			releaseTemporary() {
				this.#temporaryBytes = 0;
			}
			overBudget() {
				return err(new AnalysisResourceConstraintError("inspect_analysis_view", "memory", `${this.budgetSubject} retained state and temporary work exceed the projection representation budget.`, { output_bytes: this.maximumBytes }, fixedAllowanceOptions("The analysis-view projection allowance", "parser")));
			}
			/** Reserve schema output and validation scratch while the borrowed parent stays live. */
			admitCaptureClone(value) {
				return admitAnalysisViewData(value, false, (bytes) => this.retain(bytes) ? ok(undefined) : this.overBudget());
			}
			/** Reserve bytes a view derives from the borrowed parent before it allocates them. */
			admitDerivedBytes(bytes) {
				return this.retain(bytes) ? ok(undefined) : this.overBudget();
			}
			/** Admit the complete portable envelope before cloning or authenticating it. */
			admitInlineEvidence(value) {
				return admitAnalysisViewData(value, true, (bytes) => this.retain(bytes) ? ok(undefined) : this.overBudget());
			}
			addLimitations(limitations) {
				for (const limitation of limitations) {
					if (this.#limitations.has(limitation)) continue;
					if (!this.retain(128 + textBytes(limitation.length))) return this.overBudget();
					this.#limitations.add(limitation);
				}
				return ok(undefined);
			}
			sortedLimitations() {
				return [...this.#limitations].sort(compareUnicodeCodePoints);
			}
		};
		admitHarCaptureParent = (parent, viewKind, accumulator) => {
			const unsupported = (reason) => err(new AnalysisUnsupportedTargetError("inspect_analysis_view", parent.evidenceId, reason));
			if (parent.operation !== "inspect_web_network_capture") return unsupported(`View ${viewKind} is unsupported for parent operation ${parent.operation}; ${viewKind} requires ${viewKind === "api-surface" ? "inspect_web_network_capture" : "inspect_web_network_capture or capture_browser_scenario"}.`);
			const admitted = accumulator.admitCaptureClone(parent.normalizedResult);
			if (!admitted.ok) return admitted;
			const parsed = safeParseOwnedWebNetworkCapture(parent.normalizedResult);
			if (!parsed.success) return err(analysisViewInputError([{
				path: ["source"],
				reason: "invalid_value",
				message: "Parent Evidence result does not match inspect_web_network_capture."
			}]));
			if (parsed.data.format !== "har") return unsupported(`${viewKind} does not support capture format ${parsed.data.format}.`);
			const { artifact } = parsed.data;
			if (viewKind !== "api-surface" && artifact.sha256 !== null && (parent.subject == null || parent.subject.local_path !== artifact.path || parent.subject.digest.sha256 !== artifact.sha256)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Capture parent subject must identify the report's exact path and SHA-256."
			}]));
			const declarations = z.object({ sensitive_value_count: z.number().int().nonnegative() }).safeParse(parent.parameters);
			if (!declarations.success || declarations.data.sensitive_value_count > 0) return unsupported("sensitive_values_unretained");
			return ok(parsed.data);
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/WebNetworkApiSurfaceAccumulator.js
var WebNetworkApiSurfaceAccumulator;
function init_WebNetworkApiSurfaceAccumulator() {
	return (init_WebNetworkApiSurfaceAccumulator = __esmMin((() => {
		init_unicodeCodePointOrder();
		init_result();
		init_webNetworkCapture();
		init_analysisViewCoverage();
		init_WebNetworkProjectionAccumulator();
		init_webNetworkRouteTemplates();
		WebNetworkApiSurfaceAccumulator = class extends WebNetworkProjectionAccumulator {
			includeQueryParameterNames;
			#buckets = new Map();
			#groups = [];
			#excluded = [];
			#unavailableResponse = false;
			constructor(maximumBytes = WEB_NETWORK_CAPTURE_LIMITS.outputBytes, includeQueryParameterNames = false) {
				super(maximumBytes, "API-surface");
				this.includeQueryParameterNames = includeQueryParameterNames;
			}
			#exclude(ordinal, reason) {
				if (!this.retain(128 + 512)) return this.overBudget();
				this.#excluded.push({
					ordinal,
					reason
				});
				return ok(undefined);
			}
			add(record) {
				const limitations = this.addLimitations(record.limitations);
				if (!limitations.ok) return limitations;
				try {
					const line = readRecordedRequestLine(record.reported, this.includeQueryParameterNames, this.scratch);
					if (line === null) return this.overBudget();
					if (line.kind === "excluded") return this.#exclude(record.ordinal, line.reason);
					const route = scanRouteTemplate(line.path, this.scratch);
					if (route === null) return this.overBudget();
					const queryNames = readQueryParameterNames(line.query, this.scratch);
					if (queryNames === null) return this.overBudget();
					return this.#append(record.ordinal, line.method, line.origin, route, line.status, mediaTypeEssence(line.rawMime), queryNames);
				} finally {
					this.releaseTemporary();
				}
			}
			#append(ordinal, method, origin, route, status, mime, queryNames) {
				let group = this.#buckets.get(method)?.get(origin)?.get(route.template)?.get(route.rules);
				let bytes = 128;
				if (group === undefined) {
					bytes += GROUP_BYTES + textBytes(method.length) + textBytes(origin.length) + textBytes(route.template.length) + textBytes(route.rules.length);
					for (const segment of route.segments) bytes += SEGMENT_BYTES + 128 + textBytes(segment.value.length);
				} else {
					for (const [index, segment] of route.segments.entries()) {
						if (!group.segments[index].values.has(segment.value)) bytes += 128 + textBytes(segment.value.length);
					}
				}
				if (status !== null && !group?.statuses.has(status)) bytes += 128;
				if (mime !== null && !group?.contentTypes.has(mime)) bytes += 128 + textBytes(mime.length);
				if (queryNames !== undefined) {
					if (group === undefined) bytes += 512;
					for (const name of queryNames) {
						bytes += 128;
						if (!group?.queryNames?.has(name)) bytes += 128 + textBytes(name.length);
					}
				}
				if (!this.retain(bytes)) return this.overBudget();
				if (group === undefined) {
					group = {
						method,
						origin,
						path_template: route.template,
						segments: route.segments.map((segment) => ({
							segment_index: segment.segment_index,
							rule: segment.rule,
							values: new Set([segment.value])
						})),
						ordinals: [],
						statuses: new Set(),
						contentTypes: new Set(),
						...queryNames === undefined ? {} : { queryNames: new Map() }
					};
					const byOrigin = this.#buckets.get(method) ?? new Map();
					this.#buckets.set(method, byOrigin);
					const byTemplate = byOrigin.get(origin) ?? new Map();
					byOrigin.set(origin, byTemplate);
					const byRule = byTemplate.get(route.template) ?? new Map();
					byTemplate.set(route.template, byRule);
					byRule.set(route.rules, group);
					this.#groups.push(group);
				} else {
					for (const [index, segment] of route.segments.entries()) group.segments[index].values.add(segment.value);
				}
				group.ordinals.push(ordinal);
				if (status === null || mime === null) this.#unavailableResponse = true;
				if (status !== null) group.statuses.add(status);
				if (mime !== null) group.contentTypes.add(mime);
				if (queryNames !== undefined && group.queryNames !== undefined) {
					for (const name of queryNames) {
						const ordinals = group.queryNames.get(name);
						if (ordinals === undefined) group.queryNames.set(name, [ordinal]);
						else ordinals.push(ordinal);
					}
				}
				return ok(undefined);
			}
			page(offset, limit) {
				this.#groups.sort((a, b) => compareUnicodeCodePoints(a.origin, b.origin) || compareUnicodeCodePoints(a.path_template, b.path_template) || compareUnicodeCodePoints(a.method, b.method));
				const groups = this.#groups.slice(offset, offset + limit).map((group) => ({
					method: group.method,
					origin: group.origin,
					path_template: group.path_template,
					templated_segments: group.segments.map((segment) => ({
						segment_index: segment.segment_index,
						rule: segment.rule,
						basis: "inferred",
						observed_values: [...segment.values].sort(compareUnicodeCodePoints)
					})),
					record_ordinals: [...group.ordinals],
					statuses: [...group.statuses].sort((a, b) => a - b),
					content_types: [...group.contentTypes].sort(compareUnicodeCodePoints),
					...group.queryNames === undefined ? {} : { query_parameter_names: [...group.queryNames].sort(([a], [b]) => compareUnicodeCodePoints(a, b)).map(([name, record_ordinals]) => ({
						name,
						record_ordinals: [...record_ordinals]
					})) },
					flags: [
						...group.ordinals.length === 1 ? ["single-sample"] : [],
						...group.statuses.size > 1 ? ["mixed-statuses"] : [],
						...group.contentTypes.size > 1 ? ["mixed-content-types"] : []
					]
				}));
				return {
					coverage: pageViewCoverage(offset, groups.length, this.#groups.length),
					groups,
					templated_groups: this.#groups.reduce((count, group) => count + (group.segments.length > 0 ? 1 : 0), 0),
					excluded_records: [...this.#excluded],
					limitations: this.sortedLimitations(),
					unknowns: this.#unavailableResponse ? ["Some retained records have unavailable status or content type values."] : []
				};
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/webNetworkApiSurfaceView.js
var apiSurfaceViewSchema, ruleSchema, groupSchema, apiSurfaceFields, projectWebNetworkApiSurfaceView;
function init_webNetworkApiSurfaceView() {
	return (init_webNetworkApiSurfaceView = __esmMin((() => {
		init_analysisErrorCore();
		init_result();
		init_WebNetworkApiSurfaceAccumulator();
		init_WebNetworkProjectionAccumulator();
		init_webNetworkRouteTemplates();
		apiSurfaceViewSchema = z.strictObject({
			kind: z.literal("api-surface"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(50),
			include_query_parameter_names: z.boolean().optional().describe("Include distinct observed query parameter names and their original record ordinals; names do not establish required parameters or a complete API schema.")
		});
		ruleSchema = z.enum(ROUTE_RULES);
		groupSchema = z.strictObject({
			method: z.string(),
			origin: z.string(),
			path_template: z.string(),
			templated_segments: z.array(z.strictObject({
				segment_index: z.number().int().nonnegative(),
				rule: ruleSchema,
				basis: z.literal("inferred"),
				observed_values: z.array(z.string())
			})),
			record_ordinals: z.array(z.number().int().nonnegative()),
			statuses: z.array(z.number()),
			content_types: z.array(z.string()),
			query_parameter_names: z.array(z.strictObject({
				name: z.string(),
				record_ordinals: z.array(z.number().int().nonnegative())
			})).optional(),
			flags: z.array(z.enum([
				"single-sample",
				"mixed-statuses",
				"mixed-content-types"
			]))
		});
		apiSurfaceFields = {
			records: z.strictObject({
				examined: z.number().int().nonnegative(),
				total: z.number().int().nonnegative(),
				excluded: z.number().int().nonnegative()
			}),
			templated_groups: z.number().int().nonnegative().describe("Groups across every page that carry at least one templated segment."),
			groups: z.array(groupSchema),
			excluded_records: z.array(z.strictObject({
				ordinal: z.number().int().nonnegative(),
				reason: z.enum([
					"url-redacted",
					"url-unparseable",
					"request-unavailable",
					"method-unavailable"
				])
			}))
		};
		projectWebNetworkApiSurfaceView = (parent, view, accumulator = new WebNetworkApiSurfaceAccumulator(undefined, view.kind === "api-surface" && view.include_query_parameter_names === true)) => {
			if (view.kind !== "api-surface") return err(new AnalysisUnsupportedTargetError("inspect_analysis_view", parent.evidenceId, `View ${view.kind} is unsupported for parent operation ${parent.operation}; api-surface requires inspect_web_network_capture.`));
			const admitted = admitHarCaptureParent(parent, "api-surface", accumulator);
			if (!admitted.ok) return admitted;
			const capture = admitted.value;
			const limitations = accumulator.addLimitations([
				...parent.limitations,
				...capture.limitations,
				"Grouping does not establish handler identity, URL-space schemas or causality.",
				...view.include_query_parameter_names === true ? ["Observed query parameter names do not establish required parameters, value types or a complete API schema."] : [],
				...capture.records.length < capture.total_records ? ["Parent contains an ordinal subset; the surface covers only retained records."] : []
			]);
			if (!limitations.ok) return limitations;
			for (const record of capture.records) {
				const added = accumulator.add(record);
				if (!added.ok) return added;
			}
			const page = accumulator.page(view.offset, view.limit);
			return ok({
				kind: "api-surface",
				view,
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_web_network_capture",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: capture.artifact.path,
					sha256: capture.artifact.sha256
				},
				records: {
					examined: capture.records.length,
					total: capture.total_records,
					excluded: page.excluded_records.length
				},
				...page
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisViewText.js
var viewError$1, analysisTextPage;
function init_analysisViewText() {
	return (init_analysisViewText = __esmMin((() => {
		init_analysisViewErrors();
		init_result();
		init_analysisViewCoverage();
		viewError$1 = (message) => analysisViewInputError([{
			path: ["view"],
			reason: "invalid_value",
			message
		}]);
		analysisTextPage = (body, offset, limit, label = "Pseudocode") => {
			const start = Math.min(offset, body.length);
			const high = (n) => n >= 55296 && n <= 56319;
			const low = (n) => n >= 56320 && n <= 57343;
			if (start > 0 && start < body.length && high(body.charCodeAt(start - 1)) && low(body.charCodeAt(start))) return err(viewError$1(`${label} offset splits a UTF-16 surrogate pair.`));
			let end = Math.min(start + limit, body.length);
			if (end > start && end < body.length && high(body.charCodeAt(end - 1)) && low(body.charCodeAt(end))) end--;
			if (end === start && start < body.length) return err(viewError$1(`Increase ${label.toLowerCase()} limit to include the next complete Unicode character.`));
			return ok({
				item: {
					text: body.slice(start, end),
					unit: "utf16-code-units"
				},
				coverage: pageViewCoverage(start, end - start, body.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/nativeFunctionView.js
var viewError, parentFields, nativeRows, projectNativeFunctionView;
function init_nativeFunctionView() {
	return (init_nativeFunctionView = __esmMin((() => {
		init_analysisViewErrors();
		init_analysisViewText();
		init_canonicalOrdering();
		init_jsonValue();
		init_result();
		init_analysisViewCoverage();
		viewError = (message) => analysisViewInputError([{
			path: ["view"],
			reason: "invalid_value",
			message
		}]);
		parentFields = (parent, dossier, artifact) => {
			const flow = dossier.native_value_flow;
			const api = dossier.native_api;
			const unknowns = [];
			if (flow === null) unknowns.push("native_value_flow was not recorded");
			else if (!flow.available) unknowns.push("native_value_flow unavailable: " + flow.reason);
			else if (flow.truncated) unknowns.push("native_value_flow is truncated; omitted observations remain unknown");
			if (api === null) unknowns.push("native_api was not recorded");
			else if (!api.available) unknowns.push("native_api unavailable: " + api.reason, ...api.residual_unknowns);
			return {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "analyze_function",
				parent_digest: parent.evidenceId.slice(3),
				procedure_address: dossier.procedure.address,
				artifact,
				limitations: uniqueSorted([
					...parent.limitations,
					...dossier.limitations,
					...flow?.limitations ?? [],
					...api?.available ? api.limitations : []
				]),
				unknowns: uniqueSorted(unknowns)
			};
		};
		nativeRows = (dossier, facet) => {
			const sourceFlow = dossier.native_value_flow;
			const flow = sourceFlow?.available ? sourceFlow : undefined;
			return {
				assembly: dossier.assembly,
				basic_blocks: dossier.basic_blocks,
				comments: dossier.comments,
				callers: dossier.callers,
				callees: dossier.callees,
				incoming_references: dossier.incoming_references,
				outgoing_references: dossier.outgoing_references,
				unresolved_calls: dossier.unresolved_calls,
				referenced_strings: dossier.referenced_strings,
				referenced_names: dossier.referenced_names,
				swift_string_literals: dossier.swift_string_literals,
				swift_string_literal_omissions: dossier.swift_string_literal_omissions,
				value_flow_operations: flow?.operations,
				value_flow_def_use: flow?.def_use,
				value_flow_effects: flow?.effects,
				value_flow_parameters: flow?.parameters,
				value_flow_parameter_uses: flow?.parameter_uses
			}[facet];
		};
		projectNativeFunctionView = (parent, dossier, view) => {
			if (view.kind !== "native") return err(viewError("analyze_function Evidence requires a native view."));
			const artifact = parent.artifact;
			if (!artifact) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Native function Evidence requires an artifact-bound subject."
			}]));
			const common = parentFields(parent, dossier, artifact);
			const availabilityKeys = {
				incoming_references: "references",
				outgoing_references: "references",
				referenced_strings: "strings_names",
				referenced_names: "strings_names",
				basic_blocks: "cfg"
			};
			const availabilityKey = availabilityKeys[view.facet] ?? view.facet;
			const availability = dossier.facet_availability?.[availabilityKey];
			if (availability?.available === false) common.unknowns = uniqueSorted([...common.unknowns, availability.reason]);
			const singleton = (item) => ({
				kind: "native",
				view,
				item: jsonValueSchema.parse(item),
				coverage: completeWithinViewCoverage(1, 1),
				...common
			});
			if (availability?.available === false) return ok(singleton(availability));
			const flow = dossier.native_value_flow;
			if (view.facet === "procedure" || view.facet === "native_api" || view.facet === "value_flow_summary") {
				if (view.offset !== 0) return err(viewError("Singleton native facets require offset 0."));
				if (view.facet === "procedure") return ok(singleton(dossier.procedure));
				if (view.facet === "native_api") return ok(singleton(dossier.native_api ?? {
					available: false,
					reason: "not recorded"
				}));
				const status = flow === null ? {
					available: false,
					reason: "not recorded"
				} : !flow.available ? {
					available: false,
					reason: flow.reason
				} : {
					available: true,
					provenance: flow.provenance,
					truncated: flow.truncated,
					omitted_operations_lower_bound: flow.omitted_operations_lower_bound,
					known_omitted_inputs: flow.known_omitted_inputs,
					known_omitted_edges: flow.known_omitted_edges,
					operations: flow.operations.length,
					def_use: flow.def_use.length,
					effects: flow.effects.length,
					parameters: flow.parameters.length,
					parameter_uses: flow.parameter_uses.length
				};
				return ok(singleton(status));
			}
			if (view.facet === "pseudocode") {
				const page = analysisTextPage(dossier.pseudocode, view.offset, view.limit);
				return page.ok ? ok({
					kind: "native",
					view,
					...page.value,
					...common
				}) : page;
			}
			const rows = nativeRows(dossier, view.facet);
			if (rows === undefined) return ok(singleton({
				available: false,
				reason: view.facet.startsWith("value_flow_") && flow?.available === false ? flow.reason : "not recorded"
			}));
			const items = rows.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "native",
				view,
				item: jsonValueSchema.parse(items),
				coverage: pageViewCoverage(view.offset, items.length, rows.length),
				...common
			});
		};
	})))();
}

//#endregion
//#region dist/domain/evm/solidityMetadata.js
var solidityMetadataScalarSchema, solidityMetadataSchema;
function init_solidityMetadata() {
	return (init_solidityMetadata = __esmMin((() => {
		solidityMetadataScalarSchema = z.discriminatedUnion("kind", [
			z.strictObject({
				kind: z.literal("text"),
				value: z.string().max(65535)
			}),
			z.strictObject({
				kind: z.literal("integer"),
				value: z.string().max(21).regex(/^-?(?:0|[1-9][0-9]*)$/)
			}),
			z.strictObject({
				kind: z.literal("bytes"),
				value: z.string().max(131070).regex(/^(?:[a-f0-9]{2})*$/)
			}),
			z.strictObject({
				kind: z.literal("boolean"),
				value: z.boolean()
			}),
			z.strictObject({ kind: z.literal("null") }),
			z.strictObject({
				kind: z.literal("uninterpreted"),
				container: z.enum(["array", "map"])
			})
		]);
		solidityMetadataSchema = z.strictObject({
			profile: z.literal("terminal-cbor-scalars-v1"),
			status: z.enum([
				"unavailable",
				"decoded",
				"partial",
				"not-decoded"
			]),
			bytecode_offset: z.number().int().nonnegative().nullable(),
			cbor_bytes: z.number().int().positive().max(65535).nullable(),
			entries: z.array(z.strictObject({
				key: solidityMetadataScalarSchema,
				value: solidityMetadataScalarSchema
			})).max(32767),
			compiler_version: z.strictObject({
				representation: z.enum(["release-bytes", "prerelease-text"]),
				value: z.string().min(1).max(65535)
			}).nullable(),
			diagnostic: z.string().max(512).nullable()
		}).superRefine((value, context) => {
			const unavailable = value.status === "unavailable";
			if (unavailable ? value.bytecode_offset !== null || value.cbor_bytes !== null : value.bytecode_offset === null || value.cbor_bytes === null) context.addIssue({
				code: "custom",
				message: "Only unavailable metadata omits the candidate range."
			});
			const unexamined = unavailable || value.status === "not-decoded";
			if (unexamined && (value.entries.length !== 0 || value.compiler_version !== null)) context.addIssue({
				code: "custom",
				message: "Unavailable interpretation cannot report decoded entries or compiler identity."
			});
			const uninterpreted = value.entries.some(({ key, value: entryValue }) => key.kind === "uninterpreted" || entryValue.kind === "uninterpreted");
			if (value.status === "decoded" && uninterpreted || value.status === "partial" && !uninterpreted) context.addIssue({
				code: "custom",
				message: "Scalar coverage must preserve uninterpreted containers."
			});
		});
	})))();
}

//#endregion
//#region dist/domain/evm/evmInterface.js
var byteOffset, sha256, inspectEvmInterfaceInputSchema, evmInterfaceSchema;
function init_evmInterface() {
	return (init_evmInterface = __esmMin((() => {
		init_localPath();
		init_solidityMetadata();
		byteOffset = z.number().int().nonnegative();
		sha256 = z.string().regex(/^[a-f0-9]{64}$/);
		inspectEvmInterfaceInputSchema = z.strictObject({
			path: localPathStringSchema.describe("Absolute path to caller-selected local bytecode carrier"),
			encoding: z.enum(["raw", "hex"]).describe("Raw bytes or UTF-8 hex with optional 0x prefix and outer ASCII whitespace")
		});
		evmInterfaceSchema = z.strictObject({
			artifact: z.strictObject({
				path: z.string().min(1),
				sha256,
				bytes: byteOffset,
				encoding: z.enum(["raw", "hex"])
			}),
			bytecode: z.strictObject({
				sha256,
				bytes: byteOffset,
				hex: z.string().regex(/^(?:[0-9a-f]{2})*$/),
				digest_algorithm: z.literal("sha256"),
				kind: z.literal("unknown"),
				deployment_authenticity: z.literal("unknown"),
				hardfork: z.literal("unknown"),
				metadata: solidityMetadataSchema.nullable().default(null)
			}),
			evidence_kind: z.literal("inferred"),
			functions: z.array(z.strictObject({
				selector: z.string().regex(/^0x[0-9a-f]{8}$/),
				bytecode_offset: byteOffset,
				dispatch: z.enum(["abi", "fallback"]),
				inferred_arguments: z.string().nullable(),
				inferred_state_mutability: z.string().nullable()
			})),
			discovery_completeness: z.literal("unknown"),
			runtime_execution: z.literal("not-performed"),
			diagnostics: z.strictObject({
				stdout: z.string(),
				stderr: z.string(),
				truncated: z.boolean()
			}),
			limitations: z.array(z.string())
		}).superRefine((value, context) => {
			if (value.bytecode.hex.length !== value.bytecode.bytes * 2) context.addIssue({
				code: "custom",
				path: ["bytecode"],
				message: "Selected byte count does not match the bytecode hex representation."
			});
			const metadata = value.bytecode.metadata;
			if (metadata !== null && metadata.status !== "unavailable" && (metadata.bytecode_offset === null || metadata.cbor_bytes === null || metadata.bytecode_offset + metadata.cbor_bytes + 2 !== value.bytecode.bytes || metadata.cbor_bytes !== Number.parseInt(value.bytecode.hex.slice(-4), 16))) context.addIssue({
				code: "custom",
				path: ["bytecode", "metadata"],
				message: "Metadata range must match the terminal length suffix in selected bytecode."
			});
			for (const [index, fn] of value.functions.entries()) if (fn.bytecode_offset >= value.bytecode.bytes) context.addIssue({
				code: "custom",
				path: [
					"functions",
					index,
					"bytecode_offset"
				],
				message: "Inferred body offset lies outside the selected bytecode."
			});
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/evmInterfaceView.js
var evmViewRequestSchema, evmViewItemSchema, evmSummarySchema, projectEvmInterfaceView;
function init_evmInterfaceView() {
	return (init_evmInterfaceView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_evmInterface();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		init_analysisViewText();
		evmViewRequestSchema = z.strictObject({
			kind: z.literal("evm"),
			facet: z.enum([
				"functions",
				"bytecode_hex",
				"stdout",
				"stderr"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		evmViewItemSchema = z.union([evmInterfaceSchema.shape.functions, z.strictObject({
			text: z.string(),
			unit: z.literal("utf16-code-units")
		})]);
		evmSummarySchema = z.strictObject({
			artifact: evmInterfaceSchema.shape.artifact,
			bytecode: evmInterfaceSchema.shape.bytecode.omit({ hex: true }),
			evidence_kind: evmInterfaceSchema.shape.evidence_kind,
			functions: evmInterfaceSchema.shape.functions,
			discovery_completeness: evmInterfaceSchema.shape.discovery_completeness,
			runtime_execution: evmInterfaceSchema.shape.runtime_execution,
			diagnostics: evmInterfaceSchema.shape.diagnostics.omit({ stdout: true }).extend({ stdout_code_units: z.number().int().nonnegative() }),
			limitations: evmInterfaceSchema.shape.limitations
		});
		projectEvmInterfaceView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "evm") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "EVM Evidence supports summary and evm views."
			}]));
			const parsed = parseAnalysisViewResult(evmInterfaceSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			if (parent.subject == null || parent.subject.format !== "file" || parent.subject.local_path !== report.artifact.path || parent.subject.digest.sha256 !== report.artifact.sha256) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "EVM parent subject must identify the report's exact carrier path and SHA-256."
			}]));
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_evm_interface",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: uniqueSorted([...parent.limitations, ...report.limitations]),
				unknowns: ["Candidates remain inferred; discovery completeness, bytecode kind, hardfork and deployment authenticity are unknown. Runtime execution was not performed."]
			};
			if (view.kind === "summary") {
				const { hex: _hex, ...bytecode } = report.bytecode;
				const { stdout, ...diagnostics } = report.diagnostics;
				return ok({
					kind: "summary",
					view,
					...shared,
					summary: {
						artifact: report.artifact,
						bytecode,
						evidence_kind: report.evidence_kind,
						functions: report.functions,
						discovery_completeness: report.discovery_completeness,
						runtime_execution: report.runtime_execution,
						diagnostics: {
							...diagnostics,
							stdout_code_units: stdout.length
						},
						limitations: report.limitations
					},
					coverage: completeWithinViewCoverage(report.functions.length, report.functions.length)
				});
			}
			if (view.facet === "functions") {
				const item = report.functions.slice(view.offset, view.offset + view.limit);
				return ok({
					kind: "evm",
					view,
					item,
					...shared,
					coverage: pageViewCoverage(view.offset, item.length, report.functions.length)
				});
			}
			const text = view.facet === "bytecode_hex" ? report.bytecode.hex : report.diagnostics[view.facet];
			const page = analysisTextPage(text, view.offset, view.limit, view.facet);
			return page.ok ? ok({
				kind: "evm",
				view,
				...page.value,
				...shared
			}) : page;
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/artifactInventoryView.js
var page$2, artifactInventoryViewRequestSchema, artifactInventoryItemsSchema, artifactInventorySummarySchema, inputError, checkedSources, parseSource, parseSourceUncached, sourceFailure, projectArtifactInventoryView, occurrencePage, nodePage, inventoryCounts, occurrenceIndices, nodeIndices, selectFields$1, selectOccurrenceFields;
function init_artifactInventoryView() {
	return (init_artifactInventoryView = __esmMin((() => {
		init_artifactGraph();
		init_artifactInspection();
		init_artifactFormatMetadata();
		init_digests();
		init_immutableJson();
		init_analysisErrorCore();
		init_canonicalOrdering();
		init_result();
		init_artifactInventoryEvidence();
		init_analysisViewCoverage();
		page$2 = {
			kind: z.literal("inventory"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		artifactInventoryViewRequestSchema = z.discriminatedUnion("collection", [
			z.strictObject({
				...page$2,
				collection: z.literal("occurrences"),
				occurrence_ids: z.array(prefixedDigestSchema("occ")).optional(),
				logical_paths: z.array(z.string()).optional(),
				entry_kinds: z.array(artifactOccurrenceSchema.shape.entry_kind).optional(),
				fields: z.array(artifactOccurrenceSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$2,
				collection: z.literal("nodes"),
				artifact_ids: z.array(prefixedDigestSchema("art")).optional(),
				fields: z.array(artifactNodeSchema.keyof()).optional()
			}),
			z.strictObject({
				...page$2,
				collection: z.enum(["edges", "integrity_contradictions"])
			})
		]);
		artifactInventoryItemsSchema = z.array(z.union([
			artifactNodeSchema.partial().required({ artifact_id: true }).strict(),
			artifactOccurrenceSchema.partial().required({
				occurrence_id: true,
				artifact_id: true,
				parent_occurrence_id: true
			}).strict(),
			artifactEdgeSchema,
			integrityContradictionSchema
		]));
		artifactInventorySummarySchema = z.strictObject({
			source_coverage: artifactInventoryCoverageSchema.exactOptional(),
			available_hash_status_counts: z.strictObject({
				verified: z.number().int().nonnegative(),
				mismatched: z.number().int().nonnegative(),
				unavailable: z.number().int().nonnegative(),
				"not-hashed": z.number().int().nonnegative()
			}).exactOptional(),
			manifest: artifactGraphManifestSchema,
			root_format_metadata: artifactFormatMetadataSchema.exactOptional(),
			available_counts: z.strictObject({
				nodes: z.number().int().nonnegative(),
				occurrences: z.number().int().nonnegative(),
				edges: z.number().int().nonnegative(),
				integrity_contradictions: z.number().int().nonnegative()
			}),
			observed_entry_kind_counts: z.strictObject({
				file: z.number().int().nonnegative(),
				directory: z.number().int().nonnegative(),
				symlink: z.number().int().nonnegative(),
				slice: z.number().int().nonnegative(),
				metadata: z.number().int().nonnegative().exactOptional()
			}),
			source_complete: z.boolean(),
			inventory_evidence_ids: z.array(prefixedDigestSchema("ev")).min(1),
			inspection: z.strictObject({
				coverage: artifactInspectionResultSchema.shape.coverage,
				unexplored_branches: artifactInspectionResultSchema.shape.unexplored_branches
			}).nullable(),
			limitation_count: z.number().int().nonnegative()
		});
		inputError = (message) => new AnalysisInputError("inspect_analysis_view", undefined, [{
			path: ["source"],
			reason: "invalid_value",
			message
		}]);
		checkedSources = new WeakMap();
		parseSource = (parent) => {
			const key = parent.normalizedResult;
			const reusable = parent.sealedResult === true && typeof key === "object" && key !== null && isImmutableJsonSnapshot(key);
			const cached = reusable ? checkedSources.get(key) : undefined;
			if (cached !== undefined && cached.operation === parent.operation) {
				try {
					validateArtifactInventorySubject(parent.subject ?? null, cached.source.inventory.manifest);
				} catch (cause) {
					return sourceFailure(cause);
				}
				return ok(cached.source);
			}
			const parsed = parseSourceUncached(parent);
			if (parsed.ok && reusable) checkedSources.set(key, {
				operation: parent.operation,
				source: parsed.value
			});
			return parsed;
		};
		parseSourceUncached = (parent) => {
			try {
				if (parent.operation === "inventory_artifact") return ok({
					inventory: parseArtifactInventoryResult(parent.normalizedResult, parent.subject ?? null),
					evidenceIds: [],
					inspection: null
				});
				const parsed = parseArtifactInspectionInventoryResult(parent.normalizedResult, parent.subject ?? null);
				return ok({
					inventory: parsed.inventory,
					evidenceIds: parsed.evidenceIds,
					inspection: parsed.inspection
				});
			} catch (cause) {
				return sourceFailure(cause);
			}
		};
		sourceFailure = (cause) => {
			if (!(cause instanceof TypeError) && !(cause instanceof z.ZodError)) throw cause;
			return err(inputError(cause.message));
		};
		projectArtifactInventoryView = (parent, view) => {
			const operation = parent.operation;
			if (operation !== "inventory_artifact" && operation !== "inspect_artifact") return err(inputError("Inventory views require inventory_artifact or inspect_artifact Evidence."));
			if (view.kind !== "summary" && view.kind !== "inventory") return err(inputError("Artifact Evidence supports summary and inventory views."));
			const parsed = parseSource(parent);
			if (!parsed.ok) return parsed;
			const source = parsed.value;
			const { inventory, inspection } = source;
			const evidenceIds = inspection === null ? [parent.evidenceId] : source.evidenceIds;
			if (source.rootMetadata === undefined) source.rootMetadata = inventory.occurrences.find((row) => row.logical_path === ".")?.format_metadata ?? null;
			const rootMetadata = source.rootMetadata;
			const includeCoverage = view.kind === "inventory" || inventory.manifest.root_format === "godot-pck" || inventory.manifest.root_format === "pyinstaller";
			const sourceCoverage = includeCoverage ? { source_coverage: inventory.coverage } : {};
			const counts = includeCoverage || view.kind === "summary" ? inventoryCounts(source) : undefined;
			const limitations = uniqueSorted([
				...parent.limitations,
				...inventory.limitations,
				...inspection?.limitations ?? []
			]);
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: operation,
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: parent.artifact?.path ?? "",
					sha256: inventory.manifest.root_sha256
				},
				limitations,
				unknowns: [
					"Inventory does not establish application runtime behavior or complete format-specific analysis.",
					...includeCoverage && inventory.coverage.status === "unknown" ? ["Producer traversal coverage is unknown; missing matches do not prove source absence."] : [],
					...includeCoverage && counts !== undefined && (counts.hashes.unavailable > 0 || counts.hashes["not-hashed"] > 0) ? ["Content hashes are unknown for some recorded files; missing node IDs do not prove content absence."] : [],
					...inventory.complete ? [] : ["Parent inventory is partial; counts and exhausted pages cover only available records. Missing matches do not establish absence."]
				]
			};
			if (view.kind === "summary") {
				const counts = inventoryCounts(source);
				const examined = inventory.nodes.length + inventory.occurrences.length + inventory.edges.length;
				return ok({
					kind: "summary",
					view,
					summary: {
						manifest: inventory.manifest,
						available_counts: {
							nodes: inventory.nodes.length,
							occurrences: inventory.occurrences.length,
							edges: inventory.edges.length,
							integrity_contradictions: inventory.integrityContradictions.length
						},
						observed_entry_kind_counts: {
							file: counts.kinds.file,
							directory: counts.kinds.directory,
							symlink: counts.kinds.symlink,
							slice: counts.kinds.slice,
							...counts.kinds.metadata === 0 ? {} : { metadata: counts.kinds.metadata }
						},
						...includeCoverage ? { available_hash_status_counts: counts.hashes } : {},
						source_complete: inventory.complete,
						...sourceCoverage,
						inventory_evidence_ids: [...evidenceIds],
						...rootMetadata === null ? {} : { root_format_metadata: rootMetadata },
						inspection: inspection === null ? null : {
							coverage: inspection.coverage,
							unexplored_branches: inspection.unexplored_branches
						},
						limitation_count: limitations.length
					},
					coverage: completeWithinViewCoverage(examined, examined),
					...shared
				});
			}
			const selected = view.collection === "occurrences" ? occurrencePage(source, view) : view.collection === "nodes" ? nodePage(source, view) : {
				items: (view.collection === "edges" ? inventory.edges : inventory.integrityContradictions).slice(view.offset, view.offset + view.limit),
				total: view.collection === "edges" ? inventory.edges.length : inventory.integrityContradictions.length
			};
			return ok({
				kind: "inventory",
				view,
				manifest: inventory.manifest,
				inventory_evidence_ids: [...evidenceIds],
				source_complete: inventory.complete,
				...sourceCoverage,
				items: selected.items,
				coverage: pageViewCoverage(view.offset, selected.items.length, selected.total),
				...shared
			});
		};
		occurrencePage = (source, view) => {
			const indices = occurrenceIndices(source, view);
			const rows = source.inventory.occurrences;
			const total = indices?.length ?? rows.length;
			const items = [];
			for (let at = view.offset; at < Math.min(total, view.offset + view.limit); at++) items.push(selectOccurrenceFields(rows[indices?.[at] ?? at], view.fields));
			return {
				items,
				total
			};
		};
		nodePage = (source, view) => {
			const indices = nodeIndices(source, view.artifact_ids);
			const rows = source.inventory.nodes;
			const total = indices?.length ?? rows.length;
			const items = [];
			for (let at = view.offset; at < Math.min(total, view.offset + view.limit); at++) {
				const row = rows[indices?.[at] ?? at];
				items.push(view.fields === undefined ? row : {
					...selectFields$1(row, view.fields),
					artifact_id: row.artifact_id
				});
			}
			return {
				items,
				total
			};
		};
		inventoryCounts = (source) => {
			if (source.counts !== undefined) return source.counts;
			const kinds = {
				file: 0,
				directory: 0,
				symlink: 0,
				slice: 0,
				metadata: 0
			};
			const hashes = {
				verified: 0,
				mismatched: 0,
				unavailable: 0,
				"not-hashed": 0
			};
			for (const occurrence of source.inventory.occurrences) {
				kinds[occurrence.entry_kind]++;
				if (occurrence.entry_kind === "file" || occurrence.entry_kind === "slice") hashes[occurrence.hash_status]++;
			}
			source.counts = Object.freeze({
				kinds: Object.freeze(kinds),
				hashes: Object.freeze(hashes)
			});
			return source.counts;
		};
		occurrenceIndices = (source, view) => {
			if (view.occurrence_ids === undefined && view.logical_paths === undefined && view.entry_kinds === undefined) return undefined;
			if (view.occurrence_ids?.length === 0 || view.logical_paths?.length === 0 || view.entry_kinds?.length === 0) return [];
			if (source.index === undefined) {
				const byId = new Map();
				const byPath = new Map();
				const byKind = new Map();
				for (const [index, row] of source.inventory.occurrences.entries()) {
					byId.set(row.occurrence_id, index);
					const existing = byPath.get(row.logical_path);
					if (existing === undefined) byPath.set(row.logical_path, [index]);
					else existing.push(index);
					const kind = byKind.get(row.entry_kind);
					if (kind === undefined) byKind.set(row.entry_kind, [index]);
					else kind.push(index);
				}
				source.index = {
					byId,
					byPath,
					byKind
				};
			}
			const lookup = source.index;
			const paths = view.logical_paths === undefined ? undefined : new Set(view.logical_paths);
			const selected = view.occurrence_ids === undefined ? paths === undefined ? [...new Set(view.entry_kinds)].flatMap((kind) => lookup.byKind.get(kind) ?? []) : [...paths].flatMap((path) => lookup.byPath.get(path) ?? []) : [...new Set(view.occurrence_ids)].flatMap((id) => {
				const index = lookup.byId.get(id);
				return index === undefined || paths !== undefined && !paths.has(source.inventory.occurrences[index].logical_path) ? [] : [index];
			});
			const kinds = view.entry_kinds === undefined ? undefined : new Set(view.entry_kinds);
			return selected.filter((index) => kinds === undefined || kinds.has(source.inventory.occurrences[index].entry_kind)).sort((left, right) => left - right);
		};
		nodeIndices = (source, ids) => {
			if (ids === undefined) return undefined;
			if (ids.length === 0) return [];
			const byId = source.nodeIndex ??= new Map(source.inventory.nodes.map((row, index) => [row.artifact_id, index]));
			return [...new Set(ids)].flatMap((id) => {
				const index = byId.get(id);
				return index === undefined ? [] : [index];
			}).sort((left, right) => left - right);
		};
		selectFields$1 = (row, fields) => {
			if (fields === undefined) return row;
			const selected = {};
			for (const field of fields) {
				const value = row[field];
				if (value !== undefined) selected[field] = value;
			}
			return selected;
		};
		selectOccurrenceFields = (row, fields) => fields === undefined ? row : {
			...selectFields$1(row, fields),
			occurrence_id: row.occurrence_id,
			artifact_id: row.artifact_id,
			parent_occurrence_id: row.parent_occurrence_id
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/managedArtifactView.js
var managedViewRequestSchema, managedViewItemSchema, managedSummarySchema, managedViewContextSchema, managedViewIdentityUnknowns, projectManagedArtifactView;
function init_managedArtifactView() {
	return (init_managedArtifactView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_managedArtifact();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		managedViewRequestSchema = z.strictObject({
			kind: z.literal("managed"),
			collection: z.enum([
				"references",
				"resources",
				"attributes"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		managedViewItemSchema = z.union([
			managedArtifactInspectionSchema.shape.references,
			managedArtifactInspectionSchema.shape.resources,
			managedArtifactInspectionSchema.shape.attributes
		]);
		managedSummarySchema = managedArtifactInspectionSchema.omit({
			references: true,
			resources: true,
			attributes: true
		}).extend({
			reported_counts: z.strictObject({
				references: z.number().int().nonnegative(),
				resources: z.number().int().nonnegative(),
				attributes: z.number().int().nonnegative()
			}),
			identity_scope: managedMemberInspectionSchema.shape.identity_scope
		});
		managedViewContextSchema = z.strictObject({
			identity_scope: managedMemberInspectionSchema.shape.identity_scope,
			source_metadata_status: managedArtifactInspectionSchema.shape.metadata.shape.status,
			source_coverage: managedArtifactInspectionSchema.shape.coverage
		});
		managedViewIdentityUnknowns = (parent, mvid) => [
			"Metadata tokens are build-local coordinates bound to the recorded artifact SHA-256 and module MVID; this view does not load or execute the assembly.",
			...parent.subject == null ? ["The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest."] : [],
			...mvid === null ? ["The module MVID is unknown; tokens cannot establish a cross-observation module match."] : []
		];
		projectManagedArtifactView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "managed") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Managed artifact inspection supports summary and managed views."
			}]));
			const parsed = parseAnalysisViewResult(managedArtifactInspectionSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const identity_scope = {
				token_identity: "build-local",
				requires_artifact_sha256: report.artifact.sha256,
				requires_mvid: report.module?.mvid ?? null
			};
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_managed_artifact",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: uniqueSorted([...parent.limitations, ...report.limitations]),
				unknowns: ["Collection counts and pages cover producer-returned rows; metadata completeness remains the original metadata status and coverage, not an absence claim about unreturned rows.", ...managedViewIdentityUnknowns(parent, identity_scope.requires_mvid)]
			};
			if (view.kind === "summary") {
				const { references, resources, attributes, ...summary } = report;
				const reported_counts = {
					references: references.length,
					resources: resources.length,
					attributes: attributes.length
				};
				const total = references.length + resources.length + attributes.length;
				return ok({
					kind: "summary",
					view,
					...shared,
					summary: {
						...summary,
						reported_counts,
						identity_scope
					},
					coverage: completeWithinViewCoverage(total, total)
				});
			}
			const collection = report[view.collection];
			const item = collection.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "managed",
				view,
				item,
				...shared,
				identity_scope,
				source_metadata_status: report.metadata.status,
				source_coverage: report.coverage,
				coverage: pageViewCoverage(view.offset, item.length, collection.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/managedMemberView.js
var member$1, managedMembersViewRequestSchema, rowsOf, managedMembersViewPageSchema, nullableCount, managedMemberSummarySchema, managedMembersViewContextSchema, slice, collectionPage, validatedReports, parseMemberReport, summarizeMembers, projectManagedMemberView;
function init_managedMemberView() {
	return (init_managedMemberView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_managedArtifact();
		init_result();
		init_analysisViewCoverage();
		init_managedArtifactView();
		init_analysisViewParent();
		member$1 = managedMemberInspectionSchema.shape;
		managedMembersViewRequestSchema = z.strictObject({
			kind: z.literal("managed-members"),
			collection: z.enum([
				"types",
				"exported_types",
				"fields",
				"methods",
				"member_refs",
				"call_edges",
				"field_accesses",
				"user_strings"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		rowsOf = (collection, rows) => z.strictObject({
			collection: z.literal(collection),
			rows
		});
		managedMembersViewPageSchema = z.discriminatedUnion("collection", [
			rowsOf("types", member$1.types),
			rowsOf("exported_types", member$1.exported_types.unwrap().unwrap()),
			rowsOf("fields", member$1.fields),
			rowsOf("methods", member$1.methods),
			rowsOf("member_refs", member$1.member_refs),
			rowsOf("call_edges", member$1.call_edges),
			rowsOf("field_accesses", member$1.field_accesses),
			rowsOf("user_strings", member$1.user_strings.unwrap().unwrap().shape.literals)
		]);
		nullableCount = z.number().int().nonnegative().nullable();
		managedMemberSummarySchema = z.strictObject({
			signature_resolution: member$1.signature_resolution,
			nesting_read: member$1.nesting_read,
			artifact: member$1.artifact,
			module: member$1.module,
			metadata: member$1.metadata,
			identity_scope: member$1.identity_scope,
			selection: member$1.selection.unwrap(),
			coverage: member$1.coverage,
			user_strings: z.strictObject({
				state: member$1.user_strings.unwrap().unwrap().shape.state,
				issues: member$1.user_strings.unwrap().unwrap().shape.issues
			}).nullable(),
			limitations: member$1.limitations,
			reported_counts: z.strictObject({
				types: z.number().int().nonnegative(),
				exported_types: nullableCount,
				fields: z.number().int().nonnegative(),
				methods: z.number().int().nonnegative(),
				member_refs: z.number().int().nonnegative(),
				call_edges: z.number().int().nonnegative(),
				field_accesses: z.number().int().nonnegative(),
				user_strings: nullableCount
			})
		});
		managedMembersViewContextSchema = z.strictObject({
			signature_resolution: member$1.signature_resolution,
			nesting_read: member$1.nesting_read,
			identity_scope: member$1.identity_scope,
			selection: member$1.selection.unwrap(),
			source_metadata_status: member$1.metadata.shape.status,
			source_coverage: member$1.coverage
		});
		slice = (collection, rows, { offset, limit }) => rows == null ? null : {
			page: {
				collection,
				rows: rows.slice(offset, offset + limit)
			},
			total: rows.length
		};
		collectionPage = (report, view) => {
			const { collection } = view;
			switch (collection) {
				case "types": return slice(collection, report.types, view);
				case "exported_types": return slice(collection, report.exported_types, view);
				case "fields": return slice(collection, report.fields, view);
				case "methods": return slice(collection, report.methods, view);
				case "member_refs": return slice(collection, report.member_refs, view);
				case "call_edges": return slice(collection, report.call_edges, view);
				case "field_accesses": return slice(collection, report.field_accesses, view);
				case "user_strings": return slice(collection, report.user_strings?.literals, view);
			}
		};
		validatedReports = new WeakMap();
		parseMemberReport = (parent) => {
			const { normalizedResult } = parent;
			const sealed = parent.sealedResult === true && typeof normalizedResult === "object" && normalizedResult !== null;
			const cached = sealed ? validatedReports.get(normalizedResult)?.deref() : undefined;
			if (cached !== undefined) return ok(cached);
			const parsed = parseAnalysisViewResult(managedMemberInspectionSchema, parent);
			if (parsed.ok && sealed) validatedReports.set(normalizedResult, new WeakRef(parsed.value));
			return parsed;
		};
		summarizeMembers = (report) => {
			const { types, exported_types, fields, methods, member_refs, call_edges, field_accesses, user_strings, ...identity } = report;
			return {
				...identity,
				user_strings: user_strings === null ? null : {
					state: user_strings.state,
					issues: user_strings.issues
				},
				reported_counts: {
					types: types.length,
					exported_types: exported_types?.length ?? null,
					fields: fields.length,
					methods: methods.length,
					member_refs: member_refs.length,
					call_edges: call_edges.length,
					field_accesses: field_accesses.length,
					user_strings: user_strings?.literals.length ?? null
				}
			};
		};
		projectManagedMemberView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "managed-members") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Managed member inspection supports summary and managed-members views."
			}]));
			const parsed = parseMemberReport(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_managed_members",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: uniqueSorted([...parent.limitations, ...report.limitations]),
				unknowns: [
					"Collection counts and pages cover producer-returned rows; member completeness remains the original coverage, not an absence claim about unreturned rows.",
					...report.selection === null ? [] : ["Exported types and member references cover the whole assembly; the other collections cover only the selected declaring types."],
					...managedViewIdentityUnknowns(parent, report.identity_scope.requires_mvid)
				]
			};
			if (view.kind === "summary") {
				const summary = summarizeMembers(report);
				const total = Object.values(summary.reported_counts).reduce((sum, count) => sum + (count ?? 0), 0);
				return ok({
					kind: "summary",
					view,
					...shared,
					summary,
					coverage: completeWithinViewCoverage(total, total)
				});
			}
			const selected = collectionPage(report, view);
			if (selected === null) return err(analysisViewInputError([{
				path: ["view", "collection"],
				reason: "invalid_value",
				message: `The parent Evidence did not examine ${view.collection}; repeat inspect_managed_members with the current runtime to record it.`
			}]));
			const { page, total } = selected;
			return ok({
				kind: "managed-members",
				view,
				page,
				...shared,
				signature_resolution: report.signature_resolution,
				nesting_read: report.nesting_read,
				identity_scope: report.identity_scope,
				selection: report.selection,
				source_metadata_status: report.metadata.status,
				source_coverage: view.collection === "user_strings" && report.user_strings !== null ? {
					state: report.user_strings.state,
					issues: report.user_strings.issues
				} : report.coverage,
				coverage: pageViewCoverage(view.offset, page.rows.length, total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/wasm/wasmInterface.js
var kind, valueType, limit, signature, wasmInterfaceSchema, WASM_INTERFACE_REPRESENTATION_BYTES, wasmInterfaceEntryRepresentationBytes;
function init_wasmInterface() {
	return (init_wasmInterface = __esmMin((() => {
		kind = z.enum([
			"func",
			"table",
			"memory",
			"global",
			"tag",
			"unknown"
		]);
		valueType = z.enum([
			"i32",
			"i64",
			"f32",
			"f64",
			"v128",
			"funcref",
			"externref"
		]);
		limit = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
		signature = z.discriminatedUnion("kind", [
			z.object({
				kind: z.literal("func"),
				params: z.array(valueType),
				results: z.array(valueType)
			}),
			z.object({
				kind: z.literal("tag"),
				params: z.array(valueType),
				results: z.array(valueType)
			}),
			z.object({
				kind: z.literal("table"),
				element: z.enum(["funcref", "externref"]),
				address_type: z.enum(["i32", "i64"]),
				minimum: limit,
				maximum: limit.nullable(),
				shared: z.boolean()
			}),
			z.object({
				kind: z.literal("memory"),
				page_size: limit,
				address_type: z.enum(["i32", "i64"]),
				minimum: limit,
				maximum: limit.nullable(),
				shared: z.boolean()
			}),
			z.object({
				kind: z.literal("global"),
				value_type: valueType,
				mutable: z.boolean()
			})
		]);
		wasmInterfaceSchema = z.object({
			state: z.enum(["complete", "partial"]),
			entries: z.array(z.object({
				direction: z.enum(["import", "export"]),
				module: z.string().nullable(),
				name: z.string(),
				kind,
				index: z.number().int().nonnegative().max(4294967295).nullable(),
				signature: signature.nullable(),
				wat_form: z.string(),
				issue: z.string().nullable()
			}).superRefine((entry, context) => {
				if (entry.direction === "export" && entry.module !== null || entry.direction === "import" && entry.module === null) context.addIssue({
					code: "custom",
					message: "Interface direction does not match module-name presence"
				});
				if (entry.signature !== null && entry.signature.kind !== entry.kind) context.addIssue({
					code: "custom",
					message: "Interface kind does not match its typed signature"
				});
			})),
			issues: z.array(z.string())
		});
		WASM_INTERFACE_REPRESENTATION_BYTES = 32 * 1024 * 1024;
		wasmInterfaceEntryRepresentationBytes = (entry) => {
			let bytes = 1024 + [
				entry.module,
				entry.name,
				entry.wat_form,
				entry.issue
			].reduce((sum, value) => sum + (value?.length ?? 0) * 6, 0);
			const signature = entry.signature;
			if (signature?.kind === "func" || signature?.kind === "tag") bytes += (signature.params.length + signature.results.length) * 16;
			else if (signature !== null) {
				for (const value of Object.values(signature)) if (typeof value === "string") bytes += value.length * 6;
			}
			return bytes;
		};
	})))();
}

//#endregion
//#region dist/domain/wasm/wasmArtifact.js
var digest, artifact, DEFAULT_WASM_COMMAND_TIMEOUT_MS, MAX_WASM_COMMAND_TIMEOUT_MS, inspectWasmArtifactInputSchema, wasmArtifactSchema, wasmArtifactMatchesSubject;
function init_wasmArtifact() {
	return (init_wasmArtifact = __esmMin((() => {
		init_wasmInterface();
		init_localPath();
		digest = z.string().regex(/^[a-f0-9]{64}$/);
		artifact = z.strictObject({
			path: z.string().min(1),
			sha256: digest,
			bytes: z.number().int().nonnegative()
		});
		DEFAULT_WASM_COMMAND_TIMEOUT_MS = 3e4;
		MAX_WASM_COMMAND_TIMEOUT_MS = 2147483647;
		inspectWasmArtifactInputSchema = z.strictObject({
			path: localPathStringSchema.describe("Absolute selected local WASM artifact path"),
			glue_paths: z.array(localPathStringSchema).max(16).default([]),
			candidate_paths: z.array(localPathStringSchema).max(16).default([]),
			command_timeout_ms: z.number().int().min(1).max(MAX_WASM_COMMAND_TIMEOUT_MS).exactOptional().describe(`Deadline in milliseconds for each WABT version/analysis command (default ${String(DEFAULT_WASM_COMMAND_TIMEOUT_MS)}), not the whole inspection. Allow additional client time for all commands, file checks and cleanup. Input/output safety limits remain fixed.`)
		});
		wasmArtifactSchema = z.strictObject({
			artifact,
			validation: z.literal("valid"),
			sections: z.array(z.strictObject({
				kind: z.string().min(1),
				start: z.number().int().nonnegative(),
				end: z.number().int().nonnegative(),
				bytes: z.number().int().nonnegative(),
				description: z.string()
			})),
			interface: wasmInterfaceSchema.exactOptional(),
			imports: z.array(z.string()),
			exports: z.array(z.string()),
			headers: z.string(),
			details: z.string(),
			wat: z.strictObject({
				text: z.string().min(1),
				sha256: digest,
				representation: z.literal("decoded-wat")
			}),
			tool_profile: z.strictObject({
				source: z.literal("https://github.com/WebAssembly/wabt"),
				release: z.literal("1.0.42"),
				source_commit: z.literal("ff0ef7e0009402740c805a9744c09b05be063e48"),
				commands: z.array(z.strictObject({
					tool: z.enum([
						"wasm-validate",
						"wasm-objdump",
						"wasm2wat"
					]),
					path: z.string().min(1),
					sha256: digest,
					version_banner: z.string(),
					arguments: z.array(z.string())
				})).length(3),
				timeout_ms: z.number().int().positive(),
				output_budget_bytes: z.number().int().positive()
			}),
			candidates: z.array(artifact),
			glue: z.array(z.strictObject({
				artifact,
				parse_status: z.enum([
					"complete",
					"partial",
					"failed"
				]),
				references: z.array(z.strictObject({
					value: z.string(),
					line: z.number().int().positive(),
					column: z.number().int().nonnegative(),
					candidate_paths: z.array(z.string()),
					association: z.enum([
						"local-path-candidate",
						"basename-candidates",
						"unresolved"
					]),
					evidence_kind: z.literal("static-literal")
				}))
			})),
			runtime_execution: z.literal("not-performed"),
			network_fetch: z.literal("not-performed"),
			limitations: z.array(z.string())
		}).superRefine((value, context) => {
			if (createHash("sha256").update(value.wat.text, "utf8").digest("hex") !== value.wat.sha256) context.addIssue({
				code: "custom",
				path: ["wat", "sha256"],
				message: "Decoded WAT digest does not match its UTF-8 text."
			});
			const selected = value.candidates[0];
			if (selected?.path !== value.artifact.path || selected.sha256 !== value.artifact.sha256 || selected.bytes !== value.artifact.bytes) context.addIssue({
				code: "custom",
				path: ["candidates"],
				message: "Selected candidate does not match artifact identity."
			});
			for (const [index, command] of value.tool_profile.commands.entries()) {
				const expected = [
					"wasm-validate",
					"wasm-objdump",
					"wasm2wat"
				][index];
				const argumentsExpected = command.tool === "wasm-objdump" ? [
					"-h",
					"-x",
					"module.wasm"
				] : ["--enable-all", "module.wasm"];
				if (command.tool !== expected || command.version_banner.trim() !== "1.0.42" || JSON.stringify(command.arguments) !== JSON.stringify(argumentsExpected)) context.addIssue({
					code: "custom",
					path: [
						"tool_profile",
						"commands",
						index
					],
					message: "Unexpected WABT command profile."
				});
			}
			for (const [index, section] of value.sections.entries()) if (section.end > value.artifact.bytes || section.end - section.start !== section.bytes) context.addIssue({
				code: "custom",
				path: ["sections", index],
				message: "Section range does not match selected artifact bytes."
			});
		});
		wasmArtifactMatchesSubject = (artifact, subject) => subject != null && subject.path === artifact.path && subject.sha256 === artifact.sha256 && subject.format === "file";
	})))();
}

//#endregion
//#region dist/domain/analysisView/wasmArtifactView.js
var wasmViewRequestSchema, wasmViewItemSchema, wasmSummarySchema, projectWasmArtifactView;
function init_wasmArtifactView() {
	return (init_wasmArtifactView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_result();
		init_analysisViewParent();
		init_wasmArtifact();
		init_analysisViewCoverage();
		init_analysisViewText();
		wasmViewRequestSchema = z.strictObject({
			kind: z.literal("wasm"),
			facet: z.enum([
				"sections",
				"imports",
				"exports",
				"candidates",
				"glue",
				"wat",
				"headers",
				"details",
				"tool_profile"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		wasmViewItemSchema = z.union([
			wasmArtifactSchema.shape.sections,
			wasmArtifactSchema.shape.imports,
			wasmArtifactSchema.shape.candidates,
			wasmArtifactSchema.shape.glue,
			wasmArtifactSchema.shape.tool_profile,
			z.strictObject({
				text: z.string(),
				unit: z.literal("utf16-code-units")
			})
		]);
		wasmSummarySchema = z.strictObject({
			bytes: wasmArtifactSchema.shape.artifact.shape.bytes,
			validation: wasmArtifactSchema.shape.validation,
			available_counts: z.strictObject({
				sections: z.number().int().nonnegative(),
				imports: z.number().int().nonnegative(),
				exports: z.number().int().nonnegative(),
				candidates: z.number().int().nonnegative(),
				glue: z.number().int().nonnegative()
			}),
			wat: wasmArtifactSchema.shape.wat.omit({ text: true }).extend({ code_units: z.number().int().nonnegative() }),
			tool_profile: wasmArtifactSchema.shape.tool_profile,
			runtime_execution: wasmArtifactSchema.shape.runtime_execution,
			network_fetch: wasmArtifactSchema.shape.network_fetch,
			limitation_count: z.number().int().nonnegative()
		});
		projectWasmArtifactView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "wasm") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "WASM Evidence supports summary and wasm views."
			}]));
			const parsed = parseAnalysisViewResult(wasmArtifactSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			if (!wasmArtifactMatchesSubject(report.artifact, parent.subject == null ? null : {
				path: parent.subject.local_path,
				sha256: parent.subject.digest.sha256,
				format: parent.subject.format
			})) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "WASM parent Evidence subject must identify the report's exact path and SHA-256."
			}]));
			const limitations = uniqueSorted([...parent.limitations, ...report.limitations]);
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_wasm_artifact",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations,
				unknowns: ["Decoded WAT is not original source. Runtime behavior and network acquisition were not performed.", ...report.glue.some((glue) => glue.parse_status !== "complete") ? ["Selected glue parsing is incomplete; unmatched references do not establish absence."] : []]
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: {
					bytes: report.artifact.bytes,
					validation: report.validation,
					available_counts: {
						sections: report.sections.length,
						imports: report.imports.length,
						exports: report.exports.length,
						candidates: report.candidates.length,
						glue: report.glue.length
					},
					wat: {
						sha256: report.wat.sha256,
						representation: report.wat.representation,
						code_units: report.wat.text.length
					},
					tool_profile: report.tool_profile,
					runtime_execution: report.runtime_execution,
					network_fetch: report.network_fetch,
					limitation_count: limitations.length
				},
				coverage: completeWithinViewCoverage(report.sections.length + report.imports.length + report.exports.length, report.sections.length + report.imports.length + report.exports.length)
			});
			if (view.facet === "tool_profile") {
				if (view.offset !== 0) return err(analysisViewInputError([{
					path: ["view", "offset"],
					reason: "invalid_value",
					message: "Singleton tool_profile requires offset 0."
				}]));
				return ok({
					kind: "wasm",
					view,
					item: report.tool_profile,
					coverage: completeWithinViewCoverage(1, 1),
					...shared
				});
			}
			if (view.facet === "wat" || view.facet === "headers" || view.facet === "details") {
				const text = view.facet === "wat" ? report.wat.text : report[view.facet];
				const page = analysisTextPage(text, view.offset, view.limit, view.facet);
				return page.ok ? ok({
					kind: "wasm",
					view,
					...page.value,
					...shared
				}) : page;
			}
			const rows = report[view.facet];
			const item = rows.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "wasm",
				view,
				item,
				coverage: pageViewCoverage(view.offset, item.length, rows.length),
				...shared
			});
		};
	})))();
}

//#endregion
//#region dist/domain/native/nativeInspection.js
var hexAddress, coverage, nativeCommandInvocationSchema, architectureSchema, permissionSchema, sectionSchema, segmentSchema, symbolSchema, dependencySchema, loadCommandSchema, buildMetadataSchema, inspectMachoSchema, inspectSignatureSchema, inspectPlistSchema, listArchitecturesSchema, demangleSwiftSchema;
function init_nativeInspection() {
	return (init_nativeInspection = __esmMin((() => {
		init_bundleResourceRoot();
		init_jsonValue();
		hexAddress = z.string().regex(/^0x[a-fA-F0-9]+$/u);
		coverage = (item) => z.object({
			items: z.array(item),
			total: z.number().int().min(0).nullable(),
			exhaustive: z.boolean(),
			limitations: z.array(z.string())
		});
		nativeCommandInvocationSchema = z.object({
			tool: z.string().min(1),
			command: z.array(z.string()),
			tool_version: z.string().nullable(),
			version_reason: z.string().nullable(),
			executable_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			exit: z.object({
				code: z.number().int().nullable(),
				signal: z.string().nullable()
			}),
			stdout_bytes: z.number().int().min(0),
			stderr_bytes: z.number().int().min(0)
		});
		architectureSchema = z.object({
			name: z.string(),
			cpu_type: z.string().nullable(),
			cpu_subtype: z.string().nullable(),
			file_offset: z.number().int().min(0).nullable().describe("Offset from the start of the input Mach-O container."),
			size: z.number().int().min(0).nullable(),
			alignment: z.number().int().min(0).nullable()
		});
		permissionSchema = z.object({
			read: z.boolean().nullable(),
			write: z.boolean().nullable(),
			execute: z.boolean().nullable(),
			raw: z.string().nullable()
		});
		sectionSchema = z.object({
			segment: z.string(),
			name: z.string(),
			address: hexAddress.nullable(),
			size: z.number().int().min(0).nullable(),
			file_offset: z.number().int().min(0).nullable().describe("Offset from the start of the selected Mach-O slice."),
			alignment: z.number().int().min(0).nullable(),
			flags: z.array(z.string())
		});
		segmentSchema = z.object({
			name: z.string(),
			vm_address: hexAddress.nullable(),
			vm_size: z.number().int().min(0).nullable(),
			file_offset: z.number().int().min(0).nullable().describe("Offset from the start of the selected Mach-O slice."),
			file_size: z.number().int().min(0).nullable(),
			maximum_permissions: permissionSchema,
			initial_permissions: permissionSchema,
			sections: coverage(sectionSchema)
		});
		symbolSchema = z.object({
			name: z.string(),
			address: hexAddress.nullable(),
			weak: z.boolean().nullable(),
			reexport: z.boolean().nullable(),
			source: z.string().nullable()
		});
		dependencySchema = z.object({
			path: z.string(),
			kind: z.string(),
			current_version: z.string().nullable(),
			compatibility_version: z.string().nullable()
		});
		loadCommandSchema = z.object({
			index: z.number().int().min(0),
			kind: z.string(),
			fields: z.record(z.string(), z.union([
				z.string(),
				z.number(),
				z.null()
			]))
		});
		buildMetadataSchema = z.object({
			platform: z.string().nullable(),
			minimum_os: z.string().nullable(),
			sdk: z.string().nullable(),
			tools: z.array(z.object({
				name: z.string(),
				version: z.string()
			}))
		});
		inspectMachoSchema = z.object({
			format: z.enum(["mach-o", "mach-o-universal"]),
			/** Exact lipo slice selected for inspection and its offset in the input container. */
			selected_architecture: z.object({
				name: z.string().nullable().describe("Exact architecture name selected from lipo output; null when selection is unknown."),
				container_file_offset: z.number().int().min(0).nullable().describe("Offset of the selected slice from the start of the input Mach-O container; null when unknown.")
			}),
			endian: z.enum(["little", "big"]).nullable(),
			word_size: z.union([z.literal(32), z.literal(64)]).nullable(),
			file_type: z.string().nullable(),
			flags: z.array(z.string()),
			uuid: z.string().nullable(),
			entrypoints: coverage(z.object({ file_offset: z.number().int().min(0).describe("LC_MAIN entry offset from the start of the selected Mach-O slice.") })),
			architectures: coverage(architectureSchema),
			build_metadata: coverage(buildMetadataSchema),
			load_commands: coverage(loadCommandSchema),
			dependencies: coverage(dependencySchema),
			imports: coverage(symbolSchema),
			exports: coverage(symbolSchema),
			segments: coverage(segmentSchema),
			provenance: z.array(nativeCommandInvocationSchema),
			limitations: z.array(z.string())
		});
		inspectSignatureSchema = z.object({
			signed: z.boolean(),
			identifier: z.string().nullable(),
			team_identifier: z.string().nullable(),
			format: z.string().nullable(),
			cdhashes: z.array(z.string()),
			hash_algorithms: z.array(z.string()),
			authorities: z.array(z.string()),
			designated_requirement: z.string().nullable(),
			entitlements: jsonValueSchema.nullable(),
			timestamp: z.string().nullable(),
			hardened_runtime: z.boolean().nullable(),
			provenance: z.array(nativeCommandInvocationSchema),
			limitations: z.array(z.string())
		});
		inspectPlistSchema = z.object({
			format: z.enum([
				"xml",
				"binary",
				"json",
				"unknown"
			]),
			value: jsonValueSchema,
			bundle: z.object({
				identifier: z.string().nullable(),
				executable: z.string().nullable(),
				name: z.string().nullable(),
				version: z.string().nullable(),
				short_version: z.string().nullable()
			}),
			source_path: z.string(),
			resource_root: bundleResourceRootSchema.optional(),
			provenance: z.array(nativeCommandInvocationSchema),
			limitations: z.array(z.string())
		});
		listArchitecturesSchema = z.object({
			architectures: coverage(architectureSchema),
			provenance: z.array(nativeCommandInvocationSchema),
			limitations: z.array(z.string())
		});
		demangleSwiftSchema = z.object({
			symbols: z.array(z.object({
				input: z.string(),
				output: z.string(),
				status: z.enum([
					"demangled",
					"unchanged",
					"invalid"
				])
			})),
			provenance: z.array(nativeCommandInvocationSchema),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/analysisView/machoView.js
var MACHO_COLLECTIONS, machoViewRequestSchema, shape, exactRows, machoViewItemSchema, machoViewContextSchema, collectionCountSchema, machoSummarySchema, parseMachoReport, summarizeMacho, projectMachoView;
function init_machoView() {
	return (init_machoView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_binaryTargetTypes();
		init_nativeInspection();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		MACHO_COLLECTIONS = [
			"entrypoints",
			"architectures",
			"build_metadata",
			"load_commands",
			"dependencies",
			"imports",
			"exports",
			"segments"
		];
		machoViewRequestSchema = z.strictObject({
			kind: z.literal("macho"),
			facet: z.enum([...MACHO_COLLECTIONS, "provenance"]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		({shape} = inspectMachoSchema);
		exactRows = (rows) => z.array(z.strictObject(rows.element.shape));
		machoViewItemSchema = z.union([
			exactRows(shape.entrypoints.shape.items),
			exactRows(shape.architectures.shape.items),
			exactRows(shape.build_metadata.shape.items),
			exactRows(shape.load_commands.shape.items),
			exactRows(shape.dependencies.shape.items),
			exactRows(shape.imports.shape.items),
			exactRows(shape.segments.shape.items),
			exactRows(shape.provenance)
		]);
		machoViewContextSchema = z.strictObject({
			source_total: z.number().int().nonnegative().nullable(),
			source_exhaustive: z.boolean()
		});
		collectionCountSchema = z.strictObject({
			returned: z.number().int().nonnegative(),
			total: z.number().int().nonnegative().nullable(),
			exhaustive: z.boolean()
		});
		machoSummarySchema = z.strictObject({
			format: shape.format,
			selected_architecture: shape.selected_architecture,
			endian: shape.endian,
			word_size: shape.word_size,
			file_type: shape.file_type,
			flags: shape.flags,
			uuid: shape.uuid,
			collections: z.strictObject(Object.fromEntries(MACHO_COLLECTIONS.map((name) => [name, collectionCountSchema]))),
			provenance_count: z.number().int().nonnegative(),
			limitation_count: z.number().int().nonnegative()
		});
		parseMachoReport = (parent) => {
			const parsed = parseAnalysisViewResult(inspectMachoSchema, parent);
			if (!parsed.ok) return parsed;
			if (parent.subject != null && !isMachOFormat(parent.subject.format)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Mach-O parent Evidence subject must identify a thin or universal Mach-O."
			}]));
			return ok(parsed.value);
		};
		summarizeMacho = (report, parentLimitations) => {
			const limitations = uniqueSorted([
				...parentLimitations,
				...report.limitations,
				...MACHO_COLLECTIONS.flatMap((name) => report[name].limitations)
			]);
			const collections = Object.fromEntries(MACHO_COLLECTIONS.map((name) => [name, {
				returned: report[name].items.length,
				total: report[name].total,
				exhaustive: report[name].exhaustive
			}]));
			return {
				limitations,
				returned: MACHO_COLLECTIONS.reduce((sum, name) => sum + report[name].items.length, 0),
				summary: {
					format: report.format,
					selected_architecture: report.selected_architecture,
					endian: report.endian,
					word_size: report.word_size,
					file_type: report.file_type,
					flags: report.flags,
					uuid: report.uuid,
					collections,
					provenance_count: report.provenance.length,
					limitation_count: limitations.length
				}
			};
		};
		projectMachoView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "macho") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Mach-O inspection supports summary and macho views."
			}]));
			const parsed = parseMachoReport(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const incomplete = MACHO_COLLECTIONS.filter((name) => !report[name].exhaustive);
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_macho",
				parent_digest: parent.evidenceId.slice(3),
				artifact: parent.subject == null ? {
					path: "",
					sha256: null
				} : {
					path: parent.subject.local_path,
					sha256: parent.subject.digest.sha256
				},
				unknowns: [...incomplete.length === 0 ? [] : [`Native tools did not report exhaustive ${incomplete.join(", ")}; page exhaustion does not establish absence of unreturned rows.`], ...parent.subject == null ? ["The parent has no recorded subject, so the inspected artifact path and SHA-256 are unknown."] : []]
			};
			if (view.kind === "summary") {
				const { summary, limitations, returned } = summarizeMacho(report, parent.limitations);
				return ok({
					kind: "summary",
					view,
					...shared,
					limitations,
					summary,
					coverage: completeWithinViewCoverage(returned, returned)
				});
			}
			const source = view.facet === "provenance" ? {
				items: report.provenance,
				total: report.provenance.length,
				exhaustive: true,
				limitations: []
			} : report[view.facet];
			const item = source.items.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "macho",
				view,
				item,
				...shared,
				limitations: uniqueSorted([
					...parent.limitations,
					...report.limitations,
					...source.limitations
				]),
				source_total: source.total,
				source_exhaustive: source.exhaustive,
				coverage: pageViewCoverage(view.offset, item.length, source.items.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/interfaceBuilderView.js
var page$1, interfaceBuilderViewRequestSchema, interfaceBuilderViewItemsSchema, interfaceBuilderViewContextSchema, countsSchema$1, interfaceBuilderSummarySchema, tally, parseInterfaceBuilderReport, summarizeInterfaceBuilder, projectInterfaceBuilderView;
function init_interfaceBuilderView() {
	return (init_interfaceBuilderView = __esmMin((() => {
		init_analysisViewErrors();
		init_canonicalOrdering();
		init_interfaceBuilderGraph();
		init_bundleResourceRoot();
		init_nativeInvestigationGraph();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		page$1 = {
			kind: z.literal("interface-builder"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		interfaceBuilderViewRequestSchema = z.discriminatedUnion("collection", [z.strictObject({
			...page$1,
			collection: z.enum(["nodes", "edges"]),
			document: z.string().min(1).optional().describe("Exact documents[].relative_path; selects rows whose evidence names that archive.")
		}), z.strictObject({
			...page$1,
			collection: z.enum(["documents", "coverage"])
		})]);
		interfaceBuilderViewItemsSchema = z.union([
			z.array(interfaceBuilderDocumentSchema),
			z.array(nativeInvestigationNodeSchema),
			z.array(nativeInvestigationEdgeSchema),
			z.array(nativeInvestigationCoverageSchema)
		]);
		interfaceBuilderViewContextSchema = z.strictObject({ source_truncated: z.boolean() });
		countsSchema$1 = z.record(z.string(), z.number().int().positive());
		interfaceBuilderSummarySchema = z.strictObject({
			target_sha256: z.string().regex(/^[a-f0-9]{64}$/u).nullable(),
			provider: nativeInvestigationProviderSchema,
			documents: interfaceBuilderDocumentSchema.array().max(64),
			available_counts: z.strictObject({
				nodes: z.number().int().nonnegative(),
				edges: z.number().int().nonnegative(),
				coverage: z.number().int().nonnegative()
			}),
			node_kinds: countsSchema$1,
			edge_relations: countsSchema$1,
			coverage_statuses: countsSchema$1,
			truncated: z.boolean(),
			limitation_count: z.number().int().nonnegative()
		});
		tally = (values) => {
			const counts = new Map();
			for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
			return Object.fromEntries([...counts].sort(([left], [right]) => left < right ? -1 : 1));
		};
		parseInterfaceBuilderReport = (parent) => {
			const parsed = parseAnalysisViewResult(interfaceBuilderAnalysisSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			if (report.graph.target_sha256 !== report.target_sha256 || parent.subject != null && parent.subject.digest.sha256 !== report.target_sha256) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Interface Builder parent Evidence subject and graph must identify the report's target SHA-256."
			}]));
			return ok(report);
		};
		summarizeInterfaceBuilder = (report, limitationCount) => {
			const { graph } = report;
			const total = report.documents.length + graph.nodes.length + graph.edges.length + graph.coverage.length;
			return {
				summary: interfaceBuilderSummarySchema.parse({
					target_sha256: report.target_sha256,
					provider: graph.provider,
					documents: report.documents,
					available_counts: {
						nodes: graph.nodes.length,
						edges: graph.edges.length,
						coverage: graph.coverage.length
					},
					node_kinds: tally(graph.nodes.map((node) => node.kind)),
					edge_relations: tally(graph.edges.map((edge) => edge.relation)),
					coverage_statuses: tally(graph.coverage.map((row) => row.status)),
					truncated: graph.truncated,
					limitation_count: limitationCount
				}),
				coverage: completeWithinViewCoverage(total, total)
			};
		};
		projectInterfaceBuilderView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "interface-builder") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Interface Builder decoding supports summary and interface-builder views."
			}]));
			const parsed = parseInterfaceBuilderReport(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const { graph } = report;
			const limitations = uniqueSorted([...parent.limitations, ...report.limitations]);
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "decode_interface_builder",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: parent.subject?.local_path ?? report.resource_root?.canonical_path ?? "",
					sha256: report.target_sha256
				},
				...report.resource_root === undefined ? {} : { resource_root: report.resource_root },
				limitations,
				unknowns: ["Rows describe recognized archive objects and connections only; unrecognized classes, fields and runtime-created UI remain unknown.", ...graph.truncated ? ["The decoded graph is incomplete (see coverage and limitations for the cause); page exhaustion does not establish absence of undecoded objects or connections."] : []]
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				...summarizeInterfaceBuilder(report, limitations.length)
			});
			const document = view.collection === "nodes" || view.collection === "edges" ? view.document : undefined;
			if (document !== undefined && !report.documents.some((row) => row.relative_path === document)) return err(analysisViewInputError([{
				path: ["view", "document"],
				reason: "invalid_value",
				message: "Select an exact documents[].relative_path from this decoded report."
			}]));
			const inDocument = (candidates) => document === undefined ? candidates : candidates.filter((row) => row.evidence.some((evidence) => evidence.artifact_path === document));
			const rows = view.collection === "documents" ? report.documents : view.collection === "coverage" ? graph.coverage : view.collection === "nodes" ? inDocument(graph.nodes) : inDocument(graph.edges);
			const items = rows.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "interface-builder",
				view,
				items,
				...shared,
				source_truncated: graph.truncated,
				coverage: pageViewCoverage(view.offset, items.length, rows.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/qlogCaptureView.js
var traceSchema, streamSchema, qlogViewContextSchema, qlogSummarySchema, pageRequestShape, traceSelectorShape, streamSelectorShape, qlogViewRequestSchema, traceSummarySchema, streamSummarySchema, qlogViewPageSchema, summarizeQlogCapture, summarizeTrace, summarizeStream, projectQlogCapturePage;
function init_qlogCaptureView() {
	return (init_qlogCaptureView = __esmMin((() => {
		init_qlogCapture();
		init_result();
		init_analysisViewErrors();
		init_analysisViewCoverage();
		traceSchema = qlogCaptureFactsSchema.shape.traces.element;
		streamSchema = traceSchema.shape.streams.element;
		qlogViewContextSchema = qlogCaptureFactsSchema.omit({ traces: true });
		qlogSummarySchema = qlogViewContextSchema.extend({
			trace_count: z.number().int().nonnegative(),
			retained_stream_count: z.number().int().nonnegative(),
			loss_declaration_count: z.number().int().nonnegative(),
			incomplete_fact_record_count: z.number().int().nonnegative()
		});
		pageRequestShape = {
			kind: z.literal("qlog"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		traceSelectorShape = { trace_index: z.number().int().nonnegative() };
		streamSelectorShape = {
			...traceSelectorShape,
			stream_id: streamSchema.shape.stream_id,
			direction: streamSchema.shape.direction
		};
		qlogViewRequestSchema = z.discriminatedUnion("facet", [
			z.strictObject({
				...pageRequestShape,
				facet: z.literal("traces")
			}),
			z.strictObject({
				...pageRequestShape,
				...traceSelectorShape,
				facet: z.literal("streams")
			}),
			z.strictObject({
				...pageRequestShape,
				...traceSelectorShape,
				facet: z.literal("loss-declarations")
			}),
			z.strictObject({
				...pageRequestShape,
				...traceSelectorShape,
				facet: z.literal("incomplete-records")
			}),
			z.strictObject({
				...pageRequestShape,
				...streamSelectorShape,
				facet: z.literal("contributions")
			}),
			z.strictObject({
				...pageRequestShape,
				...streamSelectorShape,
				facet: z.literal("ranges")
			}),
			z.strictObject({
				...pageRequestShape,
				...streamSelectorShape,
				facet: z.literal("final-sizes")
			})
		]);
		traceSummarySchema = traceSchema.omit({
			streams: true,
			loss_declarations: true,
			incomplete_fact_records: true
		}).extend({
			stream_count: z.number().int().nonnegative(),
			loss_declaration_count: z.number().int().nonnegative(),
			incomplete_fact_record_count: z.number().int().nonnegative()
		});
		streamSummarySchema = streamSchema.omit({
			contributions: true,
			covered_ranges: true,
			reported_final_sizes: true
		}).extend({
			contribution_count: z.number().int().nonnegative(),
			covered_range_count: z.number().int().nonnegative(),
			reported_final_size_count: z.number().int().nonnegative()
		});
		qlogViewPageSchema = z.discriminatedUnion("facet", [
			z.strictObject({
				facet: z.literal("traces"),
				items: z.array(traceSummarySchema)
			}),
			z.strictObject({
				facet: z.literal("streams"),
				items: z.array(streamSummarySchema)
			}),
			z.strictObject({
				facet: z.literal("loss-declarations"),
				items: traceSchema.shape.loss_declarations
			}),
			z.strictObject({
				facet: z.literal("incomplete-records"),
				items: traceSchema.shape.incomplete_fact_records
			}),
			z.strictObject({
				facet: z.literal("contributions"),
				items: streamSchema.shape.contributions
			}),
			z.strictObject({
				facet: z.literal("ranges"),
				items: streamSchema.shape.covered_ranges
			}),
			z.strictObject({
				facet: z.literal("final-sizes"),
				items: streamSchema.shape.reported_final_sizes
			})
		]);
		summarizeQlogCapture = (qlog) => {
			const { traces, ...context } = qlog;
			return {
				...context,
				trace_count: traces.length,
				retained_stream_count: traces.reduce((sum, trace) => sum + trace.streams.length, 0),
				loss_declaration_count: traces.reduce((sum, trace) => sum + trace.loss_declarations.length, 0),
				incomplete_fact_record_count: traces.reduce((sum, trace) => sum + trace.incomplete_fact_records.length, 0)
			};
		};
		summarizeTrace = ({ streams, loss_declarations, incomplete_fact_records, ...trace }) => ({
			...trace,
			stream_count: streams.length,
			loss_declaration_count: loss_declarations.length,
			incomplete_fact_record_count: incomplete_fact_records.length
		});
		summarizeStream = ({ contributions, covered_ranges, reported_final_sizes, ...stream }) => ({
			...stream,
			contribution_count: contributions.length,
			covered_range_count: covered_ranges.length,
			reported_final_size_count: reported_final_sizes.length
		});
		projectQlogCapturePage = (qlog, view) => {
			const invalid = (field, message) => err(analysisViewInputError([{
				path: ["view", field],
				reason: "invalid_value",
				message
			}]));
			const slice = (items) => items.slice(view.offset, view.offset + view.limit);
			let page;
			let total;
			if (view.facet === "traces") {
				total = qlog.traces.length;
				page = {
					facet: "traces",
					items: slice(qlog.traces).map(summarizeTrace)
				};
			} else {
				const matches = qlog.traces.filter((trace) => trace.trace_index === view.trace_index);
				if (matches.length !== 1) return invalid("trace_index", "Select one unambiguous retained trace index.");
				const trace = matches[0];
				if (view.facet === "streams") {
					total = trace.streams.length;
					page = {
						facet: "streams",
						items: slice(trace.streams).map(summarizeStream)
					};
				} else if (view.facet === "loss-declarations") {
					total = trace.loss_declarations.length;
					page = {
						facet: view.facet,
						items: slice(trace.loss_declarations)
					};
				} else if (view.facet === "incomplete-records") {
					total = trace.incomplete_fact_records.length;
					page = {
						facet: view.facet,
						items: slice(trace.incomplete_fact_records)
					};
				} else {
					const matches = trace.streams.filter((stream) => stream.stream_id === view.stream_id && stream.direction === view.direction);
					if (matches.length !== 1) return invalid("stream_id", "Select one unambiguous retained stream ID and direction within the trace.");
					const stream = matches[0];
					if (view.facet === "contributions") {
						total = stream.contributions.length;
						page = {
							facet: view.facet,
							items: slice(stream.contributions)
						};
					} else if (view.facet === "ranges") {
						total = stream.covered_ranges.length;
						page = {
							facet: view.facet,
							items: slice(stream.covered_ranges)
						};
					} else {
						total = stream.reported_final_sizes.length;
						page = {
							facet: view.facet,
							items: slice(stream.reported_final_sizes)
						};
					}
				}
			}
			const { traces: _traces, ...context } = qlog;
			return ok({
				context,
				page,
				coverage: pageViewCoverage(view.offset, page.items.length, total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/webNetworkCaptureView.js
var captureViewRequestSchema, protobufSummarySchema, summarizeProtobuf, previewSchema, captureViewItemsSchema, captureSummarySchema, object, HEADLINE_FIELDS, MITMPROXY_HEADLINE_FIELDS, MITMPROXY_PATH_MAX_LENGTH, integerIn, hasControl, LONE_SURROGATE, hostLike, MITMPROXY_INTEGER_FIELDS, describesText, representationMatches, headlineShape, ancestorsOf, addAncestors, groupByPointer, indexFacets, usableScalar, textualFlowType, mitmproxyHeadline, selectHeadlines, preview, parseCaptureParent, projectWebNetworkCaptureView;
function init_webNetworkCaptureView() {
	return (init_webNetworkCaptureView = __esmMin((() => {
		init_protobufCaptureView();
		init_analysisViewErrors();
		init_inputIssueProjection();
		init_result();
		init_webNetworkCapture();
		init_analysisViewCoverage();
		init_qlogCaptureView();
		captureViewRequestSchema = z.strictObject({
			kind: z.literal("capture"),
			detail: z.enum(["preview", "complete"]).default("preview"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		protobufSummarySchema = z.strictObject({
			bodies: z.number().int().nonnegative(),
			frames: z.number().int().nonnegative(),
			fields: z.number().int().nonnegative(),
			incomplete_bodies: z.number().int().nonnegative()
		});
		summarizeProtobuf = (records) => {
			const counts = {
				bodies: 0,
				frames: 0,
				fields: 0,
				incomplete_bodies: 0
			};
			for (const record of records) for (const body of record.protobuf ?? []) {
				counts.bodies++;
				counts.frames += body.frames.length;
				counts.fields += body.fields.length;
				counts.incomplete_bodies += Number(body.status !== "complete");
			}
			return counts.bodies === 0 ? undefined : counts;
		};
		previewSchema = webNetworkCaptureRecordSchema.omit({ protobuf: true }).extend({
			binary_fields: z.array(webNetworkCaptureBinaryDescriptorSchema),
			protobuf_summary: protobufSummarySchema.exactOptional()
		});
		captureViewItemsSchema = z.array(z.union([webNetworkCaptureRecordSchema, previewSchema]));
		captureSummarySchema = z.strictObject({
			protobuf_coverage: protobufCaptureCoverageSchema.exactOptional(),
			artifact: webNetworkCaptureArtifactSchema,
			decoder: webNetworkCaptureDecoderSchema,
			format: z.enum(WEB_NETWORK_CAPTURE_FORMATS),
			total_records: z.number().int().nonnegative(),
			retained_records: z.number().int().nonnegative(),
			runtime_attribution: z.literal("unknown"),
			protobuf: protobufSummarySchema.exactOptional(),
			qlog: qlogSummarySchema.optional()
		});
		object = (value) => value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
		HEADLINE_FIELDS = [
			"method",
			"url",
			"httpVersion",
			"http_version",
			"status",
			"statusText",
			"reason"
		];
		MITMPROXY_HEADLINE_FIELDS = {
			request: [
				"scheme",
				"host",
				"port",
				"authority",
				"path"
			],
			response: ["status_code"]
		};
		MITMPROXY_PATH_MAX_LENGTH = 2 * 1024;
		integerIn = (value, min, max) => typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
		hasControl = (value, includeSpace) => {
			for (let index = 0; index < value.length; index += 1) {
				const code = value.charCodeAt(index);
				if (code < 32 || code === 127 || includeSpace && code === 32) return true;
			}
			return false;
		};
		LONE_SURROGATE = /\p{Cs}/u;
		hostLike = (value, maxLength) => typeof value === "string" && value.length <= maxLength && !hasControl(value, true) && !/[@/\\]/u.test(value) && !LONE_SURROGATE.test(value);
		MITMPROXY_INTEGER_FIELDS = new Set(["port", "status_code"]);
		describesText = (descriptor, text) => {
			if (descriptor.representation !== "producer-bytes" || descriptor.state !== "retained") return false;
			const utf8 = Buffer.from(text, "utf8");
			return utf8.toString("utf8") === text && descriptor.bytes === utf8.length && descriptor.content_base64 === utf8.toString("base64") && descriptor.sha256 === createHash("sha256").update(utf8).digest("hex");
		};
		representationMatches = (field, value, sidecars, bytes) => {
			if (MITMPROXY_INTEGER_FIELDS.has(field)) return bytes.length === 0 && typeof value === "number" && sidecars.length === 1 && sidecars[0]?.producer_type === "integer" && sidecars[0].literal === String(value);
			if (sidecars.length !== 0 || bytes.length > 1) return false;
			const [descriptor] = bytes;
			return descriptor === undefined || typeof value === "string" && describesText(descriptor, value);
		};
		headlineShape = (field, value) => {
			switch (field) {
				case "scheme": return typeof value === "string" && /^[A-Za-z][A-Za-z0-9+.-]{0,31}$/u.test(value);
				case "host": return hostLike(value, 255);
				case "authority": return hostLike(value, 262);
				case "port": return integerIn(value, 0, 65535);
				case "status_code": return integerIn(value, 100, 999);
				case "path": return typeof value === "string" && value.length <= MITMPROXY_PATH_MAX_LENGTH && !hasControl(value, false) && !value.includes("@") && !LONE_SURROGATE.test(value) && (value === "*" || value.startsWith("/") && !value.startsWith("//") && !value.startsWith("/\\"));
				default: return false;
			}
		};
		ancestorsOf = (pointer) => {
			const ancestors = [];
			for (let at = pointer.indexOf("/"); at !== -1; at = pointer.indexOf("/", at + 1)) ancestors.push(pointer.slice(0, at));
			return ancestors;
		};
		addAncestors = (pointer, into) => {
			for (let at = pointer.lastIndexOf("/"); at !== -1; at = at === 0 ? -1 : pointer.lastIndexOf("/", at - 1)) {
				const ancestor = pointer.slice(0, at);
				if (into.has(ancestor)) return;
				into.add(ancestor);
			}
		};
		groupByPointer = (facets) => {
			const groups = new Map();
			for (const facet of facets) {
				const group = groups.get(facet.pointer);
				if (group === undefined) groups.set(facet.pointer, [facet]);
				else group.push(facet);
			}
			return groups;
		};
		indexFacets = (record) => {
			const containers = new Set();
			const withheld = new Set();
			const omittedNames = new Set();
			for (const { pointer } of record.numeric_literals) addAncestors(pointer, containers);
			for (const { pointer, state } of record.binary_fields) {
				addAncestors(pointer, containers);
				if (state === "redacted") withheld.add(pointer);
			}
			for (const redaction of record.redactions) {
				addAncestors(redaction.pointer, containers);
				("scope" in redaction ? omittedNames : withheld).add(redaction.pointer);
			}
			const sidecars = groupByPointer(record.numeric_literals);
			const bytes = groupByPointer(record.binary_fields);
			return {
				sidecars,
				bytes,
				scalars: new Set([...sidecars.keys(), ...bytes.keys()]),
				containers,
				withheld,
				omittedNames
			};
		};
		usableScalar = (index, pointer) => {
			const ancestors = ancestorsOf(pointer);
			return !index.omittedNames.has(pointer) && !index.containers.has(pointer) && !index.withheld.has(pointer) && !ancestors.some((ancestor) => index.withheld.has(ancestor) || index.scalars.has(ancestor));
		};
		textualFlowType = (index) => usableScalar(index, "/type") && !index.scalars.has("/type");
		mitmproxyHeadline = (index, pointer, field, value) => usableScalar(index, pointer) && headlineShape(field, value) && representationMatches(field, value, index.sidecars.get(pointer) ?? [], index.bytes.get(pointer) ?? []);
		selectHeadlines = (fields, key, facets, selectedPointers) => {
			const selected = {};
			const candidates = [...HEADLINE_FIELDS.map((field) => [field, null]), ...(facets === null ? [] : MITMPROXY_HEADLINE_FIELDS[key] ?? []).map((field) => [field, facets])];
			for (const [field, index] of candidates) {
				const value = fields[field];
				if (!Object.hasOwn(fields, field) || value === undefined || index !== null && !mitmproxyHeadline(index, `/${key}/${field}`, field, value)) continue;
				selected[field] = value;
				selectedPointers.add(`/${key}/${field}`);
			}
			return selected;
		};
		preview = (record, format) => {
			const source = object(record.reported);
			const reported = {};
			const selectedPointers = new Set();
			if (source !== null) {
				const index = format === "mitmproxy" && source.type === "http" ? indexFacets(record) : null;
				const mitmproxyFacets = index !== null && textualFlowType(index) ? index : null;
				for (const key of [
					"session_id",
					"name",
					"time",
					"startedDateTime",
					"type"
				]) if (Object.hasOwn(source, key) && source[key] !== undefined) {
					reported[key] = source[key];
					selectedPointers.add(`/${key}`);
				}
				for (const key of ["request", "response"]) {
					const value = source[key];
					if (!Object.hasOwn(source, key) || value === undefined) continue;
					const fields = object(value);
					if (fields === null) {
						reported[key] = value;
						continue;
					}
					reported[key] = selectHeadlines(fields, key, mitmproxyFacets, selectedPointers);
				}
			}
			const { protobuf: _protobuf, ...sourceRecord } = record;
			const protobufSummary = summarizeProtobuf([record]);
			return {
				...sourceRecord,
				...protobufSummary === undefined ? {} : { protobuf_summary: protobufSummary },
				reported: source === null ? record.reported : reported,
				binary_fields: record.binary_fields.map(({ content_base64: _content, ...field }) => field),
				numeric_literals: source === null ? record.numeric_literals : record.numeric_literals.filter(({ pointer }) => selectedPointers.has(pointer))
			};
		};
		parseCaptureParent = (parent) => {
			const parsed = safeParseOwnedWebNetworkCapture(parent.normalizedResult);
			if (!parsed.success) return err(analysisInputErrorFromIssues("inspect_analysis_view", parsed.error.issues.map((issue) => ({
				...issue,
				path: [
					"source",
					"normalized_result",
					...issue.path
				]
			})), { source: { normalized_result: parent.normalizedResult } }, { cause: parsed.error }));
			const report = parsed.data;
			if (report.artifact.sha256 !== null && (parent.subject == null || parent.subject.local_path !== report.artifact.path || parent.subject.digest.sha256 !== report.artifact.sha256)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Capture parent subject must identify the report's exact path and SHA-256."
			}]));
			return ok(report);
		};
		projectWebNetworkCaptureView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "capture" && view.kind !== "protobuf" && view.kind !== "qlog") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Historical captures support summary, capture record pages, qlog fact pages and admitted api-surface, environment-manifest or environment-state views."
			}]));
			const parsed = parseCaptureParent(parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_web_network_capture",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: [...new Set([
					...parent.limitations,
					...report.limitations,
					"Capture record pages cover the records selected into the parent Evidence, in that selected order; total_records counts the original decoded capture."
				])],
				unknowns: ["Historical records do not establish live runtime attribution or deployment authenticity.", ...report.artifact.sha256 === null ? ["The explicitly excluded artifact digest remains unknown."] : []]
			};
			if (view.kind === "protobuf") return ok({
				...shared,
				...projectProtobufCapturePage(report, view),
				unknowns: [...shared.unknowns, "Decoding covers selected retained bodies only. Exhausting wire fields does not establish schema completeness or business meaning; compressed bodies and unsupported schema facets remain unknown."]
			});
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: {
					artifact: report.artifact,
					decoder: report.decoder,
					format: report.format,
					total_records: report.total_records,
					retained_records: report.records.length,
					runtime_attribution: report.runtime_attribution,
					...report.protobuf_coverage === undefined ? {} : { protobuf_coverage: report.protobuf_coverage },
					...summarizeProtobuf(report.records) === undefined ? {} : { protobuf: summarizeProtobuf(report.records) },
					...report.format === "qlog" ? { qlog: summarizeQlogCapture(report.qlog) } : {}
				},
				coverage: completeWithinViewCoverage(report.records.length, report.records.length)
			});
			if (view.kind === "qlog") {
				if (report.format !== "qlog") return err(analysisViewInputError([{
					path: ["view", "kind"],
					reason: "invalid_value",
					message: "Qlog fact views require retained qlog Evidence."
				}]));
				const projected = projectQlogCapturePage(report.qlog, view);
				return projected.ok ? ok({
					kind: "qlog",
					view,
					...shared,
					...projected.value,
					limitations: [...shared.limitations, "Qlog fact pages retain all-recorded-events-before-selection scope. Exhausting a page does not establish network completeness, body recovery, retransmission or actual loss."]
				}) : projected;
			}
			const records = report.records.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "capture",
				view,
				...shared,
				items: captureViewItemsSchema.parse(view.detail === "complete" ? records : records.map((record) => preview(record, report.format))),
				coverage: pageViewCoverage(view.offset, records.length, report.records.length),
				limitations: [...shared.limitations, ...view.detail === "preview" ? ["Preview selects recorded headline fields and byte descriptors; headers, XML, bodies, message data and other fields remain in complete record pages. Missing preview fields do not establish their absence from the producer record."] : []]
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentManifestRules.js
var TEMPLATE_RULES, OPAQUE_TOKEN, VERSION_TOKEN, STOP_WORDS, DROPPED_NAME_LITERALS, TOOL_NAME_LIMIT, SIBLING_VARIANCE_SEGMENT_LIMIT, BASE_RULES, OPT_IN_RULES, param, partKey, withParts, earliest, mergeGroups, rebucket, templateAfterUidLiteral, templateOpaqueTokens, literalAt, identifierLikeSiblings, optInParamAt, mergeLiteralSiblings, mergeSiblings, mergeSiblingVariance, SIBLING_PAIR_MINIMUM, pairCandidate, mergePairBucket, mergeSiblingPairs, applyTemplateRules, sanitizeToken, singular, paramBaseName, parameterNames, pathTemplate, toolNameRegistry, toolName, compareTools;
function init_environmentManifestRules() {
	return (init_environmentManifestRules = __esmMin((() => {
		init_unicodeCodePointOrder();
		init_webNetworkRouteTemplates();
		TEMPLATE_RULES = [
			"after-uid-literal",
			"opaque-token",
			"sibling-variance",
			"sibling-pair-variance"
		];
		OPAQUE_TOKEN = /^(?=.*\d)(?=.*[a-z])[a-z0-9]{12,}$/u;
		VERSION_TOKEN = /^v\d/u;
		STOP_WORDS = new Set([
			"search",
			"settings",
			"errors",
			"list",
			"members",
			"versions",
			"health",
			"merged",
			"usage",
			"checks",
			"dto",
			"markdown"
		]);
		DROPPED_NAME_LITERALS = new Set([
			"api",
			"apis",
			"namespaces",
			"default"
		]);
		TOOL_NAME_LIMIT = 60;
		SIBLING_VARIANCE_SEGMENT_LIMIT = 32;
		BASE_RULES = new Set(ROUTE_RULES);
		OPT_IN_RULES = new Set(TEMPLATE_RULES);
		param = (rule, values) => ({
			kind: "param",
			rule,
			values: new Set(values)
		});
		partKey = (part) => part.kind === "literal" ? part.value : ["param", part.rule];
		withParts = (group, parts) => ({
			...group,
			parts
		});
		earliest = (groups) => groups.reduce((best, group) => (group.positions[0] ?? Infinity) < (best.positions[0] ?? Infinity) ? group : best);
		mergeGroups = (groups, shape = earliest(groups)) => {
			if (groups.length === 1) return groups[0];
			const primary = earliest(groups);
			return {
				method: primary.method,
				origin: primary.origin,
				api_surface_template: primary.api_surface_template,
				parts: shape.parts.map((part, index) => part.kind === "literal" ? part : {
					...part,
					values: new Set(groups.flatMap((group) => {
						const sibling = group.parts[index];
						if (sibling === undefined) return [];
						return sibling.kind === "param" ? [...sibling.values] : [sibling.value];
					}))
				}),
				positions: groups.flatMap((group) => group.positions).sort((left, right) => left - right),
				statuses: new Set(groups.flatMap((group) => [...group.statuses])),
				contentTypes: new Set(groups.flatMap((group) => [...group.contentTypes])),
				queryNames: new Set(groups.flatMap((group) => [...group.queryNames])),
				bodyShape: primary.bodyShape
			};
		};
		rebucket = (groups) => {
			const buckets = new Map();
			for (const group of groups) {
				const key = compositeKey([
					group.method,
					group.origin,
					...group.parts.map(partKey)
				]);
				const bucket = buckets.get(key);
				if (bucket === undefined) buckets.set(key, [group]);
				else bucket.push(group);
			}
			return [...buckets.values()].map((bucket) => mergeGroups(bucket));
		};
		templateAfterUidLiteral = (parts) => parts.map((part, index) => {
			const previous = parts[index - 1];
			return part.kind === "literal" && previous?.kind === "literal" && previous.value === "uid" && !STOP_WORDS.has(part.value) ? param("after-uid-literal", [part.value]) : part;
		});
		templateOpaqueTokens = (parts) => parts.map((part) => part.kind === "literal" && OPAQUE_TOKEN.test(part.value) && !VERSION_TOKEN.test(part.value) ? param("opaque-token", [part.value]) : part);
		literalAt = (group, position) => {
			const part = group.parts[position];
			return part?.kind === "literal" ? part.value : "";
		};
		identifierLikeSiblings = (literal, position) => {
			const eligible = new Set();
			const previous = literal[0]?.parts[position - 1];
			const plural = previous?.kind === "literal" && previous.value.endsWith("s");
			const hyphenated = [];
			for (const group of literal) {
				const value = literalAt(group, position);
				if (STOP_WORDS.has(value)) continue;
				if (/[\d:]/u.test(value)) eligible.add(group);
				if (plural && value.includes("-")) hyphenated.push(group);
			}
			if (hyphenated.length >= 3) for (const group of hyphenated) eligible.add(group);
			return eligible;
		};
		optInParamAt = (group, position) => {
			const part = group.parts[position];
			return part?.kind === "param" && OPT_IN_RULES.has(part.rule);
		};
		mergeLiteralSiblings = (literal, position) => {
			const eligible = identifierLikeSiblings(literal, position);
			if (eligible.size < 2) return [...literal];
			const groups = [...eligible];
			const first = earliest(groups);
			const shape = withParts(first, first.parts.map((part, index) => index === position ? param("sibling-variance", [literalAt(first, position)]) : part));
			return [mergeGroups(groups.map((group) => group === first ? shape : group), shape), ...literal.filter((group) => !eligible.has(group))];
		};
		mergeSiblings = (bucket, position) => {
			if (bucket.length < 2) return [...bucket];
			const templated = bucket.filter((group) => group.parts[position]?.kind === "param");
			const literal = bucket.filter((group) => group.parts[position]?.kind === "literal");
			const targets = templated.filter((group) => optInParamAt(group, position));
			if (targets.length === 0) return [...templated, ...mergeLiteralSiblings(literal, position)];
			const target = earliest(targets);
			const foldable = new Set(literal.filter((group) => !STOP_WORDS.has(literalAt(group, position))));
			return [
				mergeGroups([target, ...foldable], target),
				...templated.filter((group) => group !== target),
				...literal.filter((group) => !foldable.has(group))
			];
		};
		mergeSiblingVariance = (groups) => {
			const beyondLimit = groups.filter((group) => group.parts.length > 32);
			let current = groups.filter((group) => group.parts.length <= 32);
			const longest = Math.max(0, ...current.map((group) => group.parts.length));
			for (let position = 2; position < longest; position += 1) {
				const buckets = new Map();
				const output = [];
				for (const group of current) {
					if (position >= group.parts.length) {
						output.push(group);
						continue;
					}
					const key = compositeKey([
						group.method,
						group.origin,
						group.parts.length,
						...group.parts.map((part, index) => index === position ? null : partKey(part))
					]);
					const bucket = buckets.get(key);
					if (bucket === undefined) buckets.set(key, [group]);
					else bucket.push(group);
				}
				for (const bucket of buckets.values()) output.push(...mergeSiblings(bucket, position));
				current = output;
			}
			return [...current, ...beyondLimit];
		};
		SIBLING_PAIR_MINIMUM = 3;
		pairCandidate = (group, position) => {
			const previous = group.parts[position - 1];
			const first = group.parts[position];
			const second = group.parts[position + 1];
			return previous?.kind === "literal" && previous.value.endsWith("s") && !STOP_WORDS.has(previous.value) && first?.kind === "literal" && second?.kind === "literal" && group.parts[position + 2]?.kind === "literal" && [first.value, second.value].every((value) => !STOP_WORDS.has(value) && !VERSION_TOKEN.test(value));
		};
		mergePairBucket = (bucket, position) => {
			const pairs = new Set(bucket.map((group) => compositeKey([literalAt(group, position), literalAt(group, position + 1)])));
			const firsts = new Set(bucket.map((group) => literalAt(group, position)));
			const seconds = new Set(bucket.map((group) => literalAt(group, position + 1)));
			if (pairs.size < 3 || firsts.size < 2 || seconds.size < 2) return [...bucket];
			const first = earliest(bucket);
			const shape = withParts(first, first.parts.map((part, index) => index === position || index === position + 1 ? {
				...param("sibling-pair-variance", [literalAt(first, index)]),
				pairRole: index === position ? "namespace" : "name"
			} : part));
			return [mergeGroups(bucket.map((group) => group === first ? shape : group), shape)];
		};
		mergeSiblingPairs = (groups) => {
			const beyondLimit = groups.filter((group) => group.parts.length > 32);
			let current = groups.filter((group) => group.parts.length <= 32);
			const longest = Math.max(0, ...current.map((group) => group.parts.length));
			for (let position = 2; position + 1 < longest; position += 1) {
				const buckets = new Map();
				const output = [];
				for (const group of current) {
					if (!pairCandidate(group, position)) {
						output.push(group);
						continue;
					}
					const key = compositeKey([
						group.method,
						group.origin,
						group.parts.length,
						...group.parts.map((part, index) => index === position || index === position + 1 ? null : partKey(part))
					]);
					const bucket = buckets.get(key);
					if (bucket === undefined) buckets.set(key, [group]);
					else bucket.push(group);
				}
				for (const bucket of buckets.values()) output.push(...mergePairBucket(bucket, position));
				current = output;
			}
			return [...current, ...beyondLimit];
		};
		applyTemplateRules = (groups, rules) => {
			let current = [...groups];
			if (rules.has("after-uid-literal")) current = current.map((group) => withParts(group, templateAfterUidLiteral(group.parts)));
			if (rules.has("opaque-token")) current = current.map((group) => withParts(group, templateOpaqueTokens(group.parts)));
			current = rebucket(current);
			if (rules.has("sibling-pair-variance")) current = mergeSiblingPairs(current);
			if (rules.has("sibling-variance")) current = mergeSiblingVariance(current);
			return current;
		};
		sanitizeToken = (text) => text.toLowerCase().replaceAll(/[^a-z0-9_]+/gu, "_").replaceAll(/_+/gu, "_").replace(/^_/u, "").replace(/_$/u, "");
		singular = (word) => {
			if (word.endsWith("ies") && word.length > 3) return `${word.slice(0, -3)}y`;
			if (word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
			return word;
		};
		paramBaseName = (parts, index) => {
			const part = parts[index];
			if (part?.kind !== "param") return "";
			switch (part.rule) {
				case "numeric": return "id";
				case "uuid": return "uuid";
				case "hex": return "hash";
				case "iso-date": return "date";
				case "after-uid-literal":
				case "opaque-token": return "uid";
				case "sibling-variance": {
					const previous = parts[index - 1];
					const stem = previous?.kind === "literal" ? sanitizeToken(singular(previous.value)) : "";
					return stem.length > 0 ? `${stem}_id` : "id";
				}
				case "sibling-pair-variance": {
					const role = part.pairRole ?? "namespace";
					const plural = parts[role === "name" ? index - 2 : index - 1];
					const stem = plural?.kind === "literal" ? sanitizeToken(singular(plural.value)) : "";
					return stem.length > 0 ? `${stem}_${role}` : role;
				}
			}
		};
		parameterNames = (parts) => {
			const used = new Map();
			return parts.flatMap((part, index) => {
				if (part.kind !== "param") return [];
				const base = paramBaseName(parts, index);
				const count = used.get(base) ?? 0;
				used.set(base, count + 1);
				return [count === 0 ? base : `${base}_${String(count + 1)}`];
			});
		};
		pathTemplate = (parts, names) => {
			let next = 0;
			return `/${parts.map((part) => {
				if (part.kind === "literal") return part.value;
				const name = names[next] ?? "";
				next += 1;
				return BASE_RULES.has(part.rule) ? `{${part.rule}}` : `{${name}}`;
			}).join("/")}`;
		};
		toolNameRegistry = () => ({
			used: new Set(),
			nextSuffix: new Map()
		});
		toolName = (method, parts, names, registry) => {
			const literals = parts.flatMap((part, index) => {
				if (part.kind !== "literal") return [];
				const value = part.value;
				if (value.length === 0 || DROPPED_NAME_LITERALS.has(value) || VERSION_TOKEN.test(value) || value === "uid" && parts[index + 1]?.kind === "param") return [];
				return [value.split(".")[0] ?? ""];
			});
			const base = sanitizeToken([
				method.toLowerCase(),
				...literals,
				...names.length > 0 ? ["by", ...names] : []
			].join("_")) || "tool";
			const truncate = (text, limit) => text.slice(0, limit).replace(/_+$/u, "");
			let candidate = truncate(base, TOOL_NAME_LIMIT);
			if (registry.used.has(candidate)) {
				let suffix = 2;
				for (;;) {
					const tail = `_${String(suffix)}`;
					const prefix = truncate(base, TOOL_NAME_LIMIT - tail.length);
					const namespace = compositeKey([prefix, tail.length]);
					const next = registry.nextSuffix.get(namespace) ?? suffix;
					if (next > suffix) {
						suffix = next;
						continue;
					}
					candidate = `${prefix}${tail}`;
					registry.nextSuffix.set(namespace, suffix + 1);
					if (!registry.used.has(candidate)) break;
					suffix += 1;
				}
			}
			registry.used.add(candidate);
			return candidate;
		};
		compareTools = (left, right) => compareUnicodeCodePoints(left.template, right.template) || compareUnicodeCodePoints(left.method, right.method);
	})))();
}

//#endregion
//#region dist/domain/analysisView/EnvironmentManifestAccumulator.js
var postDataSchema, JSON_LIKE_TEXT, ASSET_ESSENCES, ASSET_PREFIXES, ASSET_PATH, WRITE_METHODS$1, KEY_OVERHEAD_CHARS, UNKNOWNS$1, isJson, isJsonLike, isApiPath, isAsset, environmentName, routeParts, hasParam, EnvironmentManifestAccumulator;
function init_EnvironmentManifestAccumulator() {
	return (init_EnvironmentManifestAccumulator = __esmMin((() => {
		init_jsonShape();
		init_result();
		init_unicodeCodePointOrder();
		init_webNetworkCapture();
		init_analysisViewCoverage();
		init_WebNetworkProjectionAccumulator();
		init_environmentManifestRules();
		init_webNetworkRouteTemplates();
		postDataSchema = z.object({ request: z.object({ postData: z.object({
			mimeType: z.unknown().optional(),
			text: z.unknown().optional()
		}).nullable().optional() }) });
		JSON_LIKE_TEXT = new Set(["text/plain", "text/markdown"]);
		ASSET_ESSENCES = new Set([
			"text/html",
			"application/xhtml+xml",
			"text/css",
			"text/javascript",
			"application/javascript",
			"application/x-javascript",
			"application/wasm"
		]);
		ASSET_PREFIXES = [
			"image/",
			"font/",
			"audio/",
			"video/"
		];
		ASSET_PATH = /\.(?:m?js|css|map|html?|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf)$/iu;
		WRITE_METHODS$1 = new Set([
			"POST",
			"PUT",
			"PATCH"
		]);
		KEY_OVERHEAD_CHARS = 32;
		UNKNOWNS$1 = [
			{
				kind: "authorization-model",
				statement: "Authorization headers and cookies are structurally excluded from captures; the manifest states no authorization model."
			},
			{
				kind: "response-semantics",
				statement: "Recorded statuses and bodies are retained only as pointers to parent records; the manifest states no response semantics."
			},
			{
				kind: "state-transition",
				statement: "Recorded exchanges are independent observations; the manifest states no ordering, side effects or state transitions between tools."
			}
		];
		isJson = (essence) => essence === "application/json" || essence !== null && essence.startsWith("application/") && essence.endsWith("+json");
		isJsonLike = (essence) => isJson(essence) || essence !== null && JSON_LIKE_TEXT.has(essence);
		isApiPath = (path) => path.startsWith("/api/") || path.startsWith("/apis/");
		isAsset = (group) => [...group.contentTypes].some((essence) => ASSET_ESSENCES.has(essence) || ASSET_PREFIXES.some((prefix) => essence.startsWith(prefix))) || ASSET_PATH.test(group.api_surface_template);
		environmentName = (origin) => new URL(origin).host.toLowerCase().replaceAll(/[^a-z0-9]+/gu, "-").replace(/^-/u, "").replace(/-$/u, "");
		routeParts = (route) => {
			const byIndex = new Map(route.segments.map((segment) => [segment.segment_index, segment]));
			return route.template.slice(1).split("/").map((text, index) => {
				const segment = byIndex.get(index);
				return segment === undefined ? {
					kind: "literal",
					value: text
				} : {
					kind: "param",
					rule: segment.rule,
					values: new Set([segment.value])
				};
			});
		};
		hasParam = (parts) => parts.some((part) => part.kind === "param");
		EnvironmentManifestAccumulator = class extends WebNetworkProjectionAccumulator {
			includeQueryParameterNames;
			#groups = new Map();
			#records = [];
			#origins = new Map();
			#rules;
			#unrepresented = 0;
			#unrepresentableBodyKey = false;
			constructor(maximumBytes = WEB_NETWORK_CAPTURE_LIMITS.outputBytes, includeQueryParameterNames = true, rules = [], budgetSubject = "Environment-manifest") {
				super(maximumBytes, budgetSubject);
				this.includeQueryParameterNames = includeQueryParameterNames;
				this.#rules = new Set(rules);
			}
			/** Whether the finished projection publishes body shapes, and so states their limitation. */
			get reportsBodyShapes() {
				return true;
			}
			add(record) {
				const limitations = this.addLimitations(record.limitations);
				if (!limitations.ok) return limitations;
				try {
					const line = readRecordedRequestLine(record.reported, this.includeQueryParameterNames, this.scratch);
					if (line === null) return this.overBudget();
					if (line.kind === "excluded") {
						this.#unrepresented += 1;
						return ok(undefined);
					}
					const route = scanRouteTemplate(line.path, this.scratch);
					if (route === null) return this.overBudget();
					const queryNames = readQueryParameterNames(line.query, this.scratch);
					if (queryNames === null) return this.overBudget();
					if (!this.scratch(textBytes(line.method.length + line.origin.length + route.template.length + route.rules.length + KEY_OVERHEAD_CHARS))) return this.overBudget();
					const key = compositeKey([
						line.method,
						line.origin,
						route.template,
						route.rules
					]);
					const group = this.#groups.get(key);
					const bodyShape = group === undefined && WRITE_METHODS$1.has(line.method) ? this.#bodyShape(record.reported) : ok(null);
					if (!bodyShape.ok) return bodyShape;
					return this.#append(record.ordinal, line, route, queryNames, {
						key,
						group
					}, bodyShape.value);
				} finally {
					this.releaseTemporary();
				}
			}
			/** Read the top-level key types of the group's first recorded JSON-typed request body; nested values are never walked. */
			#bodyShape(reported) {
				const parsed = postDataSchema.safeParse(reported);
				const body = parsed.success ? parsed.data.request.postData : undefined;
				if (body === undefined || body === null || typeof body.text !== "string" || typeof body.mimeType !== "string") return ok(null);
				if (!this.scratch(textBytes(body.mimeType.length))) return this.overBudget();
				if (!isJson(mediaTypeEssence(body.mimeType))) return ok(null);
				if (!this.scratch(512 + textBytes(body.text.length) * 3)) return this.overBudget();
				const root = parseJsonObject(body.text);
				if (root === null) return ok(null);
				const entries = [];
				for (const [name, value] of Object.entries(root)) {
					if (name === "__proto__") this.#unrepresentableBodyKey = true;
					else entries.push([name, jsonValueType(value)]);
				}
				return ok({
					type: "object",
					properties: Object.fromEntries(entries)
				});
			}
			#append(ordinal, line, route, queryNames, bucket, bodyShape) {
				const mime = mediaTypeEssence(line.rawMime);
				let group = bucket.group;
				let bytes = 128 * 2 + textBytes(line.path.length) + textBytes(line.method.length);
				const origin = this.#origins.get(line.origin);
				if (origin === undefined) bytes += 128 * 2 + textBytes(line.origin.length);
				if (group === undefined) {
					bytes += GROUP_BYTES + textBytes(bucket.key.length) + textBytes(line.method.length) + textBytes(line.origin.length) + textBytes(route.template.length) * 2 + textBytes(route.rules.length);
					bytes += 128 * 4 * routePartCount(route.template);
					for (const segment of route.segments) bytes += SEGMENT_BYTES + 128 + textBytes(segment.value.length);
					if (bodyShape !== null) for (const name of Object.keys(bodyShape.properties)) bytes += 128 + textBytes(name.length);
				} else {
					for (const segment of route.segments) {
						const part = group.parts[segment.segment_index];
						if (part?.kind === "param" && !part.values.has(segment.value)) bytes += 128 + textBytes(segment.value.length);
					}
				}
				if (line.status !== null && !group?.statuses.has(line.status)) bytes += 128;
				if (mime !== null && !group?.contentTypes.has(mime)) bytes += 128 + textBytes(mime.length);
				for (const name of queryNames ?? []) if (!group?.queryNames.has(name)) bytes += 128 + textBytes(name.length);
				if (!this.retain(bytes)) return this.overBudget();
				const position = this.#records.length;
				this.#records.push({
					ordinal,
					method: line.method,
					path: line.path,
					status: line.status,
					contentType: mime
				});
				const jsonLike = isJsonLike(mime);
				const stats = origin ?? {
					records: 0,
					jsonLike: 0
				};
				stats.records += 1;
				if (jsonLike) stats.jsonLike += 1;
				this.#origins.set(line.origin, stats);
				if (group === undefined) {
					group = {
						method: line.method,
						origin: line.origin,
						api_surface_template: route.template,
						parts: routeParts(route),
						positions: [],
						statuses: new Set(),
						contentTypes: new Set(),
						queryNames: new Set(),
						bodyShape,
						apiPath: isApiPath(route.template),
						jsonLike: false
					};
					this.#groups.set(bucket.key, group);
				} else {
					for (const segment of route.segments) {
						const part = group.parts[segment.segment_index];
						if (part?.kind === "param") part.values.add(segment.value);
					}
				}
				group.positions.push(position);
				group.jsonLike ||= jsonLike;
				if (line.status !== null) group.statuses.add(line.status);
				if (mime !== null) group.contentTypes.add(mime);
				for (const name of queryNames ?? []) group.queryNames.add(name);
				return ok(undefined);
			}
			/** The origin with the most JSON-like records, then most records, then lowest code points. */
			#primaryOrigin() {
				let best = null;
				for (const [origin, stats] of this.#origins) {
					if (best === null || stats.jsonLike > best.jsonLike || stats.jsonLike === best.jsonLike && (stats.records > best.records || stats.records === best.records && compareUnicodeCodePoints(origin, best.origin) < 0)) best = {
						origin,
						...stats
					};
				}
				return best?.origin ?? null;
			}
			#tools(groups) {
				const registry = toolNameRegistry();
				return applyTemplateRules(groups, this.#rules).map((group) => {
					const names = parameterNames(group.parts);
					return {
						group,
						names,
						template: pathTemplate(group.parts, names)
					};
				}).sort((left, right) => compareTools({
					template: left.template,
					method: left.group.method
				}, {
					template: right.template,
					method: right.group.method
				})).map(({ group, names, template }) => {
					let next = 0;
					return {
						name: toolName(group.method, group.parts, names, registry),
						method: group.method,
						path_template: template,
						api_surface_template: group.api_surface_template,
						params: group.parts.flatMap((part, index) => {
							if (part.kind !== "param") return [];
							const name = names[next] ?? "";
							next += 1;
							return [{
								index,
								name,
								rule: part.rule,
								basis: "inferred",
								observed_values: [...part.values].sort(compareUnicodeCodePoints)
							}];
						}),
						query_parameter_names: [...group.queryNames].sort(compareUnicodeCodePoints),
						body_shape: group.bodyShape,
						statuses: [...group.statuses].sort((left, right) => left - right),
						content_types: [...group.contentTypes].sort(compareUnicodeCodePoints),
						record_ordinals: group.positions.map((position) => this.#records[position].ordinal)
					};
				});
			}
			/** One limitation per selected sibling rule when a route is too long for it to compare. */
			#segmentLimitLimitations(toolGroups) {
				if (!toolGroups.some((group) => group.parts.length > 32)) return [];
				return ["sibling-variance", "sibling-pair-variance"].filter((rule) => this.#rules.has(rule)).map((rule) => `Routes with more than ${String(32)} segments are not compared by ${rule}; they keep their grouped templates.`);
			}
			/** Project the complete manifest; tools, records and exclusions are sorted deterministically. */
			finish() {
				const primary = this.#primaryOrigin();
				const toolGroups = [];
				const exclusions = new Map();
				for (const group of this.#groups.values()) {
					const reason = group.origin !== primary ? "other-origin" : group.apiPath || group.jsonLike ? null : isAsset(group) ? "ui-page-or-asset" : "non-json";
					if (reason === null) {
						toolGroups.push(group);
						continue;
					}
					const exclusion = {
						method: group.method,
						origin: group.origin,
						path_template: group.api_surface_template,
						reason
					};
					const key = compositeKey(Object.values(exclusion));
					exclusions.set(key, {
						...exclusion,
						templated: (exclusions.get(key)?.templated ?? false) || hasParam(group.parts)
					});
				}
				const tools = this.#tools(toolGroups);
				const cited = [...new Set(tools.flatMap((tool) => tool.record_ordinals))];
				const positions = new Map(this.#records.map((record, position) => [record.ordinal, position]));
				const excluded = [...exclusions.values()].sort((left, right) => compareUnicodeCodePoints(left.origin, right.origin) || compareUnicodeCodePoints(left.path_template, right.path_template) || compareUnicodeCodePoints(left.method, right.method) || compareUnicodeCodePoints(left.reason, right.reason));
				const limitations = this.addLimitations([
					...this.reportsBodyShapes && tools.some((tool) => tool.body_shape !== null) ? ["Body shapes list top-level JSON key types from one recorded request each; they do not establish required fields or a complete schema."] : [],
					...this.#unrepresentableBodyKey ? ["A top-level __proto__ key in a recorded JSON body is omitted from body_shape; it cannot be an own property of the published object."] : [],
					...this.#segmentLimitLimitations(toolGroups),
					...this.#unrepresented > 0 ? [`${String(this.#unrepresented)} retained records without a usable request line are not represented in the manifest.`] : [],
					...primary === null ? ["No retained record had a parseable origin; the manifest names no primary origin."] : []
				]);
				if (!limitations.ok) return limitations;
				return ok({
					origin: primary ?? "",
					name: primary === null ? "" : environmentName(primary),
					tools,
					records: cited.sort((left, right) => positions.get(left) - positions.get(right)).map((ordinal) => {
						const record = this.#records[positions.get(ordinal)];
						return {
							ordinal: record.ordinal,
							method: record.method,
							path: record.path,
							status: record.status,
							content_type: record.contentType
						};
					}),
					excluded: excluded.map(({ templated: _templated, ...exclusion }) => exclusion),
					unknowns: UNKNOWNS$1.map((unknown) => ({ ...unknown })),
					templated_groups: tools.filter((tool) => tool.params.length > 0).length + excluded.filter((exclusion) => exclusion.templated).length,
					coverage: completeWithinViewCoverage(tools.length, tools.length),
					limitations: this.sortedLimitations()
				});
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/scenarioCaptureRecords.js
var append, indexTransactions, onlyContent, headerValue, captured, retainedBody, utf8Text, mediaType, reportedRequest, record, scenarioCaptureRecords, member, derivedTextBytes, admitScenarioCaptureParent;
function init_scenarioCaptureRecords() {
	return (init_scenarioCaptureRecords = __esmMin((() => {
		init_analysisErrorCore();
		init_browserScenarioCapture();
		init_result();
		init_analysisViewErrors();
		init_webNetworkRouteTemplates();
		append = (map, key, value) => {
			const existing = map.get(key);
			if (existing === undefined) map.set(key, [value]);
			else existing.push(value);
		};
		indexTransactions = (events) => {
			const index = {
				requests: [],
				requestCounts: new Map(),
				responses: new Map(),
				contents: new Map()
			};
			for (const [item, event] of events.entries()) {
				if (event.kind === "request") {
					index.requests.push({
						event,
						item
					});
					index.requestCounts.set(event.transaction_id, (index.requestCounts.get(event.transaction_id) ?? 0) + 1);
				} else if (event.kind === "response") append(index.responses, event.transaction_id, event);
				else if (event.kind === "network-content") append(index.contents, event.source_event_sequence, event);
			}
			return index;
		};
		onlyContent = (index, sequence) => {
			const found = sequence === undefined ? undefined : index.contents.get(sequence);
			return found?.length === 1 ? found[0] : undefined;
		};
		headerValue = (headers, name) => {
			if (headers?.state !== "captured") return undefined;
			const item = headers.items.find((candidate) => candidate.name.toLowerCase() === name);
			return item?.value ?? undefined;
		};
		captured = (content) => content?.body.state === "captured" ? content.body : undefined;
		retainedBody = (content) => {
			const body = captured(content);
			return body?.redacted === true && body.bytes === 0 ? undefined : body;
		};
		utf8Text = (body) => {
			try {
				return new TextDecoder("utf-8", {
					fatal: true,
					ignoreBOM: true
				}).decode(Buffer.from(body.content, "base64"));
			} catch {
				return undefined;
			}
		};
		mediaType = (content) => captured(content)?.media_type ?? headerValue(content?.headers, "content-type");
		reportedRequest = (request, content, purpose) => {
			const body = purpose === "manifest" ? captured(content) : undefined;
			const text = body === undefined ? undefined : utf8Text(body);
			const mimeType = mediaType(content);
			return {
				method: request.method,
				url: request.url.redacted ? null : request.url.url,
				...text === undefined || mimeType === undefined ? {} : { postData: {
					mimeType,
					text
				} }
			};
		};
		record = (ordinal, observed, index, purpose) => {
			const { item, event: request } = observed;
			const location = {
				kind: "json-pointer",
				pointer: `/events/items/${String(item)}`
			};
			const empty = {
				binary_fields: [],
				numeric_literals: [],
				redactions: [],
				limitations: []
			};
			const responses = index.responses.get(request.transaction_id) ?? [];
			const response = responses.length === 1 ? responses[0] : undefined;
			if (index.requestCounts.get(request.transaction_id) !== 1 || responses.length > 1 || (index.contents.get(request.sequence)?.length ?? 0) > 1 || response !== undefined && (index.contents.get(response.sequence)?.length ?? 0) > 1) return {
				record: {
					ordinal,
					location,
					reported: {},
					...empty
				},
				represented: false,
				body: false,
				redacted: false
			};
			const requestContent = onlyContent(index, request.sequence);
			const responseContent = onlyContent(index, response?.sequence);
			const body = retainedBody(responseContent);
			const mimeType = mediaType(responseContent) ?? "";
			return {
				record: {
					ordinal,
					location,
					reported: {
						request: reportedRequest(request, requestContent, purpose),
						...response === undefined ? {} : { response: {
							status: response.status,
							content: body === undefined ? { mimeType } : {
								mimeType,
								text: body.content,
								encoding: "base64"
							}
						} }
					},
					...empty,
					binary_fields: body === undefined ? [] : [{
						pointer: "/response/content/text",
						representation: "har-base64-content",
						state: "retained",
						bytes: body.bytes,
						sha256: body.sha256,
						content_base64: body.content
					}]
				},
				represented: !request.url.redacted,
				body: body !== undefined,
				redacted: body?.redacted === true
			};
		};
		scenarioCaptureRecords = (capture, purpose) => {
			const index = indexTransactions(capture.events.items);
			const records = [];
			let withoutBody = 0;
			let representedCount = 0;
			let redactedBodies = 0;
			for (const [ordinal, observed] of index.requests.entries()) {
				const projected = record(ordinal, observed, index, purpose);
				records.push(projected.record);
				if (!projected.represented) continue;
				representedCount += 1;
				if (!projected.body) withoutBody += 1;
				if (projected.redacted) redactedBodies += 1;
			}
			return {
				records,
				totalRecords: records.length,
				limitations: [
					"Scenario records are the capture's network transactions in request order; each record ordinal is the transaction's zero-based position.",
					...capture.events.dropped > 0 ? [`The scenario capture omitted ${String(capture.events.dropped)} events; the manifest covers only retained transactions.`] : [],
					...withoutBody > 0 ? [`${String(withoutBody)} of ${String(representedCount)} scenario transactions with a usable request line retained no response body; tools citing them replay only the recorded status and content type, either of which may be absent.`] : [],
					...redactedBodies > 0 ? [`${String(redactedBodies)} of ${String(representedCount)} scenario transactions with a usable request line retained a response body with declared secret values replaced by redaction markers; tools citing them replay the redacted bytes.`] : []
				]
			};
		};
		member = (value, key) => typeof value === "object" && value !== null && Object.hasOwn(value, key) ? value[key] : undefined;
		derivedTextBytes = (value) => {
			const items = member(member(value, "events"), "items");
			let largestBody = 0;
			let requestText = 0;
			for (const event of Array.isArray(items) ? items : []) {
				const content = member(member(event, "body"), "content");
				if (member(event, "kind") !== "network-content" || typeof content !== "string") continue;
				largestBody = Math.max(largestBody, content.length);
				if (member(event, "phase") === "request") requestText += textBytes(Math.ceil(content.length * 3 / 4));
			}
			return 64 + largestBody * 2 + requestText;
		};
		admitScenarioCaptureParent = (parent, viewKind, accumulator) => {
			const admitted = accumulator.admitCaptureClone(parent.normalizedResult);
			if (!admitted.ok) return admitted;
			const derived = accumulator.admitDerivedBytes(derivedTextBytes(parent.normalizedResult));
			if (!derived.ok) return derived;
			const parsed = browserScenarioCaptureSchema.safeParse(parent.normalizedResult);
			if (!parsed.success) return err(analysisViewInputError([{
				path: ["source"],
				reason: "invalid_value",
				message: "Parent Evidence result does not match capture_browser_scenario."
			}]));
			const content = parsed.data.scenario.network_content;
			if (viewKind === "environment-state" ? !content.response_body : !content.response_body && !content.header_values) return err(new AnalysisUnsupportedTargetError("inspect_analysis_view", parent.evidenceId, viewKind === "environment-state" ? "environment-state needs a capture_browser_scenario capture with capture.network.response_body selected." : "environment-manifest needs a capture_browser_scenario capture with capture.network.response_body or header_values selected."));
			return ok(scenarioCaptureRecords(parsed.data, "manifest"));
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentManifestView.js
var templateRulesSchema, environmentManifestViewRequestSchema, manifestRuleSchema, jsonTypeNameSchema, toolSchema, environmentManifestFields, admitCaptureParent, groupCaptureRecords, addCaptureRecords, projectEnvironmentManifestView;
function init_environmentManifestView() {
	return (init_environmentManifestView = __esmMin((() => {
		init_analysisErrorCore();
		init_canonicalOrdering();
		init_result();
		init_EnvironmentManifestAccumulator();
		init_environmentManifestRules();
		init_WebNetworkProjectionAccumulator();
		init_scenarioCaptureRecords();
		init_webNetworkRouteTemplates();
		templateRulesSchema = z.array(z.enum(TEMPLATE_RULES)).refine((rules) => new Set(rules).size === rules.length, { message: "template_rules must not repeat a rule" }).meta({ uniqueItems: true }).default([]);
		environmentManifestViewRequestSchema = z.strictObject({
			kind: z.literal("environment-manifest"),
			template_rules: templateRulesSchema.describe("Opt-in template rules applied after the four format rules, each listed at most once: after-uid-literal templates the segment following a literal uid, opaque-token templates long mixed alphanumeric segments, sibling-variance merges groups that differ in one identifier-like segment, sibling-pair-variance merges groups that differ in two adjacent literals between a plural literal and another literal when at least three distinct pairs vary in both. Literal sibling folding into existing opt-in parameters also requires sibling-variance. Merged parameters are inferences."),
			include_query_parameter_names: z.boolean().default(true).describe("Include distinct observed query parameter names per tool; names do not establish required parameters or a complete API schema.")
		});
		manifestRuleSchema = z.enum([...ROUTE_RULES, ...TEMPLATE_RULES]);
		jsonTypeNameSchema = z.enum([
			"string",
			"number",
			"boolean",
			"object",
			"array",
			"null"
		]);
		toolSchema = z.strictObject({
			name: z.string(),
			method: z.string(),
			path_template: z.string(),
			api_surface_template: z.string().describe("Four-rule template of the tool's earliest record."),
			params: z.array(z.strictObject({
				index: z.number().int().nonnegative(),
				name: z.string(),
				rule: manifestRuleSchema,
				basis: z.literal("inferred"),
				observed_values: z.array(z.string())
			})),
			query_parameter_names: z.array(z.string()),
			body_shape: z.strictObject({
				type: z.literal("object"),
				properties: z.record(z.string(), jsonTypeNameSchema)
			}).nullable(),
			statuses: z.array(z.number()),
			content_types: z.array(z.string()),
			record_ordinals: z.array(z.number().int().nonnegative())
		});
		environmentManifestFields = {
			origin: z.string().describe("Primary origin: the origin with the most JSON-like records."),
			name: z.string().describe("Kebab-case environment name derived from the primary origin host."),
			tools: z.array(toolSchema),
			records: z.array(z.strictObject({
				ordinal: z.number().int().nonnegative(),
				method: z.string(),
				path: z.string(),
				status: z.number().nullable(),
				content_type: z.string().nullable()
			})).describe("Pointers to the retained parent records cited by tools; no bodies."),
			excluded: z.array(z.strictObject({
				method: z.string(),
				origin: z.string(),
				path_template: z.string(),
				reason: z.enum([
					"other-origin",
					"ui-page-or-asset",
					"non-json"
				])
			})),
			unknowns: z.array(z.strictObject({
				kind: z.enum([
					"authorization-model",
					"response-semantics",
					"state-transition"
				]),
				statement: z.string()
			})),
			templated_groups: z.number().int().nonnegative().describe("Tools and excluded groups that carry at least one templated segment.")
		};
		admitCaptureParent = (parent, viewKind, accumulator) => {
			if (parent.operation === "capture_browser_scenario") {
				const scenario = admitScenarioCaptureParent(parent, viewKind, accumulator);
				return scenario.ok ? ok({
					operation: "capture_browser_scenario",
					records: scenario.value.records,
					total_records: scenario.value.totalRecords,
					limitations: scenario.value.limitations,
					artifact: {
						path: "",
						sha256: null
					}
				}) : scenario;
			}
			const har = admitHarCaptureParent(parent, viewKind, accumulator);
			return har.ok ? ok({
				operation: "inspect_web_network_capture",
				...har.value
			}) : har;
		};
		groupCaptureRecords = (parent, viewKind, rules, target) => {
			const admitted = admitCaptureParent(parent, viewKind, target.accumulator);
			if (!admitted.ok) return admitted;
			const added = addCaptureRecords(parent, admitted.value, rules, target);
			return added.ok ? admitted : added;
		};
		addCaptureRecords = (parent, capture, rules, target) => {
			const limitations = target.accumulator.addLimitations([
				...parent.limitations,
				...capture.limitations,
				"Tool templates, parameters and names are inferences from recorded request lines; they do not establish handler identity, URL-space schemas or causality.",
				...target.limitations,
				...rules.length > 0 ? [`Opt-in template rules ${uniqueSorted(rules).join(", ")} merge recorded literals by shape; merged parameters may conflate distinct resources.`] : [],
				...capture.records.length < capture.total_records ? [`Parent contains an ordinal subset; the ${target.noun} covers only retained records.`] : []
			]);
			if (!limitations.ok) return limitations;
			for (const record of capture.records) {
				const added = target.accumulator.add(record);
				if (!added.ok) return added;
			}
			return ok(undefined);
		};
		projectEnvironmentManifestView = (parent, view, accumulator = view.kind === "environment-manifest" ? new EnvironmentManifestAccumulator(undefined, view.include_query_parameter_names, view.template_rules) : new EnvironmentManifestAccumulator()) => {
			if (view.kind !== "environment-manifest") return err(new AnalysisUnsupportedTargetError("inspect_analysis_view", parent.evidenceId, `View ${view.kind} is unsupported for parent operation ${parent.operation}; environment-manifest requires inspect_web_network_capture or capture_browser_scenario.`));
			const grouped = groupCaptureRecords(parent, view.kind, view.template_rules, {
				accumulator,
				noun: "manifest",
				limitations: view.include_query_parameter_names ? ["Observed query parameter names do not establish required parameters, value types or a complete API schema."] : []
			});
			if (!grouped.ok) return grouped;
			const capture = grouped.value;
			const manifest = accumulator.finish();
			if (!manifest.ok) return manifest;
			return ok({
				kind: "environment-manifest",
				view,
				parent_evidence_id: parent.evidenceId,
				parent_operation: capture.operation,
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: capture.artifact.path,
					sha256: capture.artifact.sha256
				},
				...manifest.value
			});
		};
	})))();
}

//#endregion
//#region dist/domain/exactJsonNumber.js
var isExactJsonNumber, parseExactJson;
function init_exactJsonNumber() {
	return (init_exactJsonNumber = __esmMin((() => {
		init_jsonValue();
		init_safeJson();
		isExactJsonNumber = (value, source) => source !== undefined && isSafeNumber(source) && !Object.is(value, -0);
		parseExactJson = (text) => {
			const parsed = safeParseJson(text, (_key, value, context) => {
				if (typeof value === "number" && !isExactJsonNumber(value, context?.source)) throw new RangeError("JSON numeric conversion would lose recorded data");
				return value;
			});
			if (!parsed.ok) return undefined;
			const value = jsonValueSchema.safeParse(parsed.value);
			return value.success ? value.data : undefined;
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentStateRules.js
var WRITE_METHODS, QUERY_SEGMENTS, IDENTITY_NAMES, VERSION_SEGMENT, segmentsOf, isParam, isObject, scalarText, same, lastSegmentValue, normalizedPath, collectionPathOf, isQueryPost, isStateWrite, writeSpanCheck, apiBaseLengths, rootOf, jsonBytes, hasPrototypeKey, pointerTo, pointerName, at, replaceAt, matchingKeys, locateItem, identifies, locateList, listItems, renderStateEntity, renderStateList;
function init_environmentStateRules() {
	return (init_environmentStateRules = __esmMin((() => {
		init_comparisonSemantics();
		init_webNetworkRouteTemplates();
		WRITE_METHODS = new Set([
			"POST",
			"PUT",
			"PATCH",
			"DELETE"
		]);
		QUERY_SEGMENTS = new Set([
			"search",
			"query",
			"list",
			"find",
			"fuzzy",
			"lookup",
			"count",
			"aggregate",
			"stats",
			"_search",
			"_count",
			"_msearch"
		]);
		IDENTITY_NAMES = [
			"id",
			"uid",
			"uuid",
			"_id",
			"ID",
			"UID",
			"Id",
			"guid",
			"key",
			"slug",
			"name"
		];
		VERSION_SEGMENT = /^v\d+(?:\.\d+)*$/u;
		segmentsOf = (path) => path.split("/").filter((segment) => segment.length > 0);
		isParam = (segment) => segment.startsWith("{") && segment.endsWith("}");
		isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
		scalarText = (value) => typeof value === "string" ? value : typeof value === "number" ? String(value) : undefined;
		same = (left, right) => left === undefined || right === undefined ? left === right : canonicalJson(left, "Environment state") === canonicalJson(right, "Environment state");
		lastSegmentValue = (path) => {
			const segment = segmentsOf(path).at(-1) ?? "";
			try {
				return decodeURIComponent(segment);
			} catch {
				return segment;
			}
		};
		normalizedPath = (path) => `/${segmentsOf(path).join("/")}`;
		collectionPathOf = (record, item) => item ? `/${segmentsOf(record.path).slice(0, -1).join("/")}` : normalizedPath(record.path);
		isQueryPost = (method, path) => method === "POST" && segmentsOf(path).some((segment) => QUERY_SEGMENTS.has(segment.toLowerCase()));
		isStateWrite = (record) => WRITE_METHODS.has(record.method) && !isQueryPost(record.method, record.path) && (record.status === null || record.status >= 200 && record.status < 400);
		writeSpanCheck = (writes) => {
			const reach = [];
			for (const write of writes) reach.push(Math.max(reach.at(-1) ?? Number.NEGATIVE_INFINITY, write.end));
			return (earlier, later) => {
				let low = 0;
				let high = writes.length;
				while (low < high) {
					const middle = low + high >>> 1;
					if (writes[middle].start < later.end) low = middle + 1;
					else high = middle;
				}
				return low > 0 && reach[low - 1] > earlier.start;
			};
		};
		apiBaseLengths = (templates) => {
			const groups = new Map();
			for (const template of templates) {
				const segments = segmentsOf(template);
				const first = segments[0] ?? "";
				const group = groups.get(first);
				if (group === undefined) groups.set(first, [segments]);
				else group.push(segments);
			}
			return new Map([...groups.entries()].map(([first, members]) => {
				const head = members[0] ?? [];
				let length = 0;
				while (length < head.length && !isParam(head[length]) && members.every((segments) => segments[length] === head[length])) length += 1;
				return [first, length];
			}));
		};
		rootOf = (path, bases) => {
			const segments = segmentsOf(path);
			let end = Math.min(bases.get(segments[0] ?? "") ?? 0, segments.length);
			while (end < segments.length && VERSION_SEGMENT.test(segments[end])) end += 1;
			return segments.slice(0, end + 1);
		};
		jsonBytes = (value) => {
			if (typeof value === "string") return textBytes(value.length);
			if (Array.isArray(value)) return value.reduce((sum, item) => sum + jsonBytes(item), 128);
			if (isObject(value)) return Object.entries(value).reduce((sum, [name, item]) => sum + textBytes(name.length) + jsonBytes(item), 128);
			return 128;
		};
		hasPrototypeKey = (value) => Array.isArray(value) ? value.some(hasPrototypeKey) : isObject(value) && Object.entries(value).some(([name, item]) => name === "__proto__" || hasPrototypeKey(item));
		pointerTo = (name) => `/${name.replaceAll("~", "~0").replaceAll("/", "~1")}`;
		pointerName = (pointer) => pointer.slice(1).replaceAll("~1", "/").replaceAll("~0", "~");
		at = (body, pointer) => {
			if (pointer === "") return body;
			if (!isObject(body)) return undefined;
			const name = pointerName(pointer);
			return Object.hasOwn(body, name) ? body[name] : undefined;
		};
		replaceAt = (body, pointer, value) => {
			if (pointer === "" || !isObject(body)) return value;
			const name = pointerName(pointer);
			return Object.fromEntries(Object.entries(body).map(([key, item]) => [key, key === name ? value : item]));
		};
		matchingKeys = (object, value) => Object.keys(object).filter((key) => scalarText(object[key]) === value);
		locateItem = (body, value) => {
			if (!isObject(body)) return undefined;
			const root = matchingKeys(body, value);
			if (root.length > 0) return {
				pointer: "",
				keys: root
			};
			const wrapped = Object.entries(body).flatMap(([name, item]) => {
				if (!isObject(item)) return [];
				const keys = matchingKeys(item, value);
				return keys.length > 0 ? [{
					pointer: pointerTo(name),
					keys
				}] : [];
			});
			return wrapped.length === 1 ? wrapped[0] : undefined;
		};
		identifies = (items, name) => {
			const values = items.map((item) => scalarText(item[name]));
			return values.every((value) => value !== undefined) && new Set(values).size === values.length;
		};
		locateList = (body, idField) => {
			if (Array.isArray(body)) return body.every(isObject) ? "" : undefined;
			if (!isObject(body) || IDENTITY_NAMES.some((name) => scalarText(body[name]) !== undefined)) return undefined;
			const arrays = Object.entries(body).filter((entry) => Array.isArray(entry[1]) && entry[1].every(isObject));
			const carrying = arrays.filter(([, items]) => items.length > 0 && (idField === undefined ? IDENTITY_NAMES.some((name) => identifies(items, name)) : identifies(items, idField)));
			const chosen = carrying.length === 1 ? carrying[0] : carrying.length === 0 && arrays.length === 1 ? arrays[0] : undefined;
			return chosen === undefined ? undefined : pointerTo(chosen[0]);
		};
		listItems = (body, pointer) => {
			const items = at(body, pointer);
			return Array.isArray(items) && items.every(isObject) ? items : undefined;
		};
		renderStateEntity = (entity, view, volatileFields, observed) => {
			const own = entity.view_fields.find((candidate) => candidate.tool === view.tool)?.fields ?? {};
			return Object.fromEntries(view.fields.flatMap((name) => {
				const source = observed !== undefined && volatileFields.has(name) ? observed : Object.hasOwn(own, name) ? own : entity.fields;
				return Object.hasOwn(source, name) ? [[name, source[name]]] : [];
			}));
		};
		renderStateList = (view, base, items) => view.counters.reduce((body, name) => replaceAt(body, pointerTo(name), items.length), replaceAt(base, view.pointer, [...items]));
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentStateMerge.js
var compareObservedEntities, mergeObservedEntity, classifyEntityChanges;
function init_environmentStateMerge() {
	return (init_environmentStateMerge = __esmMin((() => {
		init_unicodeCodePointOrder();
		init_environmentStateRules();
		compareObservedEntities = (left, right) => compareUnicodeCodePoints(left.type, right.type) || compareUnicodeCodePoints(left.collection, right.collection) || left.order[0] - right.order[0] || left.order[1] - right.order[1];
		mergeObservedEntity = (entity) => {
			const latest = new Map();
			for (const observation of entity.observations) latest.set(observation.tool, observation);
			const fields = new Map();
			const ranked = [...latest.values()].sort((left, right) => Number(left.item) - Number(right.item) || left.position - right.position);
			for (const observation of ranked) for (const [name, value] of Object.entries(observation.object)) fields.set(name, value);
			return {
				type: entity.type,
				collection: entity.collection,
				id: entity.id,
				fields: Object.fromEntries(fields),
				view_fields: [...latest.values()].map((observation) => ({
					tool: observation.tool,
					fields: Object.fromEntries(Object.entries(observation.object).filter(([name, value]) => !same(fields.get(name), value)))
				})).filter((view) => Object.keys(view.fields).length > 0).sort((left, right) => compareUnicodeCodePoints(left.tool, right.tool)),
				record_ordinals: [...new Set(entity.observations.map((observation) => observation.ordinal))]
			};
		};
		classifyEntityChanges = (entities, lineOf, writeBetween) => {
			const rewritten = new Set();
			const volatile = new Map();
			const changed = (before, after) => Object.keys(after.object).filter((name) => Object.hasOwn(before.object, name) && !same(before.object[name], after.object[name]));
			for (const entity of entities) {
				const timeline = [...entity.observations].sort((left, right) => left.position - right.position);
				const lastOfLine = new Map();
				const lastOfField = new Map();
				timeline.forEach((after) => {
					const line = JSON.stringify(lineOf(after));
					const repeat = lastOfLine.get(line);
					if (repeat !== undefined) {
						if (writeBetween(repeat, after)) {
							if (!same(repeat.object, after.object)) rewritten.add(entity.type);
						} else for (const name of changed(repeat, after)) volatile.set(entity.type, (volatile.get(entity.type) ?? new Set()).add(name));
					}
					const sighting = {
						observation: after,
						line
					};
					for (const name of Object.keys(after.object)) {
						const previous = lastOfField.get(name);
						if (previous !== undefined && previous.line !== line && !same(previous.observation.object[name], after.object[name]) && writeBetween(previous.observation, after)) rewritten.add(entity.type);
						lastOfField.set(name, sighting);
					}
					lastOfLine.set(line, after);
				});
			}
			return {
				rewritten,
				volatile
			};
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentStateGate.js
var FieldUnion, recorded, itemMismatch, checkItemPlan, listFacts, nameTokens, isItemTotal, countOf, CONTINUATION_NAMES, continues, listReproduces, checkListPlan;
function init_environmentStateGate() {
	return (init_environmentStateGate = __esmMin((() => {
		init_comparisonSemantics();
		init_unicodeCodePointOrder();
		init_environmentStateRules();
		init_webNetworkRouteTemplates();
		FieldUnion = class {
			fields = [];
			/** Membership beside the ordered list, so a wide object is not scanned per key. */
			#seen = new Set();
			#required;
			add(object) {
				for (const key of Object.keys(object)) if (!this.#seen.has(key)) {
					this.#seen.add(key);
					this.fields.push(key);
				}
				const keys = new Set(Object.keys(object));
				this.#required = this.#required === undefined ? keys : new Set([...this.#required].filter((key) => keys.has(key)));
			}
			get required() {
				return this.fields.filter((key) => this.#required?.has(key) === true);
			}
			/** Retained bytes of the field lists a plan keeps. */
			get bytes() {
				return this.fields.reduce((sum, name) => sum + 128 * 2 + textBytes(name.length) * 2, 128 * 2);
			}
		};
		recorded = (plan, reason) => ({
			tool: plan.tool.name,
			shape: "recorded",
			reason
		});
		itemMismatch = (context, plan, check, record) => {
			const { view, envelope } = check;
			const entity = context.entity(plan.type, collectionPathOf(record, true), lastSegmentValue(record.path));
			return context.withBody(record.ordinal, (body) => {
				const object = body === undefined ? undefined : at(body, plan.pointer);
				if (entity === undefined || body === undefined || !isObject(object)) return "fields-differ";
				const skeleton = canonicalJson(replaceAt(body, plan.pointer, null), "Environment state");
				if (envelope.skeleton === undefined) {
					context.retain(textBytes(skeleton.length));
					envelope.skeleton = skeleton;
				}
				if (skeleton !== envelope.skeleton) return "envelope-varies";
				const shown = renderStateEntity(entity, view, context.volatileOf(plan.type), object);
				return same(shown, object) ? undefined : "fields-differ";
			});
		};
		checkItemPlan = (context, plan) => {
			const union = new FieldUnion();
			for (const record of plan.latest) context.withBody(record.ordinal, (body) => {
				const object = body === undefined ? undefined : at(body, plan.pointer);
				if (isObject(object)) union.add(object);
			});
			context.retain(union.bytes);
			const view = {
				tool: plan.tool.name,
				fields: union.fields
			};
			const envelope = {};
			for (const record of plan.latest) {
				const reason = itemMismatch(context, plan, {
					view,
					envelope
				}, record);
				if (reason !== undefined) return recorded(plan, reason);
			}
			return {
				tool: plan.tool.name,
				shape: "item",
				type: plan.type,
				pointer: plan.pointer,
				fields: union.fields,
				required_fields: union.required,
				envelope_ordinal: plan.latest[0].ordinal,
				checked_record_ordinals: plan.latest.map((record) => record.ordinal)
			};
		};
		listFacts = (context, plan, union) => {
			const field = context.idField(plan.type);
			let all = true;
			let counters;
			for (const record of plan.latest) context.withBody(record.ordinal, (body) => {
				const items = body === undefined ? undefined : listItems(body, plan.pointer);
				if (body === undefined || items === undefined) return;
				items.forEach((item) => union.add(item));
				if (all && record.query === undefined) {
					const ids = items.map((item) => scalarText(item[field]) ?? "");
					const expected = context.inCollection(plan.type, collectionPathOf(record, false)).map((entity) => entity.id);
					if (!same(ids, expected)) all = false;
				} else all = false;
				const parent = plan.pointer === "" || !isObject(body) ? {} : body;
				const counted = Object.keys(parent).filter((name) => isItemTotal(name) && countOf(parent[name]) !== undefined);
				if (counted.some((name) => countOf(parent[name]) !== items.length) || Object.keys(parent).some((name) => continues(name, parent[name]))) all = false;
				const names = counted.filter((name) => parent[name] === items.length);
				counters = (counters ?? names).filter((name) => names.includes(name));
			});
			return {
				all,
				counters: (counters ?? []).sort(compareUnicodeCodePoints)
			};
		};
		nameTokens = (name) => name.split(/[_\-\s]|(?<=[a-z0-9])(?=[A-Z])/u).map((token) => token.toLowerCase());
		isItemTotal = (name) => {
			const tokens = nameTokens(name);
			return tokens.some((token) => token === "total" || token === "count" || token === "totalcount" || token === "itemcount") && !tokens.some((token) => token === "page" || token === "pages" || token === "per");
		};
		countOf = (value) => typeof value === "number" ? value : typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : undefined;
		CONTINUATION_NAMES = new Set([
			"hasmore",
			"next",
			"nextcursor",
			"nextpage",
			"nextpagetoken",
			"nexttoken"
		]);
		continues = (name, value) => CONTINUATION_NAMES.has(nameTokens(name).join("")) && value !== undefined && value !== null && value !== false && value !== "";
		listReproduces = (context, plan, view, record) => {
			const field = context.idField(plan.type);
			return context.withBody(record.ordinal, (body) => {
				const items = body === undefined ? undefined : listItems(body, plan.pointer);
				if (body === undefined || items === undefined) return false;
				const observed = new Map(items.map((item) => [scalarText(item[field]) ?? "", item]));
				const members = view.all ? context.inCollection(plan.type, collectionPathOf(record, false)) : items.flatMap((item) => {
					const entity = context.entity(plan.type, collectionPathOf(record, false), scalarText(item[field]) ?? "");
					return entity === undefined ? [] : [entity];
				});
				const rendered = members.map((entity) => renderStateEntity(entity, view, context.volatileOf(plan.type), observed.get(entity.id)));
				return same(renderStateList(view, body, rendered), body);
			});
		};
		checkListPlan = (context, plan) => {
			const union = new FieldUnion();
			const { all, counters } = listFacts(context, plan, union);
			context.retain(union.bytes);
			const view = {
				tool: plan.tool.name,
				fields: union.fields,
				pointer: plan.pointer,
				counters,
				all
			};
			if (!plan.latest.every((record) => listReproduces(context, plan, view, record))) return recorded(plan, "list-differs");
			return {
				tool: plan.tool.name,
				shape: "list",
				type: plan.type,
				pointer: plan.pointer,
				fields: union.fields,
				required_fields: union.required,
				membership: all ? "all" : "recorded",
				counters,
				checked_record_ordinals: plan.latest.map((record) => record.ordinal)
			};
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentStateWriteCutoffs.js
var node, StateWriteCutoffs;
function init_environmentStateWriteCutoffs() {
	return (init_environmentStateWriteCutoffs = __esmMin((() => {
		init_webNetworkRouteTemplates();
		init_environmentStateRules();
		node = () => ({
			children: new Map(),
			wildcard: undefined,
			exact: undefined,
			first: undefined
		});
		StateWriteCutoffs = class {
			before;
			#root;
			constructor(writes, bases, before, retain) {
				this.before = before;
				retain(128 * 4);
				this.#root = node();
				for (const write of writes) {
					let current = this.#root;
					current.first = this.#earlier(current.first, write);
					for (const segment of rootOf(write.path, bases)) {
						const wildcard = isParam(segment);
						let child = wildcard ? current.wildcard : current.children.get(segment);
						if (child === undefined) {
							retain(128 * 4 + textBytes(segment.length));
							child = node();
							if (wildcard) current.wildcard = child;
							else current.children.set(segment, child);
						}
						current = child;
						current.first = this.#earlier(current.first, write);
					}
					current.exact = this.#earlier(current.exact, write);
				}
			}
			#earlier(left, right) {
				if (right === undefined) return left;
				return left === undefined || this.before(right, left) ? right : left;
			}
			/** Earliest ancestor/descendant match; parameters on either side match any one segment. */
			first(root) {
				const nodes = [this.#root];
				const depths = [0];
				let first;
				while (nodes.length > 0) {
					const current = nodes.pop();
					const depth = depths.pop();
					first = this.#earlier(first, current.exact);
					if (depth === root.length || depth === root.length - 1 && isParam(root[depth])) {
						first = this.#earlier(first, current.first);
						continue;
					}
					const segment = root[depth];
					if (isParam(segment)) {
						for (const child of current.children.values()) {
							nodes.push(child);
							depths.push(depth + 1);
						}
					} else {
						const child = current.children.get(segment);
						if (child !== undefined) {
							nodes.push(child);
							depths.push(depth + 1);
						}
					}
					if (current.wildcard !== undefined) {
						nodes.push(current.wildcard);
						depths.push(depth + 1);
					}
				}
				return first;
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/EnvironmentStateExtraction.js
var StateBudgetExhausted, entityKey, requestLine, EnvironmentStateExtraction;
function init_EnvironmentStateExtraction() {
	return (init_EnvironmentStateExtraction = __esmMin((() => {
		init_unicodeCodePointOrder();
		init_environmentStateRules();
		init_webNetworkRouteTemplates();
		init_environmentStateMerge();
		init_environmentStateGate();
		init_environmentStateWriteCutoffs();
		StateBudgetExhausted = class extends Error {};
		entityKey = (type, collection, id) => compositeKey([
			type,
			collection,
			id
		]);
		requestLine = (record) => record.path + (record.query ?? "");
		EnvironmentStateExtraction = class {
			#tools;
			#timeline;
			#budget;
			#position;
			#byOrdinal;
			#writes;
			#writeWithin;
			#bases;
			#writeCutoffs;
			#initLimits = new Map();
			#identity = new Map();
			#views = new Map();
			#plans = [];
			#entities = new Map();
			#volatile = new Map();
			/** Types with a value that changed across a recorded write, which may be that write's effect. */
			#rewritten = new Set();
			#merged = new Map();
			/** Merged entities by type and collection, built once on first use after merging. */
			#collections;
			constructor(input) {
				this.#tools = input.tools;
				this.#timeline = input.timeline;
				this.#budget = input.budget;
				this.#position = new Map(input.records.map((record, index) => [record.ordinal, index]));
				this.#byOrdinal = new Map(input.records.map((record) => [record.ordinal, record]));
				this.#writes = input.records.filter(isStateWrite);
				this.#writeWithin = writeSpanCheck(this.#writes);
				this.#bases = apiBaseLengths(input.tools.map((tool) => tool.path_template));
			}
			/** The extracted state, or null when the representation budget is exhausted. */
			run() {
				try {
					if (this.#writes.length > 0) this.#writeCutoffs = new StateWriteCutoffs(this.#writes, this.#bases, (left, right) => this.#position.get(left.ordinal) < this.#position.get(right.ordinal), (bytes) => this.#retain(bytes));
					const candidates = this.#candidates();
					for (const candidate of candidates.filter((entry) => entry.item)) this.#planItem(candidate);
					for (const candidate of candidates.filter((entry) => !entry.item)) this.#planList(candidate);
					for (const plan of this.#plans) this.#observePlan(plan);
					this.#classifyChanges();
					this.#merge();
					const gate = this.#gateContext();
					for (const plan of this.#plans) if (this.#rewritten.has(plan.type)) this.#recorded(plan.tool, "fields-differ");
					else this.#views.set(plan.tool.name, plan.item ? checkItemPlan(gate, plan) : checkListPlan(gate, plan));
					const documents = this.#documents(candidates);
					for (const { tool } of candidates) if (!this.#views.has(tool.name)) this.#recorded(tool, "not-entity");
					return this.#result(documents);
				} catch (cause) {
					if (cause instanceof StateBudgetExhausted) return null;
					throw cause;
				}
			}
			#retain(bytes) {
				if (!this.#budget.retain(bytes)) throw new StateBudgetExhausted();
			}
			/** Parse one body and hand it to `use` before its temporary work is dropped; unusable bodies arrive undefined. */
			#withBody(ordinal, use) {
				const parsed = this.#budget.body(ordinal);
				if (parsed === null) throw new StateBudgetExhausted();
				try {
					return use(parsed.kind === "json" && !hasPrototypeKey(parsed.value) ? parsed.value : undefined);
				} finally {
					this.#budget.release();
				}
			}
			#recorded(tool, reason) {
				this.#views.set(tool.name, {
					tool: tool.name,
					shape: "recorded",
					reason
				});
			}
			/** GET tools may render from state; query POSTs stay recorded. */
			#candidates() {
				const candidates = [];
				for (const tool of this.#tools) {
					if (isQueryPost(tool.method, tool.path_template)) this.#recorded(tool, "query-body");
					if (tool.method !== "GET") continue;
					const segments = segmentsOf(tool.path_template);
					const item = segments.length > 0 && isParam(segments.at(-1));
					candidates.push({
						tool,
						item,
						type: item ? `/${segments.slice(0, -1).join("/")}` : normalizedPath(tool.path_template)
					});
				}
				return candidates;
			}
			/** The first write whose root relates to the template's bounds its init recordings. */
			#initLimit(template) {
				if (this.#writeCutoffs === undefined) return undefined;
				if (this.#initLimits.has(template)) return this.#initLimits.get(template);
				const first = this.#writeCutoffs.first(rootOf(template, this.#bases));
				this.#retain(128 + textBytes(template.length));
				this.#initLimits.set(template, first);
				return first;
			}
			/** Successful recordings that finished before the first related write began. */
			#initRecordings(tool, template) {
				const limit = this.#initLimit(template);
				const before = (record) => limit === undefined || this.#position.get(record.ordinal) < this.#position.get(limit.ordinal) && (this.#timeline === "record-order" || record.end <= limit.start);
				return tool.record_ordinals.map((ordinal) => this.#byOrdinal.get(ordinal)).filter((record) => record !== undefined && record.status !== null && record.status >= 200 && record.status < 300 && before(record)).sort((left, right) => this.#position.get(left.ordinal) - this.#position.get(right.ordinal));
			}
			#latestPerLine(recordings) {
				const latest = new Map();
				for (const record of recordings) {
					latest.delete(requestLine(record));
					latest.set(requestLine(record), record);
				}
				return [...latest.values()];
			}
			/** A candidate's initial recordings, or undefined after recording that it has none. */
			#initRecordingsOf(candidate) {
				const recordings = this.#initRecordings(candidate.tool, candidate.type);
				if (recordings.length > 0) return recordings;
				this.#recorded(candidate.tool, "no-init-recording");
				return undefined;
			}
			#addPlan(candidate, pointer, recordings) {
				this.#plans.push({
					...candidate,
					pointer,
					recordings,
					latest: this.#latestPerLine(recordings)
				});
			}
			/** Item tools prove a type's identity field by the path value their bodies repeat. */
			#planItem(candidate) {
				const { tool, type } = candidate;
				const recordings = this.#initRecordingsOf(candidate);
				if (recordings === undefined) return;
				let pointer;
				let keys;
				for (const record of recordings) {
					const located = this.#withBody(record.ordinal, (body) => body === undefined ? null : locateItem(body, lastSegmentValue(record.path)));
					if (located === null) {
						this.#recorded(tool, "body-unusable");
						return;
					}
					if (located === undefined || (pointer ?? located.pointer) !== located.pointer) {
						this.#recorded(tool, "no-identity");
						return;
					}
					pointer = located.pointer;
					if (keys === undefined) keys = located.keys;
					else {
						const matching = new Set(located.keys);
						keys = keys.filter((key) => matching.has(key));
					}
				}
				const field = IDENTITY_NAMES.find((name) => keys?.includes(name) === true) ?? keys?.[0];
				const known = this.#identity.get(type);
				if (field === undefined || pointer === undefined || known !== undefined && known.field !== field) {
					this.#recorded(tool, "no-identity");
					return;
				}
				this.#identity.set(type, {
					field,
					basis: "path-parameter"
				});
				this.#addPlan(candidate, pointer, recordings);
			}
			/** List tools use the proved field, else the first identity name every non-empty recording's items carry. */
			#planList(candidate) {
				const { tool, type } = candidate;
				const recordings = this.#initRecordingsOf(candidate);
				if (recordings === undefined) return;
				const proved = this.#identity.get(type)?.field;
				let pointer;
				let names;
				let sawItems = false;
				for (const record of recordings) {
					const found = this.#withBody(record.ordinal, (body) => {
						if (body === undefined) return null;
						const located = locateList(body, proved);
						if (pointer !== undefined && located !== pointer) return undefined;
						const items = located === undefined ? undefined : listItems(body, located);
						if (items === undefined) return undefined;
						pointer = located;
						if (items.length > 0) sawItems = true;
						return items.length === 0 ? names ?? (proved === undefined ? IDENTITY_NAMES : [proved]) : (proved === undefined ? IDENTITY_NAMES : [proved]).filter((name) => identifies(items, name));
					});
					if (found === null || found === undefined) {
						this.#recorded(tool, found === null ? "body-unusable" : "not-entity");
						return;
					}
					names = (names ?? found).filter((name) => found.includes(name));
				}
				const field = names?.[0];
				if (field === undefined || pointer === undefined || proved === undefined && !sawItems) {
					this.#recorded(tool, "no-identity");
					return;
				}
				if (!this.#identity.has(type)) this.#identity.set(type, {
					field,
					basis: "field-name"
				});
				this.#addPlan(candidate, pointer, recordings);
			}
			#observePlan(plan) {
				const memberships = !plan.item && this.#writeWithin(plan.recordings[0], plan.recordings.at(-1)) ? new Map() : undefined;
				for (const record of plan.recordings) this.#withBody(record.ordinal, (body) => {
					const located = body === undefined ? undefined : at(body, plan.pointer);
					const objects = plan.item ? isObject(located) ? [located] : [] : body === undefined ? [] : listItems(body, plan.pointer) ?? [];
					if (memberships !== undefined) this.#observeMembership(plan, record, objects, memberships);
					objects.forEach((object, index) => this.#observe(plan, record, object, index));
				});
			}
			/** Compare one request line's membership before discarding older recordings; reuse its bounded set. */
			#observeMembership(plan, record, objects, memberships) {
				const line = requestLine(record);
				let previous = memberships.get(line);
				const earlier = previous?.record;
				if (previous === undefined) {
					this.#retain(128 * 2 + textBytes(line.length));
					previous = {
						record,
						ids: new Set(),
						capacity: 0
					};
					memberships.set(line, previous);
				}
				if (objects.length > previous.capacity) {
					this.#retain((objects.length - previous.capacity) * 128 * 4);
					previous.capacity = objects.length;
				}
				const field = this.#identity.get(plan.type).field;
				let changed = previous.ids.size !== objects.length;
				for (const object of objects) if (!previous.ids.delete(scalarText(object[field]))) changed = true;
				if (previous.ids.size > 0) changed = true;
				if (earlier !== undefined && changed && this.#writeWithin(earlier, record)) this.#rewritten.add(plan.type);
				previous.ids.clear();
				for (const object of objects) previous.ids.add(scalarText(object[field]));
				previous.record = record;
			}
			/** Record one observed entity object; a value that changes between one tool's own observations is volatile. */
			#observe(plan, record, object, index) {
				const field = this.#identity.get(plan.type).field;
				const id = scalarText(object[field]);
				if (id === undefined) return;
				const collection = collectionPathOf(record, plan.item);
				const key = entityKey(plan.type, collection, id);
				const position = this.#position.get(record.ordinal);
				let entity = this.#entities.get(key);
				if (entity === undefined) {
					this.#retain(128 * 4 + textBytes(key.length));
					entity = {
						type: plan.type,
						collection,
						id,
						order: [position, index],
						observations: []
					};
					this.#entities.set(key, entity);
				} else {
					const [first, at] = entity.order;
					if (position < first || position === first && index < at) entity.order = [position, index];
				}
				this.#retain(128 + jsonBytes(object));
				entity.observations.push({
					position,
					ordinal: record.ordinal,
					tool: plan.tool.name,
					item: plan.item,
					object
				});
			}
			/** A change across any recorded write rewrites the type; one between repeats of a line with no write is volatile. */
			#classifyChanges() {
				const recordOf = (observation) => this.#byOrdinal.get(observation.ordinal);
				const changes = classifyEntityChanges(this.#entities.values(), (observation) => [observation.tool, requestLine(recordOf(observation))], (earlier, later) => this.#writeWithin(recordOf(earlier), recordOf(later)));
				for (const type of changes.rewritten) this.#rewritten.add(type);
				for (const [type, names] of changes.volatile) this.#volatile.set(type, names);
			}
			#merge() {
				for (const entity of [...this.#entities.values()].sort(compareObservedEntities)) this.#merged.set(entityKey(entity.type, entity.collection, entity.id), mergeObservedEntity(entity));
			}
			#gateContext() {
				return {
					withBody: (ordinal, use) => this.#withBody(ordinal, use),
					retain: (bytes) => this.#retain(bytes),
					entity: (type, collection, id) => this.#merged.get(entityKey(type, collection, id)),
					inCollection: (type, collection) => this.#inCollection(type, collection),
					volatileOf: (type) => this.#volatileOf(type),
					idField: (type) => this.#identity.get(type).field
				};
			}
			#volatileOf(type) {
				return this.#volatile.get(type) ?? new Set();
			}
			#inCollection(type, collection) {
				if (this.#collections === undefined) {
					this.#retain(128 * (this.#merged.size + 1));
					this.#collections = new Map();
					for (const entity of this.#merged.values()) {
						const key = JSON.stringify([entity.type, entity.collection]);
						const members = this.#collections.get(key);
						if (members === undefined) this.#collections.set(key, [entity]);
						else members.push(entity);
					}
				}
				return this.#collections.get(JSON.stringify([type, collection])) ?? [];
			}
			/** A written path whose read is not an entity holds one document value: its latest init recording. */
			#documents(candidates) {
				const written = new Set(this.#tools.filter((tool) => [
					"POST",
					"PUT",
					"PATCH"
				].includes(tool.method) && !isQueryPost(tool.method, tool.path_template)).map((tool) => tool.path_template));
				const documents = [];
				for (const { tool, item } of candidates) {
					const current = this.#views.get(tool.name);
					const entityless = current === undefined || current.shape === "recorded" && (current.reason === "not-entity" || current.reason === "no-identity");
					if (item || !entityless || !written.has(tool.path_template)) continue;
					const latest = this.#latestPerLine(this.#initRecordings(tool, tool.path_template));
					if (latest.length !== 1) {
						if (latest.length > 1) this.#recorded(tool, "query-varies");
						continue;
					}
					const record = latest[0];
					const value = this.#withBody(record.ordinal, (body) => body);
					if (value === undefined) {
						this.#recorded(tool, "body-unusable");
						continue;
					}
					this.#retain(128 + jsonBytes(value) + textBytes(record.path.length));
					documents.push({
						tool: tool.name,
						path: record.path,
						value,
						record_ordinal: record.ordinal
					});
					this.#views.set(tool.name, {
						tool: tool.name,
						shape: "document",
						checked_record_ordinals: [record.ordinal]
					});
				}
				return documents.sort((left, right) => compareUnicodeCodePoints(left.tool, right.tool));
			}
			/** Types and entities that at least one state-backed view renders; view values only for those views. */
			#result(documents) {
				const backed = new Set();
				const backedTypes = new Set();
				for (const view of this.#views.values()) if (view.shape === "item" || view.shape === "list") {
					this.#retain(128);
					backed.add(view.tool);
					if (!backedTypes.has(view.type)) {
						this.#retain(128);
						backedTypes.add(view.type);
					}
				}
				const types = [...this.#identity.entries()].filter(([type]) => backedTypes.has(type)).map(([type, { field, basis }]) => ({
					collection_template: type,
					id_field: field,
					id_basis: basis,
					init_before_ordinal: this.#initLimit(type)?.ordinal ?? null,
					volatile_fields: [...this.#volatileOf(type)].sort(compareUnicodeCodePoints)
				})).sort((left, right) => compareUnicodeCodePoints(left.collection_template, right.collection_template));
				const typed = new Set(types.map((type) => type.collection_template));
				return {
					types,
					entities: [...this.#merged.values()].filter((entity) => typed.has(entity.type)).map((entity) => ({
						...entity,
						view_fields: entity.view_fields.filter((view) => backed.has(view.tool))
					})),
					documents,
					views: this.#tools.flatMap((tool) => {
						const view = this.#views.get(tool.name);
						return view === undefined ? [] : [view];
					})
				};
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/recordedResponseBody.js
var contentTextSchema, strictUtf8, base64PrefixChars, readRecordedResponseBody;
function init_recordedResponseBody() {
	return (init_recordedResponseBody = __esmMin((() => {
		contentTextSchema = z.object({ response: z.object({ content: z.object({
			text: z.unknown().optional(),
			encoding: z.unknown().optional()
		}) }) });
		strictUtf8 = () => new TextDecoder("utf-8", {
			fatal: true,
			ignoreBOM: true
		});
		base64PrefixChars = (limitBytes) => Math.ceil((limitBytes + 4) / 3) * 4;
		readRecordedResponseBody = (record, limitBytes) => {
			const content = contentTextSchema.safeParse(record.reported);
			if (!content.success) return { bodyText: null };
			const { text, encoding } = content.data.response.content;
			if (typeof text !== "string") return { bodyText: null };
			if (encoding !== "base64") return { bodyText: text };
			const binary = record.binary_fields.find((field) => field.pointer === "/response/content/text" && field.state === "retained");
			if (binary === undefined || binary.content_base64 === null) return { bodyText: null };
			const prefixChars = base64PrefixChars(limitBytes);
			const cut = binary.content_base64.length > prefixChars;
			const encoded = cut ? binary.content_base64.slice(0, prefixChars) : binary.content_base64;
			const flags = cut ? { bodyCut: true } : {};
			try {
				const text = strictUtf8().decode(Buffer.from(encoded, "base64"), { stream: cut });
				return {
					bodyText: text,
					...flags
				};
			} catch {
				return {
					bodyText: encoded,
					bodyEncoding: "base64",
					...flags
				};
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/EnvironmentStateAccumulator.js
var STATE_BODY_LIMIT_BYTES, timingSchema, redactedWriteSchema, contentSchema, UNKNOWNS, EnvironmentStateAccumulator;
function init_EnvironmentStateAccumulator() {
	return (init_EnvironmentStateAccumulator = __esmMin((() => {
		init_exactJsonNumber();
		init_result();
		init_webNetworkCapture();
		init_EnvironmentManifestAccumulator();
		init_EnvironmentStateExtraction();
		init_environmentStateRules();
		init_recordedResponseBody();
		init_webNetworkRouteTemplates();
		STATE_BODY_LIMIT_BYTES = 256 * 1024;
		timingSchema = z.object({
			startedDateTime: z.string(),
			time: z.number().nonnegative()
		});
		redactedWriteSchema = z.object({
			request: z.object({ method: z.string() }),
			response: z.object({ status: z.number() }).optional()
		});
		contentSchema = z.object({ response: z.object({ content: z.object({ text: z.string() }) }) });
		UNKNOWNS = [
			{
				kind: "authorization-model",
				statement: "Authorization headers and cookies are structurally excluded from captures; the state states no authorization model."
			},
			{
				kind: "response-semantics",
				statement: "Views reproduce their recorded responses from the state; they do not establish how the application computes responses, derived values or values copied outside entity objects."
			},
			{
				kind: "state-transition",
				statement: "The state is one snapshot from before the first related recorded write; it states no effects of writes."
			}
		];
		EnvironmentStateAccumulator = class extends EnvironmentManifestAccumulator {
			#entries = new Map();
			constructor(maximumBytes = WEB_NETWORK_CAPTURE_LIMITS.outputBytes, rules = []) {
				super(maximumBytes, true, rules, "Environment-state");
			}
			/** The state publishes no body shapes. */
			get reportsBodyShapes() {
				return false;
			}
			add(record) {
				const grouped = super.add(record);
				if (!grouped.ok) return grouped;
				try {
					const line = readRecordedRequestLine(record.reported, true, this.scratch);
					if (line === null) return this.overBudget();
					const timing = timingSchema.safeParse(record.reported);
					const start = timing.success ? Date.parse(timing.data.startedDateTime) : Number.NaN;
					const timed = timing.success && Number.isFinite(start);
					if (line.kind === "excluded") return line.reason === "url-redacted" ? this.#redactedWrite(record, timing.success && timed ? {
						start,
						end: start + timing.data.time
					} : undefined) : ok(undefined);
					if (!this.retain(128 * 8 + textBytes(line.method.length + line.origin.length + line.path.length + (line.query?.length ?? 0) + line.rawMime.length))) return this.overBudget();
					this.#entries.set(record.ordinal, {
						facts: {
							ordinal: record.ordinal,
							method: line.method,
							path: line.path,
							query: line.query === "" ? undefined : line.query,
							status: line.status,
							start: timed ? start : record.ordinal,
							end: timed ? start + timing.data.time : record.ordinal
						},
						origin: line.origin,
						contentType: line.rawMime,
						timed,
						record
					});
					return ok(undefined);
				} finally {
					this.releaseTemporary();
				}
			}
			/** Keep a successful write whose URL was redacted, with an empty path whose root relates to every type. */
			#redactedWrite(record, timing) {
				const parsed = redactedWriteSchema.safeParse(record.reported);
				if (!parsed.success) return ok(undefined);
				const status = parsed.data.response?.status ?? 0;
				const facts = {
					ordinal: record.ordinal,
					method: parsed.data.request.method,
					path: "",
					query: undefined,
					status: status > 0 ? status : null,
					start: timing?.start ?? record.ordinal,
					end: timing?.end ?? record.ordinal
				};
				if (!isStateWrite(facts)) return ok(undefined);
				if (!this.retain(128 * 8 + textBytes(facts.method.length))) return this.overBudget();
				this.#entries.set(record.ordinal, {
					facts,
					origin: null,
					contentType: "",
					timed: timing !== undefined,
					record
				});
				return ok(undefined);
			}
			/** Parse one retained response body as exact JSON, charging its decoding and tree as temporary work. */
			#body(ordinal) {
				const entry = this.#entries.get(ordinal);
				if (entry === undefined || !isJsonLike(mediaTypeEssence(entry.contentType))) return { kind: "unusable" };
				const content = contentSchema.safeParse(entry.record.reported);
				if (!content.success) return { kind: "unusable" };
				const length = content.data.response.content.text.length;
				if (length > base64PrefixChars(262144)) return { kind: "unusable" };
				if (!this.temporary(512 + textBytes(length) * 4)) return null;
				const body = readRecordedResponseBody(entry.record, STATE_BODY_LIMIT_BYTES);
				if (body.bodyText === null || body.bodyEncoding === "base64" || body.bodyCut === true || Buffer.byteLength(body.bodyText, "utf8") > 262144) return { kind: "unusable" };
				const value = parseExactJson(body.bodyText);
				return value === undefined ? { kind: "unusable" } : {
					kind: "json",
					value
				};
			}
			/** Project the init state of the manifest's primary origin; records keep timeline order. */
			finishState() {
				const manifest = this.finish();
				if (!manifest.ok) return manifest;
				const entries = [...this.#entries.values()].filter((entry) => entry.origin === manifest.value.origin || entry.origin === null);
				const redactedWrites = entries.filter((entry) => entry.origin === null).length;
				const timeline = entries.length > 0 && entries.every((entry) => entry.timed) ? "recorded-start-time" : "record-order";
				const records = entries.map((entry) => entry.facts).sort((left, right) => timeline === "record-order" ? left.ordinal - right.ordinal : left.start - right.start || left.ordinal - right.ordinal).map((facts) => timeline === "record-order" ? {
					...facts,
					start: facts.ordinal,
					end: facts.ordinal
				} : facts);
				const state = new EnvironmentStateExtraction({
					tools: manifest.value.tools,
					records,
					timeline,
					budget: {
						body: (ordinal) => this.#body(ordinal),
						retain: (bytes) => this.retain(bytes),
						release: () => this.releaseTemporary()
					}
				}).run();
				if (state === null) return this.overBudget();
				const limitations = this.addLimitations([
					...redactedWrites > 0 ? [`${String(redactedWrites)} of the recorded writes had a redacted URL; each ends the initial state of every type, since its target is unknown.`] : [],
					...timeline === "record-order" ? ["Some records carry no start time, so the state's timeline is record order and overlapping requests are not detected."] : [],
					...state.views.some((view) => view.shape === "recorded") ? ["Tools whose recordings do not reproduce from the extracted state are listed as recorded views with the reason; they replay their recordings."] : []
				]);
				if (!limitations.ok) return limitations;
				return ok({
					origin: manifest.value.origin,
					name: manifest.value.name,
					timeline,
					...state,
					unknowns: UNKNOWNS.map((unknown) => ({ ...unknown })),
					coverage: manifest.value.coverage,
					limitations: this.sortedLimitations()
				});
			}
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/environmentStateView.js
var environmentStateViewRequestSchema, jsonObjectFieldsSchema, checkedSchema, entityViewFields, viewSchema, environmentStateFields, projectEnvironmentStateView;
function init_environmentStateView() {
	return (init_environmentStateView = __esmMin((() => {
		init_jsonValue();
		init_result();
		init_EnvironmentStateAccumulator();
		init_environmentManifestView();
		environmentStateViewRequestSchema = z.strictObject({
			kind: z.literal("environment-state"),
			template_rules: templateRulesSchema.describe("Opt-in template rules as for environment-manifest, each listed at most once. Use the rules of the manifest the state accompanies so tool names match.")
		});
		jsonObjectFieldsSchema = z.record(z.string(), jsonValueSchema);
		checkedSchema = z.array(z.number().int().nonnegative()).describe("Latest init record per request line that the view reproduced from the state.");
		entityViewFields = {
			tool: z.string(),
			type: z.string(),
			pointer: z.string().describe("JSON pointer, of depth at most one, to the entity object or array within the response."),
			fields: z.array(z.string()).describe("Ordered fields the view shows of each entity."),
			required_fields: z.array(z.string()),
			checked_record_ordinals: checkedSchema
		};
		viewSchema = z.discriminatedUnion("shape", [
			z.strictObject({
				...entityViewFields,
				shape: z.literal("item"),
				envelope_ordinal: z.number().int().nonnegative().describe("Record whose response, with the entity object replaced, every item response shares.")
			}),
			z.strictObject({
				...entityViewFields,
				shape: z.literal("list"),
				membership: z.enum(["all", "recorded"]).describe("all: every entity of the collection in state order; recorded: the entities each recorded response listed."),
				counters: z.array(z.string()).describe("Envelope members that count the listed entities.")
			}),
			z.strictObject({
				tool: z.string(),
				shape: z.literal("document"),
				checked_record_ordinals: checkedSchema
			}),
			z.strictObject({
				tool: z.string(),
				shape: z.literal("recorded"),
				reason: z.enum([
					"query-body",
					"no-init-recording",
					"body-unusable",
					"not-entity",
					"no-identity",
					"query-varies",
					"fields-differ",
					"envelope-varies",
					"list-differs"
				])
			})
		]);
		environmentStateFields = {
			origin: z.string().describe("Primary origin, as the environment manifest selects it."),
			name: z.string(),
			timeline: z.enum(["recorded-start-time", "record-order"]).describe("Records are ordered by recorded start time, or by record order when any start time is missing."),
			types: z.array(z.strictObject({
				collection_template: z.string(),
				id_field: z.string(),
				id_basis: z.enum(["path-parameter", "field-name"]).describe("path-parameter: item responses repeat the requested path value in this field; field-name: an inferred identity name every listed item carries distinctly."),
				init_before_ordinal: z.number().int().nonnegative().nullable().describe("First recorded write whose path root relates to the type; state comes from records that finished before it."),
				volatile_fields: z.array(z.string()).describe("Fields whose recorded values changed with no recorded write between; the state keeps the latest.")
			})),
			entities: z.array(z.strictObject({
				type: z.string(),
				collection: z.string(),
				id: z.string(),
				fields: jsonObjectFieldsSchema,
				view_fields: z.array(z.strictObject({
					tool: z.string(),
					fields: jsonObjectFieldsSchema
				})),
				record_ordinals: z.array(z.number().int().nonnegative())
			})).describe("Entities in collection order: type, collection, then first sighting."),
			documents: z.array(z.strictObject({
				tool: z.string(),
				path: z.string(),
				value: jsonValueSchema,
				record_ordinal: z.number().int().nonnegative()
			})),
			views: z.array(viewSchema),
			unknowns: z.array(z.strictObject({
				kind: z.enum([
					"authorization-model",
					"response-semantics",
					"state-transition"
				]),
				statement: z.string()
			}))
		};
		projectEnvironmentStateView = (parent, view, accumulator = new EnvironmentStateAccumulator(undefined, view.template_rules)) => {
			const grouped = groupCaptureRecords(parent, view.kind, view.template_rules, {
				accumulator,
				noun: "state",
				limitations: ["Entity types, identity fields, list membership and counters are inferences from recorded response bodies; the state does not establish server-side schemas, derived values or values copied outside entity objects."]
			});
			if (!grouped.ok) return grouped;
			const state = accumulator.finishState();
			if (!state.ok) return state;
			return ok({
				kind: "environment-state",
				view,
				parent_evidence_id: parent.evidenceId,
				parent_operation: grouped.value.operation,
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: grouped.value.artifact.path,
					sha256: grouped.value.artifact.sha256
				},
				...state.value
			});
		};
	})))();
}

//#endregion
//#region dist/domain/pcap/pcapAnalysis.js
var pcapInputSchemas, pcapRequestSchema, client, endpoint, dnsQuery, protocolCount, pcapResultSchemas;
function init_pcapAnalysis() {
	return (init_pcapAnalysis = __esmMin((() => {
		init_localPath();
		init_digests();
		pcapInputSchemas = {
			inspect_pcap_client: z.strictObject({}),
			inspect_pcap_capture: z.strictObject({ path: localPathStringSchema.describe("Local pcap or pcapng capture file to inspect") })
		};
		pcapRequestSchema = z.discriminatedUnion("operation", [z.strictObject({
			operation: z.literal("inspect_pcap_client"),
			input: pcapInputSchemas.inspect_pcap_client
		}), z.strictObject({
			operation: z.literal("inspect_pcap_capture"),
			input: pcapInputSchemas.inspect_pcap_capture
		})]);
		client = z.strictObject({
			tshark_command: z.string().min(1),
			tshark_source: z.enum(["environment", "path"]),
			tshark_version: z.string().min(1).nullable(),
			capinfos_command: z.string().min(1),
			capinfos_source: z.enum(["environment", "path"]),
			capinfos_version: z.string().min(1).nullable()
		});
		endpoint = z.strictObject({
			address: z.string().min(1),
			port: z.number().int().positive().nullable(),
			packet_count: z.number().int().positive()
		});
		dnsQuery = z.strictObject({
			query: z.string().min(1),
			response_addresses: z.array(z.string().min(1)),
			response_address_count: z.number().int().nonnegative()
		});
		protocolCount = z.strictObject({
			protocol: z.string().min(1),
			packet_count: z.number().int().positive()
		});
		pcapResultSchemas = {
			inspect_pcap_client: z.strictObject({ client }),
			inspect_pcap_capture: z.strictObject({
				client,
				target: z.strictObject({
					path: localPathStringSchema,
					bytes: z.number().int().nonnegative(),
					sha256: digestSchema
				}),
				/** File format as capinfos reports it (pcap vs pcapng). */
				file_type: z.string().min(1).nullable(),
				encapsulation: z.string().min(1).nullable(),
				packet_count: z.number().int().nonnegative().nullable(),
				capture_start: z.string().nullable(),
				capture_end: z.string().nullable(),
				capture_duration_seconds: z.number().nonnegative().nullable(),
				snapshot_length: z.number().int().positive().nullable(),
				/** Distinct endpoints with packet counts, bounded. */
				endpoints: z.array(endpoint),
				endpoint_count: z.number().int().nonnegative(),
				/** DNS queries with resolved addresses, bounded. */
				dns_queries: z.array(dnsQuery),
				dns_query_count: z.number().int().nonnegative(),
				/** TLS Server Name Indication values observed in handshakes. */
				tls_sni_values: z.array(z.string().min(1)),
				tls_sni_count: z.number().int().nonnegative(),
				/** Protocol distribution (frame.protocols column counts). */
				protocol_distribution: z.array(protocolCount),
				protocol_count: z.number().int().nonnegative(),
				/** HTTP request URIs seen on plain-text ports, bounded. */
				http_request_uris: z.array(z.string().min(1)),
				http_request_uri_count: z.number().int().nonnegative(),
				http_uri_redaction_count: z.number().int().nonnegative(),
				unattributed_dns_addresses: z.array(z.string().min(1)),
				unattributed_dns_address_count: z.number().int().nonnegative(),
				unattributed_dns_packet_count: z.number().int().nonnegative(),
				coverage: z.enum(["complete", "partial"]),
				diagnostics: z.strictObject({
					capinfos_stderr: z.string(),
					tshark_stderr: z.string()
				}).optional()
			})
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/pcapCaptureView.js
var captureSchema, fields, pageShape, pcapViewRequestSchema, pcapViewPageSchema, pcapSummarySchema, parseParent, summarize, selectRows, projectPcapCaptureView;
function init_pcapCaptureView() {
	return (init_pcapCaptureView = __esmMin((() => {
		init_analysisViewErrors();
		init_pcapAnalysis();
		init_inputIssueProjection();
		init_result();
		init_analysisViewCoverage();
		init_analysisViewText();
		captureSchema = pcapResultSchemas.inspect_pcap_capture;
		fields = captureSchema.shape;
		pageShape = {
			kind: z.literal("pcap"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		};
		pcapViewRequestSchema = z.discriminatedUnion("facet", [
			z.strictObject({
				...pageShape,
				facet: z.enum([
					"endpoints",
					"dns-queries",
					"tls-sni",
					"protocols",
					"http-uris",
					"unattributed-addresses"
				])
			}),
			z.strictObject({
				...pageShape,
				facet: z.literal("dns-addresses"),
				query: z.string().min(1)
			}),
			z.strictObject({
				...pageShape,
				facet: z.literal("diagnostics"),
				stream: z.enum(["tshark", "capinfos"])
			})
		]);
		pcapViewPageSchema = z.discriminatedUnion("facet", [
			z.strictObject({
				facet: z.literal("endpoints"),
				items: fields.endpoints
			}),
			z.strictObject({
				facet: z.literal("dns-queries"),
				items: z.array(fields.dns_queries.element.omit({ response_addresses: true }).extend({ retained_response_address_count: z.number().int().nonnegative() }))
			}),
			z.strictObject({
				facet: z.literal("tls-sni"),
				items: fields.tls_sni_values
			}),
			z.strictObject({
				facet: z.literal("protocols"),
				items: fields.protocol_distribution
			}),
			z.strictObject({
				facet: z.literal("http-uris"),
				items: fields.http_request_uris
			}),
			z.strictObject({
				facet: z.literal("unattributed-addresses"),
				items: fields.unattributed_dns_addresses
			}),
			z.strictObject({
				facet: z.literal("dns-addresses"),
				items: fields.unattributed_dns_addresses
			}),
			z.strictObject({
				facet: z.literal("diagnostics"),
				text: z.string(),
				status: z.enum(["retained", "unknown"])
			})
		]);
		pcapSummarySchema = captureSchema.omit({
			endpoints: true,
			dns_queries: true,
			tls_sni_values: true,
			protocol_distribution: true,
			http_request_uris: true,
			unattributed_dns_addresses: true,
			diagnostics: true
		}).extend({
			retained_counts: z.strictObject({
				endpoints: z.number().int().nonnegative(),
				dns_queries: z.number().int().nonnegative(),
				tls_sni_values: z.number().int().nonnegative(),
				protocol_distribution: z.number().int().nonnegative(),
				http_request_uris: z.number().int().nonnegative(),
				unattributed_dns_addresses: z.number().int().nonnegative()
			}),
			diagnostics_code_units: z.strictObject({
				tshark: z.number().int().nonnegative(),
				capinfos: z.number().int().nonnegative()
			}).nullable()
		});
		parseParent = (parent) => {
			const parsed = captureSchema.safeParse(parent.normalizedResult);
			if (!parsed.success) return err(analysisInputErrorFromIssues("inspect_analysis_view", parsed.error.issues, parent.normalizedResult, { cause: parsed.error }));
			if (parent.subject?.local_path !== parsed.data.target.path || parent.subject.digest.sha256 !== parsed.data.target.sha256) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Packet parent subject must identify the report's exact path and SHA-256."
			}]));
			return ok(parsed.data);
		};
		summarize = ({ endpoints, dns_queries, tls_sni_values, protocol_distribution, http_request_uris, unattributed_dns_addresses, diagnostics, ...metadata }) => ({
			...metadata,
			retained_counts: {
				endpoints: endpoints.length,
				dns_queries: dns_queries.length,
				tls_sni_values: tls_sni_values.length,
				protocol_distribution: protocol_distribution.length,
				http_request_uris: http_request_uris.length,
				unattributed_dns_addresses: unattributed_dns_addresses.length
			},
			diagnostics_code_units: diagnostics === undefined ? null : {
				tshark: diagnostics.tshark_stderr.length,
				capinfos: diagnostics.capinfos_stderr.length
			}
		});
		selectRows = (capture, view) => {
			const slice = (items) => items.slice(view.offset, view.offset + view.limit);
			switch (view.facet) {
				case "endpoints": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.endpoints)
					},
					total: capture.endpoints.length
				});
				case "dns-queries": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.dns_queries).map(({ response_addresses, ...query }) => ({
							...query,
							retained_response_address_count: response_addresses.length
						}))
					},
					total: capture.dns_queries.length
				});
				case "tls-sni": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.tls_sni_values)
					},
					total: capture.tls_sni_values.length
				});
				case "protocols": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.protocol_distribution)
					},
					total: capture.protocol_distribution.length
				});
				case "http-uris": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.http_request_uris)
					},
					total: capture.http_request_uris.length
				});
				case "unattributed-addresses": return ok({
					page: {
						facet: view.facet,
						items: slice(capture.unattributed_dns_addresses)
					},
					total: capture.unattributed_dns_addresses.length
				});
				case "dns-addresses": {
					const matches = capture.dns_queries.filter((query) => query.query === view.query);
					if (matches.length !== 1) return err(analysisViewInputError([{
						path: ["view", "query"],
						reason: "invalid_value",
						message: "Select one unambiguous exact retained DNS question."
					}]));
					return ok({
						page: {
							facet: view.facet,
							items: slice(matches[0].response_addresses)
						},
						total: matches[0].response_addresses.length
					});
				}
			}
		};
		projectPcapCaptureView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "pcap") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Packet summary parents support summary and pcap fact pages."
			}]));
			const parsed = parseParent(parent);
			if (!parsed.ok) return parsed;
			const capture = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_pcap_capture",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: capture.target.path,
					sha256: capture.target.sha256
				},
				limitations: [...parent.limitations, "Page totals count retained rows or UTF-16 diagnostic code units. Exhaustion does not prove whole-network completeness; source coverage and examined counts remain separate."],
				unknowns: ["Saved packet observations do not establish process identity, causality, encrypted payload contents or traffic missing from the recording."]
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: summarize(capture),
				coverage: completeWithinViewCoverage(1, 1)
			});
			if (view.facet === "diagnostics") {
				const value = view.stream === "tshark" ? capture.diagnostics?.tshark_stderr : capture.diagnostics?.capinfos_stderr;
				const text = analysisTextPage(value ?? "", view.offset, view.limit, "Diagnostics");
				if (!text.ok) return text;
				return ok({
					kind: "pcap",
					view,
					...shared,
					source_coverage: capture.coverage,
					page: {
						facet: "diagnostics",
						text: text.value.item.text,
						status: value === undefined ? "unknown" : "retained"
					},
					coverage: text.value.coverage,
					unknowns: value === undefined ? [...shared.unknowns, "The parent did not retain diagnostics; an empty text page does not establish their absence."] : shared.unknowns
				});
			}
			const selected = selectRows(capture, view);
			return selected.ok ? ok({
				kind: "pcap",
				view,
				...shared,
				source_coverage: capture.coverage,
				page: selected.value.page,
				coverage: pageViewCoverage(view.offset, selected.value.page.items.length, selected.value.total)
			}) : selected;
		};
	})))();
}

//#endregion
//#region dist/domain/android/androidAnalysis.js
var target, classTarget, androidInputSchemas, androidPackageInspectionInputSchema, androidRequestSchema, textCoverage, dexDescriptorSchema, method, engine, common, androidResultSchemas;
function init_androidAnalysis() {
	return (init_androidAnalysis = __esmMin((() => {
		init_localPath();
		target = { path: localPathStringSchema.describe("Local APK path; the target is never executed") };
		classTarget = {
			...target,
			class_name: z.string().min(1).describe("Exact fully qualified class name")
		};
		androidInputSchemas = {
			inspect_android_package: z.strictObject(target),
			search_android_classes: z.strictObject({
				...target,
				query: z.string().describe("Case-sensitive class-name substring; empty lists all classes")
			}),
			inspect_android_class: z.strictObject(classTarget),
			inspect_android_method: z.strictObject({
				...classTarget,
				method_name: z.string().min(1),
				overload_index: z.number().int().nonnegative().optional().describe("Explicit index among same-name methods; required when ambiguous")
			}),
			trace_android_references: z.strictObject({
				...classTarget,
				method_name: z.string().min(1).optional().describe("Omit for class references; select ambiguous methods with overload_index"),
				overload_index: z.number().int().nonnegative().optional().describe("Index among same-name methods from inspect_android_class; requires method_name")
			})
		};
		androidPackageInspectionInputSchema = androidInputSchemas.inspect_android_package.extend({ detail: z.enum(["complete", "summary"]).optional() });
		androidRequestSchema = z.discriminatedUnion("operation", [
			z.strictObject({
				operation: z.literal("inspect_android_package"),
				input: androidInputSchemas.inspect_android_package
			}),
			z.strictObject({
				operation: z.literal("search_android_classes"),
				input: androidInputSchemas.search_android_classes
			}),
			z.strictObject({
				operation: z.literal("inspect_android_class"),
				input: androidInputSchemas.inspect_android_class
			}),
			z.strictObject({
				operation: z.literal("inspect_android_method"),
				input: androidInputSchemas.inspect_android_method
			}),
			z.strictObject({
				operation: z.literal("trace_android_references"),
				input: androidInputSchemas.trace_android_references
			})
		]);
		textCoverage = z.strictObject({
			status: z.enum(["complete", "partial"]),
			text: z.string(),
			reported_total_bytes: z.number().int().nonnegative().nullable()
		});
		dexDescriptorSchema = z.string().regex(/^\((?:\[*(?:[ZBSCIJFD]|L[^;\x28\x29]+;))*\)(?:V|\[*(?:[ZBSCIJFD]|L[^;\x28\x29]+;))$/u);
		method = z.strictObject({
			name: z.string(),
			reported_signature: z.string(),
			overload_index: z.number().int().nonnegative(),
			is_constructor: z.boolean(),
			dex_descriptor: dexDescriptorSchema
		});
		engine = z.strictObject({
			name: z.string().min(1),
			version: z.string().nullable(),
			artifact_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			source_revision: z.string().nullable(),
			worker_count: z.number().int().positive(),
			heap_limit_mib: z.number().int().positive().nullable()
		});
		common = { engine };
		androidResultSchemas = {
			inspect_android_package: z.strictObject({
				...common,
				package_name: z.string().nullable(),
				version_name: z.string().nullable(),
				version_code: z.string().nullable(),
				min_sdk: z.string().nullable(),
				target_sdk: z.string().nullable(),
				permissions: z.array(z.string()),
				manifest: textCoverage,
				class_count: z.number().int().nonnegative(),
				resource_count: z.number().int().nonnegative(),
				signature_verification: z.literal("not_performed")
			}),
			search_android_classes: z.strictObject({
				...common,
				query: z.string(),
				total_classes: z.number().int().nonnegative(),
				matches: z.array(z.string()),
				duplicate_names: z.array(z.strictObject({
					name: z.string(),
					occurrences: z.number().int().min(2)
				})),
				coverage: z.literal("complete")
			}),
			inspect_android_class: z.strictObject({
				...common,
				class_name: z.string(),
				methods: z.array(method),
				fields: z.array(z.strictObject({
					name: z.string(),
					reported_type: z.string()
				})),
				inner_classes: z.array(z.string())
			}),
			inspect_android_method: z.strictObject({
				...common,
				class_name: z.string(),
				method,
				overload_count: z.number().int().positive(),
				representation: z.enum(["java", "smali"]),
				body_status: z.enum(["available", "not_available"]),
				fell_back: z.boolean(),
				markers: z.array(z.string()),
				source: textCoverage
			}),
			trace_android_references: z.strictObject({
				...common,
				class_name: z.string(),
				method_name: z.string().nullable(),
				overload_index: z.number().int().nonnegative().nullable(),
				reported_signature: z.string().nullable(),
				dex_descriptor: dexDescriptorSchema.nullable(),
				total: z.number().int().nonnegative(),
				references: z.array(z.strictObject({
					kind: z.string(),
					name: z.string(),
					reported_full_name: z.string(),
					containing_class: z.string(),
					top_class: z.string(),
					source_line: z.null(),
					dex_offset: z.null(),
					/** false means transport-bounded instruction evidence; null is unknown. */
					direct_invokes_exhaustive: z.boolean().nullable(),
					/** Raw direct invoke instructions inside this using node, when available. */
					direct_invokes: z.array(z.strictObject({
						dex_entry: z.string().min(1),
						source_raw_method_id: z.string().min(1),
						dex_code_unit_offset: z.number().int().nonnegative(),
						dex_method_index: z.number().int().nonnegative(),
						opcode: z.string().regex(/^INVOKE_/u)
					})).nullable()
				})),
				coverage: z.literal("complete"),
				reference_unit: z.literal("using_node")
			})
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/androidPackageView.js
var packageSchema, androidPackageSummarySchema, androidViewRequestSchema, androidManifestViewItemSchema, projectAndroidPackageView;
function init_androidPackageView() {
	return (init_androidPackageView = __esmMin((() => {
		init_analysisViewErrors();
		init_androidAnalysis();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		init_analysisViewText();
		packageSchema = androidResultSchemas.inspect_android_package;
		androidPackageSummarySchema = packageSchema.extend({ manifest: packageSchema.shape.manifest.omit({ text: true }).extend({
			text_code_units: z.number().int().nonnegative(),
			text_included: z.literal(false)
		}) });
		androidViewRequestSchema = z.strictObject({
			kind: z.literal("android"),
			facet: z.literal("manifest"),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive()
		});
		androidManifestViewItemSchema = z.strictObject({
			text: z.string(),
			unit: z.literal("utf16-code-units"),
			source_status: packageSchema.shape.manifest.shape.status,
			reported_total_bytes: packageSchema.shape.manifest.shape.reported_total_bytes
		});
		projectAndroidPackageView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "android") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Android package Evidence supports summary and manifest views."
			}]));
			const parsed = parseAnalysisViewResult(packageSchema, parent);
			if (!parsed.ok) return parsed;
			if (parent.subject == null) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "Android package views require the recorded APK subject identity."
			}]));
			const report = parsed.value;
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_android_package",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: parent.subject.local_path,
					sha256: parent.subject.digest.sha256
				},
				limitations: [...parent.limitations],
				unknowns: ["APK signatures were not verified; package declarations do not establish authenticity or runtime behavior.", ...report.manifest.status === "partial" ? ["The decoded manifest is partial; exhausting retained text does not establish complete manifest coverage."] : []]
			};
			if (view.kind === "summary") {
				const { text, ...manifest } = report.manifest;
				return ok({
					kind: "summary",
					view,
					...shared,
					summary: {
						...report,
						manifest: {
							...manifest,
							text_code_units: text.length,
							text_included: false
						}
					},
					coverage: completeWithinViewCoverage(1, 1)
				});
			}
			const page = analysisTextPage(report.manifest.text, view.offset, view.limit, "Manifest");
			if (!page.ok) return page;
			return ok({
				kind: "android",
				view,
				...shared,
				item: {
					...page.value.item,
					source_status: report.manifest.status,
					reported_total_bytes: report.manifest.reported_total_bytes
				},
				coverage: page.value.coverage
			});
		};
	})))();
}

//#endregion
//#region dist/domain/flutter/flutterBuildAnalysis.js
var MAX_FLUTTER_LIBRARY_PATH_BYTES, ABI_SELECTOR_MAX_CHARACTERS, ABI_SELECTOR_MESSAGE, abiSelectorSchema, flutterInputSchemas, dartAotInspectionInputSchema, flutterRequestSchema, flutterResultSchemas;
function init_flutterBuildAnalysis() {
	return (init_flutterBuildAnalysis = __esmMin((() => {
		init_localPath();
		init_digests();
		MAX_FLUTTER_LIBRARY_PATH_BYTES = 1024;
		ABI_SELECTOR_MAX_CHARACTERS = MAX_FLUTTER_LIBRARY_PATH_BYTES - "lib/".length - "/libapp.so".length;
		ABI_SELECTOR_MESSAGE = `ABI must be the exact lib/ directory label: 1–${String(ABI_SELECTOR_MAX_CHARACTERS)} Unicode characters without '/'.`;
		abiSelectorSchema = z.string().min(1, ABI_SELECTOR_MESSAGE).refine((label) => {
			const characters = label[Symbol.iterator]();
			for (let count = 0; count <= ABI_SELECTOR_MAX_CHARACTERS; count += 1) if (characters.next().done) return true;
			return false;
		}, {
			message: ABI_SELECTOR_MESSAGE,
			abort: true
		}).regex(/^[^\/]*$/u, ABI_SELECTOR_MESSAGE).meta({ maxLength: ABI_SELECTOR_MAX_CHARACTERS });
		flutterInputSchemas = {
			identify_flutter_build: z.strictObject({ path: localPathStringSchema.describe("Local APK file to inspect") }),
			inspect_dart_aot: z.strictObject({
				path: localPathStringSchema.describe("Local APK file carrying a Flutter AOT payload"),
				abi: abiSelectorSchema.optional().describe("Exact lib/ directory label reported by identify_flutter_build; defaults to arm64-v8a, x86_64, x86, armeabi-v7a, then remaining ABIs alphabetically")
			})
		};
		dartAotInspectionInputSchema = flutterInputSchemas.inspect_dart_aot.extend({ detail: z.enum(["complete", "summary"]).optional() });
		flutterRequestSchema = z.discriminatedUnion("operation", [z.strictObject({
			operation: z.literal("identify_flutter_build"),
			input: flutterInputSchemas.identify_flutter_build
		}), z.strictObject({
			operation: z.literal("inspect_dart_aot"),
			input: flutterInputSchemas.inspect_dart_aot
		})]);
		flutterResultSchemas = {
			identify_flutter_build: z.strictObject({
				target: z.strictObject({
					path: localPathStringSchema,
					bytes: z.number().int().nonnegative(),
					sha256: digestSchema
				}),
				flutter_detected: z.boolean(),
				abis: z.array(z.strictObject({
					abi: z.string().min(1),
					libapp: z.strictObject({
						present: z.boolean(),
						bytes: z.number().int().nonnegative().nullable(),
						sha256: digestSchema.nullable(),
						/** Supported ELF header with table extents inside the library; table contents are not validated. */
						elf_header_valid: z.boolean().nullable(),
						/** Number of Dart snapshot sections found (vm + isolate). */
						snapshot_hash_sources: z.number().int().nonnegative(),
						/** Distinct hashes found; more than one means the sections disagree. */
						snapshot_hash_candidates: z.array(z.string().regex(/^[0-9a-f]{32}$/u)),
						/** The single hash when every snapshot section agrees. */
						snapshot_hash: z.string().regex(/^[0-9a-f]{32}$/u).nullable()
					}),
					libflutter: z.strictObject({
						present: z.boolean(),
						bytes: z.number().int().nonnegative().nullable(),
						sha256: digestSchema.nullable(),
						build_id: z.string().regex(/^[0-9a-f]{8,128}$/u).nullable().describe("The single GNU build ID when ELF note coverage is complete and unambiguous"),
						build_id_candidates: z.array(z.string().regex(/^[0-9a-f]{8,128}$/u)).max(64).describe("Distinct GNU build IDs observed in ELF-owned note ranges; conflicting IDs remain explicit"),
						dart_version: z.string().nullable().describe("Labeled 'Dart VM version' string, when a build carries one"),
						toolchain_lines: z.array(z.string().min(1)),
						/** Dart labels omitted by grammar or single-version projection bounds. */
						dart_version_capped: z.boolean(),
						/** Toolchain labels omitted by grammar or projection bounds. */
						toolchain_capped: z.boolean()
					})
				})),
				coverage: z.enum(["complete", "partial"])
			}),
			inspect_dart_aot: z.strictObject({
				target: z.strictObject({
					path: localPathStringSchema,
					bytes: z.number().int().nonnegative(),
					sha256: digestSchema
				}),
				abi: z.string().min(1),
				libapp: z.strictObject({
					coverage: z.enum(["complete", "partial"]).describe("Coverage of ELF symbols, independent data headers, AOT kind, extents and agreeing hashes"),
					bytes: z.number().int().nonnegative(),
					sha256: digestSchema,
					snapshot_hash: z.string().regex(/^[0-9a-f]{32}$/u).nullable(),
					/** Distinct hashes found; more than one means the sections disagree. */
					snapshot_hash_candidates: z.array(z.string().regex(/^[0-9a-f]{32}$/u)),
					/** Distinct exported data headers with a valid hash at the header's fixed offset. */
					snapshot_hash_sources: z.number().int().nonnegative(),
					/** Snapshot symbols read from the dynamic symbol table. */
					sections: z.array(z.strictObject({
						name: z.string().min(1),
						offset: z.number().int().nonnegative(),
						size: z.number().int().nonnegative(),
						magic_valid: z.boolean(),
						kind: z.number().int().nonnegative().nullable(),
						/** Raw declared snapshot length, excluding the four magic bytes. */
						header_length: z.number().int().nonnegative().nullable()
					}))
				}),
				string_pool: z.strictObject({
					coverage: z.enum(["complete", "partial"]).describe("Coverage of the bounded printable-run projection; independent of snapshot header validity"),
					/** Distinct package: source URIs, sorted, bounded. */
					package_uris: z.array(z.string().min(1)),
					package_uri_count_at_least: z.number().int().nonnegative(),
					/** Distinct dart: SDK URIs, sorted, bounded. */
					dart_uris: z.array(z.string().min(1)),
					dart_uri_count_at_least: z.number().int().nonnegative(),
					/** Identifier-like tokens, bounded; includes incidental matches. */
					class_like_tokens: z.array(z.string().min(1)),
					class_like_token_count_at_least: z.number().int().nonnegative(),
					printable_run_count: z.number().int().nonnegative()
				}),
				coverage: z.enum(["complete", "partial"])
			})
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/dartAotView.js
var aotSchema, dartAotSummarySchema, dartAotViewRequestSchema, dartAotViewContextSchema, projectDartAotView;
function init_dartAotView() {
	return (init_dartAotView = __esmMin((() => {
		init_analysisViewErrors();
		init_flutterBuildAnalysis();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		aotSchema = flutterResultSchemas.inspect_dart_aot;
		dartAotSummarySchema = aotSchema.extend({ string_pool: aotSchema.shape.string_pool.omit({
			package_uris: true,
			dart_uris: true,
			class_like_tokens: true
		}).extend({ returned_counts: z.strictObject({
			package_uris: z.number().int().nonnegative(),
			dart_uris: z.number().int().nonnegative(),
			class_like_tokens: z.number().int().nonnegative()
		}) }) });
		dartAotViewRequestSchema = z.strictObject({
			kind: z.literal("dart-aot"),
			collection: z.enum([
				"package_uris",
				"dart_uris",
				"class_like_tokens"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		dartAotViewContextSchema = z.strictObject({
			abi: aotSchema.shape.abi,
			libapp: aotSchema.shape.libapp,
			source_coverage: aotSchema.shape.coverage,
			string_pool: dartAotSummarySchema.shape.string_pool
		});
		projectDartAotView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "dart-aot") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "Dart AOT Evidence supports summary and string-pool pages."
			}]));
			const parsed = parseAnalysisViewResult(aotSchema, parent);
			if (!parsed.ok) return parsed;
			const report = parsed.value;
			const { package_uris, dart_uris, class_like_tokens, ...pool } = report.string_pool;
			const string_pool = {
				...pool,
				returned_counts: {
					package_uris: package_uris.length,
					dart_uris: dart_uris.length,
					class_like_tokens: class_like_tokens.length
				}
			};
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_dart_aot",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.target.path,
					sha256: report.target.sha256
				},
				limitations: [...parent.limitations],
				unknowns: [
					"String-pool entries are byte-pattern observations, not recovered typed classes or functions.",
					"Counts ending in _at_least remain lower bounds; exhausting returned strings does not establish a complete snapshot inventory.",
					...parent.subject == null ? ["The parent has no recorded subject; its normalized target identity cannot be cross-checked against a subject digest."] : []
				]
			};
			if (view.kind === "summary") return ok({
				kind: "summary",
				view,
				...shared,
				summary: {
					...report,
					string_pool
				},
				coverage: completeWithinViewCoverage(1, 1)
			});
			const collection = report.string_pool[view.collection];
			const items = collection.slice(view.offset, view.offset + view.limit);
			return ok({
				kind: "dart-aot",
				view,
				...shared,
				items,
				abi: report.abi,
				libapp: report.libapp,
				source_coverage: report.coverage,
				string_pool,
				coverage: pageViewCoverage(view.offset, items.length, collection.length)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/il2cpp/il2cppMetadata.js
var IL2CPP_METADATA_MAGIC, IL2CPP_METADATA_SECTION_NAMES, IL2CPP_METADATA_V27_SECTION_NAMES, IL2CPP_METADATA_V24_SECTION_NAMES, IL2CPP_METADATA_VERSIONS, il2cppMetadataSectionNames, count, optionalIndex, indexWidth, inspectIl2cppMetadataInputSchema, il2cppMetadataSectionSchema, il2cppMetadataImageSchema, il2cppMetadataTypeSchema, il2cppMetadataMethodSchema, il2cppMetadataMemberSchema, il2cppMetadataParameterSchema, il2cppMetadataStringLiteralSchema, addressPattern, il2cppAddressSchema, IL2CPP_METHOD_ADDRESS_STATES, il2cppMethodAddressSchema, il2cppTypeReferenceSchema, il2cppCodeGenModuleSchema, il2cppBinaryLinkSchema, il2cppMetadataObjectSchema, il2cppMetadataMemberCollections, il2cppMetadataBinaryCollections, il2cppMetadataParentObjectSchema, validateMetadataFacts, il2cppMetadataSchema, il2cppMetadataParentSchema;
function init_il2cppMetadata() {
	return (init_il2cppMetadata = __esmMin((() => {
		init_digests();
		init_localPath();
		init_stringPatterns();
		IL2CPP_METADATA_MAGIC = 4205910959;
		IL2CPP_METADATA_SECTION_NAMES = [
			"stringLiterals",
			"stringLiteralData",
			"strings",
			"events",
			"properties",
			"methods",
			"parameterDefaultValues",
			"fieldDefaultValues",
			"fieldAndParameterDefaultValueData",
			"fieldMarshaledSizes",
			"parameters",
			"fields",
			"genericParameters",
			"genericParameterConstraints",
			"genericContainers",
			"nestedTypes",
			"interfaces",
			"vtableMethods",
			"interfaceOffsets",
			"typeDefinitions",
			"images",
			"assemblies",
			"fieldRefs",
			"referencedAssemblies",
			"attributeData",
			"attributeDataRanges",
			"unresolvedIndirectCallParameterTypes",
			"unresolvedIndirectCallParameterRanges",
			"windowsRuntimeTypeNames",
			"windowsRuntimeStrings",
			"exportedTypeDefinitions"
		];
		IL2CPP_METADATA_V27_SECTION_NAMES = [
			...IL2CPP_METADATA_SECTION_NAMES.slice(0, 24),
			"attributesInfo",
			"attributeTypes",
			"unresolvedVirtualCallParameterTypes",
			"unresolvedVirtualCallParameterRanges",
			...IL2CPP_METADATA_SECTION_NAMES.slice(28)
		];
		IL2CPP_METADATA_V24_SECTION_NAMES = [
			...IL2CPP_METADATA_SECTION_NAMES.slice(0, 22),
			"metadataUsageLists",
			"metadataUsagePairs",
			"fieldRefs",
			"referencedAssemblies",
			"attributesInfo",
			"attributeTypes",
			"unresolvedVirtualCallParameterTypes",
			"unresolvedVirtualCallParameterRanges",
			"windowsRuntimeTypeNames",
			"exportedTypeDefinitions"
		];
		IL2CPP_METADATA_VERSIONS = [
			24,
			27,
			29,
			31,
			39
		];
		il2cppMetadataSectionNames = (version) => version === 24 ? IL2CPP_METADATA_V24_SECTION_NAMES : version === 27 ? IL2CPP_METADATA_V27_SECTION_NAMES : IL2CPP_METADATA_SECTION_NAMES;
		count = z.number().int().nonnegative();
		optionalIndex = z.number().int().min(-1);
		indexWidth = z.union([
			z.literal(1),
			z.literal(2),
			z.literal(4)
		]);
		inspectIl2cppMetadataInputSchema = z.strictObject({
			path: localPathStringSchema.describe("Absolute filesystem path to a Unity IL2CPP global-metadata.dat file"),
			detail: z.enum(["complete", "summary"]).default("summary").describe("summary (default) retains complete Evidence and returns identity and collection counts; complete returns every image, type, method, member, parameter and string-literal row inline"),
			binary_path: localPathStringSchema.optional().describe("Absolute path to the caller-selected matching 64-bit IL2CPP binary (Mach-O GameAssembly.dylib, PE GameAssembly.dll or ELF libil2cpp.so); static reading, never executed"),
			binary_architecture: z.enum(["arm64", "amd64"]).optional().describe("Slice to read from a universal Mach-O binary_path; required for universal binaries and rejected otherwise")
		});
		il2cppMetadataSectionSchema = z.strictObject({
			name: z.enum([
				...IL2CPP_METADATA_SECTION_NAMES,
				"attributesInfo",
				"attributeTypes",
				"unresolvedVirtualCallParameterTypes",
				"unresolvedVirtualCallParameterRanges",
				"metadataUsageLists",
				"metadataUsagePairs"
			]),
			offset: count,
			size: count,
			/** Header-recorded entry count; versions 29 and 31 record none. */
			count: count.nullable()
		});
		il2cppMetadataImageSchema = z.strictObject({
			name: z.string(),
			type_start: optionalIndex,
			type_count: count
		});
		il2cppMetadataTypeSchema = z.strictObject({
			name: z.string(),
			namespace: z.string(),
			method_start: optionalIndex,
			method_count: count,
			nested_type_start: optionalIndex,
			nested_type_count: count,
			/** Enclosing type derived from the nestedTypes section. */
			declaring_type: optionalIndex.describe("Enclosing TypeDefinitionIndex derived from nestedTypes; -1 means no enclosing metadata type was recorded")
		});
		il2cppMetadataMethodSchema = z.strictObject({
			name: z.string(),
			declaring_type: optionalIndex.describe("Declared TypeDefinitionIndex from this MethodDefinition; -1 is an absent reference")
		});
		il2cppMetadataMemberSchema = z.strictObject({
			name: z.string(),
			/** -1 when no type range claims the row. */
			declaring_type: optionalIndex
		});
		il2cppMetadataParameterSchema = z.strictObject({
			name: z.string(),
			/** -1 when no method range claims the row. */
			method: optionalIndex
		});
		il2cppMetadataStringLiteralSchema = z.strictObject({
			value: z.string().nullable(),
			value_base64: canonicalBase64Schema.nullable()
		});
		addressPattern = /^0x[0-9a-f]{1,16}$/u;
		il2cppAddressSchema = z.string().regex(addressPattern);
		IL2CPP_METHOD_ADDRESS_STATES = [
			"code",
			"no-body",
			"unknown"
		];
		il2cppMethodAddressSchema = z.strictObject({
			state: z.enum(IL2CPP_METHOD_ADDRESS_STATES),
			/** Null unless state is code. */
			address: il2cppAddressSchema.nullable(),
			rva: il2cppAddressSchema.nullable()
		});
		il2cppTypeReferenceSchema = z.strictObject({
			type: optionalIndex,
			/** Null for type index -1, and for every row of a version 27 report. */
			name: z.string().nullable()
		});
		il2cppCodeGenModuleSchema = z.strictObject({
			image: count,
			address: il2cppAddressSchema,
			method_pointer_count: count
		});
		il2cppBinaryLinkSchema = z.strictObject({
			artifact: z.strictObject({
				path: localPathStringSchema,
				sha256: digestSchema,
				bytes: count
			}),
			format: z.enum([
				"elf",
				"macho",
				"pe"
			]),
			architecture: z.string(),
			image_base: il2cppAddressSchema,
			/**
			* CodeRegistration's codeGenModulesCount field, followed by the module array
			* pointer; null when no static pair was resolved and executable byte-pattern
			* candidates identified the array without verified instruction boundaries.
			*/
			code_gen_modules_field: il2cppAddressSchema.nullable(),
			/** The code-generation module pointer array. */
			code_gen_modules_array: il2cppAddressSchema,
			code_gen_modules: z.array(il2cppCodeGenModuleSchema),
			/** MetadataRegistration's typesCount field, followed by the types pointer. */
			types_field: il2cppAddressSchema,
			types_count: count
		});
		il2cppMetadataObjectSchema = z.strictObject({
			artifact: z.strictObject({
				path: localPathStringSchema,
				sha256: digestSchema,
				bytes: count
			}),
			magic: z.literal(IL2CPP_METADATA_MAGIC),
			metadata_version: z.union(IL2CPP_METADATA_VERSIONS.map((version) => z.literal(version))),
			index_widths: z.strictObject({
				type_definition: indexWidth,
				generic_container: indexWidth,
				parameter: indexWidth,
				type: indexWidth,
				type_width_source: z.enum([
					"interface-offsets-record",
					"type-definition-record",
					"fixed-width-version"
				])
			}),
			sections: z.array(il2cppMetadataSectionSchema),
			images: z.array(il2cppMetadataImageSchema),
			types: z.array(il2cppMetadataTypeSchema),
			methods: z.array(il2cppMetadataMethodSchema),
			fields: z.array(il2cppMetadataMemberSchema),
			properties: z.array(il2cppMetadataMemberSchema),
			events: z.array(il2cppMetadataMemberSchema),
			parameters: z.array(il2cppMetadataParameterSchema),
			string_literals: z.array(il2cppMetadataStringLiteralSchema),
			/** Null unless binary_path was selected. */
			binary: il2cppBinaryLinkSchema.nullable(),
			/** One row per method index when binary is linked, otherwise empty. */
			method_addresses: z.array(il2cppMethodAddressSchema),
			/** Per method, field and parameter index when binary is linked, otherwise empty. */
			return_types: z.array(il2cppTypeReferenceSchema),
			field_types: z.array(il2cppTypeReferenceSchema),
			parameter_types: z.array(il2cppTypeReferenceSchema),
			limitations: z.array(z.string())
		});
		il2cppMetadataMemberCollections = [
			"fields",
			"properties",
			"events",
			"parameters",
			"string_literals"
		];
		il2cppMetadataBinaryCollections = [
			"method_addresses",
			"return_types",
			"field_types",
			"parameter_types"
		];
		il2cppMetadataParentObjectSchema = il2cppMetadataObjectSchema.partial({
			fields: true,
			properties: true,
			events: true,
			parameters: true,
			string_literals: true,
			binary: true,
			method_addresses: true,
			return_types: true,
			field_types: true,
			parameter_types: true
		});
		validateMetadataFacts = (report, context) => {
			const names = il2cppMetadataSectionNames(report.metadata_version);
			if (report.sections.length !== names.length) context.addIssue({
				code: "custom",
				path: ["sections"],
				message: `Version ${report.metadata_version} headers have ${names.length} sections.`
			});
			report.sections.forEach((section, index) => {
				if (section.name !== names[index]) context.addIssue({
					code: "custom",
					path: [
						"sections",
						index,
						"name"
					],
					message: "Sections must follow header order."
				});
				if (section.offset + section.size > report.artifact.bytes) context.addIssue({
					code: "custom",
					path: ["sections", index],
					message: "Section range is outside the selected artifact."
				});
			});
			if (report.binary != null) for (const collection of [
				"return_types",
				"field_types",
				"parameter_types"
			]) report[collection]?.forEach((row, index) => {
				if (row.type >= report.binary.types_count || row.type === -1 && row.name !== null) context.addIssue({
					code: "custom",
					path: [collection, index],
					message: "Type reference is outside the linked type table or names an unavailable type."
				});
			});
			report.method_addresses?.forEach((row, index) => {
				if (row.state === "code" ? row.address === null || row.rva === null || report.binary == null || addressPattern.test(row.address) && addressPattern.test(row.rva) && addressPattern.test(report.binary.image_base) && BigInt(row.address) !== BigInt(report.binary.image_base) + BigInt(row.rva) : row.address !== null || row.rva !== null) context.addIssue({
					code: "custom",
					path: ["method_addresses", index],
					message: "Only a code row carries an address and RVA; both are then present."
				});
			});
			for (const collection of [
				"fields",
				"properties",
				"events"
			]) report[collection]?.forEach((row, index) => {
				if (row.declaring_type >= report.types.length) context.addIssue({
					code: "custom",
					path: [
						collection,
						index,
						"declaring_type"
					],
					message: "Member owner is outside the retained type definitions."
				});
			});
			report.parameters?.forEach((row, index) => {
				if (row.method >= report.methods.length) context.addIssue({
					code: "custom",
					path: [
						"parameters",
						index,
						"method"
					],
					message: "Parameter owner is outside the retained method definitions."
				});
			});
			const linkedRows = {
				method_addresses: report.methods,
				return_types: report.methods,
				field_types: report.fields,
				parameter_types: report.parameters
			};
			for (const collection of il2cppMetadataBinaryCollections) {
				const rows = report[collection];
				if (report.binary === undefined !== (rows === undefined)) {
					context.addIssue({
						code: "custom",
						path: [collection],
						message: `${collection} is retained exactly when the binary link field is.`
					});
					continue;
				}
				const owners = linkedRows[collection];
				if (rows === undefined) continue;
				const expected = report.binary === null ? 0 : owners?.length;
				if (expected === undefined || rows.length !== expected) context.addIssue({
					code: "custom",
					path: [collection],
					message: `A linked binary needs one ${collection} row per metadata row; none without one.`
				});
			}
			report.string_literals?.forEach((row, index) => {
				if (row.value === null === (row.value_base64 === null)) context.addIssue({
					code: "custom",
					path: ["string_literals", index],
					message: "A literal must retain exactly one UTF-8 or byte-exact base64 representation."
				});
			});
		};
		il2cppMetadataSchema = il2cppMetadataObjectSchema.superRefine(validateMetadataFacts);
		il2cppMetadataParentSchema = il2cppMetadataParentObjectSchema.superRefine(validateMetadataFacts);
	})))();
}

//#endregion
//#region dist/domain/analysisView/il2cppMetadataView.js
/** Direct batch lookup visits selected indices only; metadata order is stable. */
function* rowIndices(length, indices) {
	if (indices === undefined) {
		for (let index = 0; index < length; index++) yield index;
	} else {
		for (const index of [...new Set(indices)].sort((a, b) => a - b)) if (index < length) yield index;
	}
}
var countsSchema, il2cppMetadataSummarySchema, indexSchema, sectionRowSchema, imageRowSchema, typeRowSchema, methodRowSchema, memberRowSchema, parameterRowSchema, stringLiteralRowSchema, methodAddressRowSchema, typeReferenceRowSchema, codeGenModuleRowSchema, indexPage, page, declaringTypes, il2cppMetadataViewRequestSchema, il2cppMetadataViewItemsSchema, il2cppMetadataViewContextSchema, checkedReports, parseMetadataReport, selectFields, selection, projectIl2cppMetadataView;
function init_il2cppMetadataView() {
	return (init_il2cppMetadataView = __esmMin((() => {
		init_analysisViewErrors();
		init_immutableJson();
		init_il2cppMetadata();
		init_result();
		init_analysisViewParent();
		init_analysisViewCoverage();
		countsSchema = z.strictObject({
			sections: z.number().int().nonnegative(),
			images: z.number().int().nonnegative(),
			types: z.number().int().nonnegative(),
			methods: z.number().int().nonnegative(),
			nested_types: z.number().int().nonnegative(),
			fields: z.number().int().nonnegative().nullable(),
			properties: z.number().int().nonnegative().nullable(),
			events: z.number().int().nonnegative().nullable(),
			parameters: z.number().int().nonnegative().nullable(),
			string_literals: z.number().int().nonnegative().nullable(),
			code_gen_modules: z.number().int().nonnegative().nullable(),
			method_addresses: z.number().int().nonnegative().nullable(),
			/** method_addresses rows per state; null when native observations were not collected. */
			method_address_states: z.strictObject({
				code: z.number().int().nonnegative(),
				no_body: z.number().int().nonnegative(),
				unknown: z.number().int().nonnegative()
			}).nullable(),
			return_types: z.number().int().nonnegative().nullable(),
			field_types: z.number().int().nonnegative().nullable(),
			parameter_types: z.number().int().nonnegative().nullable()
		});
		il2cppMetadataSummarySchema = il2cppMetadataObjectSchema.omit({
			sections: true,
			images: true,
			types: true,
			methods: true,
			fields: true,
			properties: true,
			events: true,
			parameters: true,
			string_literals: true,
			method_addresses: true,
			return_types: true,
			field_types: true,
			parameter_types: true,
			binary: true
		}).extend({
			binary: il2cppBinaryLinkSchema.omit({ code_gen_modules: true }).nullable().optional(),
			counts: countsSchema
		});
		indexSchema = z.number().int().nonnegative();
		sectionRowSchema = il2cppMetadataSectionSchema.extend({ index: indexSchema });
		imageRowSchema = il2cppMetadataImageSchema.extend({ index: indexSchema });
		typeRowSchema = il2cppMetadataTypeSchema.extend({ index: indexSchema });
		methodRowSchema = il2cppMetadataMethodSchema.extend({ index: indexSchema });
		memberRowSchema = il2cppMetadataMemberSchema.extend({ index: indexSchema });
		parameterRowSchema = il2cppMetadataParameterSchema.extend({ index: indexSchema });
		stringLiteralRowSchema = il2cppMetadataStringLiteralSchema.extend({ index: indexSchema });
		methodAddressRowSchema = il2cppMethodAddressSchema.extend({ index: indexSchema });
		typeReferenceRowSchema = il2cppTypeReferenceSchema.extend({ index: indexSchema });
		codeGenModuleRowSchema = il2cppCodeGenModuleSchema.extend({ index: indexSchema });
		indexPage = {
			kind: z.literal("il2cpp-metadata"),
			indices: z.array(indexSchema).optional(),
			offset: indexSchema.default(0),
			limit: z.number().int().positive().default(64)
		};
		page = {
			...indexPage,
			names: z.array(z.string()).optional()
		};
		declaringTypes = z.array(z.number().int().min(-1)).optional();
		il2cppMetadataViewRequestSchema = z.discriminatedUnion("collection", [
			z.strictObject({
				...page,
				collection: z.literal("sections"),
				fields: z.array(sectionRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...page,
				collection: z.literal("images"),
				fields: z.array(imageRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...page,
				collection: z.literal("types"),
				image_indices: z.array(indexSchema).optional(),
				namespaces: z.array(z.string()).optional(),
				declaring_types: declaringTypes,
				fields: z.array(typeRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...page,
				collection: z.literal("methods"),
				declaring_types: declaringTypes,
				fields: z.array(methodRowSchema.keyof()).optional()
			}),
			...[
				"fields",
				"properties",
				"events"
			].map((collection) => z.strictObject({
				...page,
				collection: z.literal(collection),
				declaring_types: declaringTypes,
				fields: z.array(memberRowSchema.keyof()).optional()
			})),
			z.strictObject({
				...page,
				collection: z.literal("parameters"),
				method_indices: z.array(indexSchema).optional(),
				fields: z.array(parameterRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...indexPage,
				collection: z.literal("string_literals"),
				fields: z.array(stringLiteralRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...indexPage,
				collection: z.literal("method_addresses"),
				addresses: z.array(z.string().regex(/^0x[0-9a-fA-F]{1,16}$/u)).optional(),
				states: z.array(il2cppMethodAddressSchema.shape.state).optional(),
				fields: z.array(methodAddressRowSchema.keyof()).optional()
			}),
			z.strictObject({
				...indexPage,
				collection: z.literal("code_gen_modules"),
				image_indices: z.array(indexSchema).optional(),
				fields: z.array(codeGenModuleRowSchema.keyof()).optional()
			}),
			...["return_types", "field_types"].map((collection) => z.strictObject({
				...indexPage,
				collection: z.literal(collection),
				fields: z.array(typeReferenceRowSchema.keyof()).optional()
			})),
			z.strictObject({
				...indexPage,
				collection: z.literal("parameter_types"),
				method_indices: z.array(indexSchema).optional(),
				fields: z.array(typeReferenceRowSchema.keyof()).optional()
			})
		]);
		il2cppMetadataViewItemsSchema = z.union([
			z.array(sectionRowSchema.partial().required({ index: true })),
			z.array(imageRowSchema.partial().required({ index: true })),
			z.array(typeRowSchema.partial().required({ index: true })),
			z.array(methodRowSchema.partial().required({ index: true })),
			z.array(memberRowSchema.partial().required({ index: true })),
			z.array(parameterRowSchema.partial().required({ index: true })),
			z.array(stringLiteralRowSchema.partial().required({ index: true })),
			z.array(methodAddressRowSchema.partial().required({ index: true })),
			z.array(typeReferenceRowSchema.partial().required({ index: true })),
			z.array(codeGenModuleRowSchema.partial().required({ index: true }))
		]);
		il2cppMetadataViewContextSchema = z.strictObject({
			metadata_version: il2cppMetadataObjectSchema.shape.metadata_version,
			counts: countsSchema,
			binary_source: il2cppBinaryLinkSchema.pick({
				artifact: true,
				format: true,
				architecture: true,
				image_base: true
			}).optional()
		});
		checkedReports = new WeakMap();
		parseMetadataReport = (parent) => {
			const key = parent.normalizedResult;
			const reusable = parent.sealedResult === true && typeof key === "object" && key !== null && isImmutableJsonSnapshot(key);
			const cached = reusable ? checkedReports.get(key) : undefined;
			if (cached !== undefined) return ok(cached);
			const parsed = parseAnalysisViewResult(il2cppMetadataParentSchema, parent);
			if (!parsed.ok) return parsed;
			const report = reusable ? key : parsed.value;
			const checked = {
				report,
				counts: {
					sections: report.sections.length,
					images: report.images.length,
					types: report.types.length,
					methods: report.methods.length,
					nested_types: report.types.reduce((count, type) => count + Number(type.declaring_type !== -1), 0),
					fields: report.fields?.length ?? null,
					properties: report.properties?.length ?? null,
					events: report.events?.length ?? null,
					parameters: report.parameters?.length ?? null,
					string_literals: report.string_literals?.length ?? null,
					code_gen_modules: report.binary?.code_gen_modules.length ?? null,
					method_addresses: report.binary == null ? null : report.method_addresses?.length ?? null,
					method_address_states: (report.binary == null ? undefined : report.method_addresses)?.reduce((states, row) => {
						if (row.state === "code") states.code++;
						else if (row.state === "no-body") states.no_body++;
						else states.unknown++;
						return states;
					}, {
						code: 0,
						no_body: 0,
						unknown: 0
					}) ?? null,
					return_types: report.binary == null ? null : report.return_types?.length ?? null,
					field_types: report.binary == null ? null : report.field_types?.length ?? null,
					parameter_types: report.binary == null ? null : report.parameter_types?.length ?? null
				}
			};
			if (reusable) checkedReports.set(key, checked);
			return ok(checked);
		};
		selectFields = (row, index, fields) => {
			const item = { index };
			const values = row;
			for (const key of Object.keys(values)) {
				const value = values[key];
				if (value !== undefined && (fields === undefined || fields.has(key))) item[key] = value;
			}
			return item;
		};
		selection = (view, report) => {
			const names = !("names" in view) || view.names === undefined ? undefined : new Set(view.names);
			const owners = !("declaring_types" in view) || view.declaring_types === undefined ? undefined : new Set(view.declaring_types);
			const addresses = view.collection === "method_addresses" && view.addresses !== undefined ? new Set(view.addresses.map((value) => BigInt(value).toString(16))) : undefined;
			const states = view.collection === "method_addresses" && view.states !== undefined ? new Set(view.states) : undefined;
			const methods = (view.collection === "parameters" || view.collection === "parameter_types") && view.method_indices !== undefined ? new Set(view.method_indices) : undefined;
			const parameterOwner = (row, index) => "method" in row ? row.method : view.collection === "parameter_types" ? report.parameters?.[index]?.method : undefined;
			const namespaces = view.collection !== "types" || view.namespaces === undefined ? undefined : new Set(view.namespaces);
			const imageIndices = view.collection === "types" ? view.image_indices : undefined;
			const ranges = [];
			if (imageIndices !== undefined) {
				const selected = [...new Set(imageIndices)].flatMap((index) => {
					const image = report.images[index];
					return image === undefined || image.type_count === 0 ? [] : [{
						start: image.type_start,
						end: image.type_start + image.type_count
					}];
				}).sort((a, b) => a.start - b.start);
				for (const range of selected) {
					const last = ranges.at(-1);
					if (last !== undefined && range.start <= last.end) last.end = Math.max(last.end, range.end);
					else ranges.push(range);
				}
			}
			const moduleImages = view.collection === "code_gen_modules" && view.image_indices !== undefined ? new Set(view.image_indices) : undefined;
			if ([
				moduleImages,
				addresses,
				states,
				names,
				owners,
				namespaces,
				methods,
				imageIndices
			].every((filter) => filter === undefined)) return undefined;
			return (row, index) => {
				if (moduleImages !== undefined && (!("image" in row) || !moduleImages.has(row.image))) return false;
				if (addresses !== undefined && (!("address" in row) || row.address === null || !addresses.has(BigInt(row.address).toString(16)))) return false;
				if (states !== undefined && (!("state" in row) || !states.has(row.state))) return false;
				if (names !== undefined && (!("name" in row) || row.name === null || !names.has(row.name))) return false;
				if (owners !== undefined && (!("declaring_type" in row) || !owners.has(row.declaring_type))) return false;
				if (namespaces !== undefined && (!("namespace" in row) || !namespaces.has(row.namespace))) return false;
				if (methods !== undefined && !methods.has(parameterOwner(row, index) ?? -1)) return false;
				if (imageIndices === undefined) return true;
				let lower = 0;
				let upper = ranges.length;
				while (lower < upper) {
					const middle = lower + Math.floor((upper - lower) / 2);
					if (ranges[middle].start <= index) lower = middle + 1;
					else upper = middle;
				}
				const range = ranges[lower - 1];
				return range !== undefined && index < range.end;
			};
		};
		projectIl2cppMetadataView = (parent, view) => {
			if (view.kind !== "summary" && view.kind !== "il2cpp-metadata") return err(analysisViewInputError([{
				path: ["view"],
				reason: "invalid_value",
				message: "IL2CPP metadata Evidence supports summary and selected sections, images, types, methods, member, parameter, string literal, method address and type reference pages."
			}]));
			const parsed = parseMetadataReport(parent);
			if (!parsed.ok) return parsed;
			const { report, counts } = parsed.value;
			if (parent.subject != null && (parent.subject.format !== "file" || parent.subject.local_path !== report.artifact.path || parent.subject.digest.sha256 !== report.artifact.sha256)) return err(analysisViewInputError([{
				path: ["source", "subject"],
				reason: "invalid_value",
				message: "IL2CPP metadata artifact identity does not match its parent subject."
			}]));
			const { sections, images, types, methods, fields, properties, events, parameters, string_literals, method_addresses, return_types, field_types, parameter_types, ...identity } = report;
			const allRows = {
				code_gen_modules: report.binary?.code_gen_modules,
				sections,
				images,
				types,
				methods,
				fields,
				properties,
				events,
				parameters,
				string_literals,
				method_addresses,
				return_types,
				field_types,
				parameter_types
			};
			const shared = {
				parent_evidence_id: parent.evidenceId,
				parent_operation: "inspect_il2cpp_metadata",
				parent_digest: parent.evidenceId.slice(3),
				artifact: {
					path: report.artifact.path,
					sha256: report.artifact.sha256
				},
				limitations: [...parent.limitations],
				unknowns: [
					...report.binary != null && report.binary.code_gen_modules_field === null ? ["Module-array association is inferred from executable byte patterns; instruction boundaries and runtime use remain unverified."] : [],
					...[...il2cppMetadataMemberCollections, ...il2cppMetadataBinaryCollections].filter((name) => report[name] === undefined).map((name) => `Retained Evidence did not collect ${name}; its count is unknown. Reinspect the metadata to acquire these facts.`),
					report.binary == null ? "Names come from unencrypted metadata only; native code addresses and runtime registration remain unknown." : "Addresses come from static binary tables; runtime behavior and generic instance code remain unknown.",
					...parent.subject == null ? ["The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest."] : []
				]
			};
			if (view.kind === "summary") {
				const binary = report.binary == null ? report.binary : (({ code_gen_modules: _modules, ...facts }) => facts)(report.binary);
				return ok({
					kind: "summary",
					view,
					...shared,
					summary: {
						...identity,
						...binary === undefined ? {} : { binary },
						counts
					},
					coverage: completeWithinViewCoverage(1, 1)
				});
			}
			const nativeUnavailable = report.binary == null && [
				"method_addresses",
				"return_types",
				"field_types",
				"parameter_types"
			].includes(view.collection);
			const rows = nativeUnavailable ? undefined : allRows[view.collection];
			if (rows === undefined) return err(analysisViewInputError([{
				path: ["view", "collection"],
				reason: "invalid_value",
				message: `Retained Evidence did not collect ${view.collection}; inspect the metadata again to acquire these facts.`
			}]));
			if (view.collection === "parameter_types" && view.method_indices !== undefined && report.parameters === undefined) return err(analysisViewInputError([{
				path: ["view", "method_indices"],
				reason: "invalid_value",
				message: "Retained Evidence did not collect parameters, so parameter owners are unknown; inspect the metadata again to select parameter types by method."
			}]));
			const matches = selection(view, report);
			const selectedFields = view.fields === undefined ? undefined : new Set(view.fields);
			const items = [];
			let total = 0;
			if (matches === undefined && view.indices === undefined) {
				total = rows.length;
				const end = Math.min(rows.length, view.offset + view.limit);
				for (let index = Math.min(view.offset, rows.length); index < end; index++) items.push(selectFields(rows[index], index, selectedFields));
			} else {
				for (const index of rowIndices(rows.length, view.indices)) {
					const row = rows[index];
					if (matches !== undefined && !matches(row, index)) continue;
					if (total >= view.offset && items.length < view.limit) items.push(selectFields(row, index, selectedFields));
					total++;
				}
			}
			return ok({
				kind: "il2cpp-metadata",
				view,
				...shared,
				items,
				metadata_version: report.metadata_version,
				...report.binary == null ? {} : { binary_source: {
					artifact: report.binary.artifact,
					format: report.binary.format,
					architecture: report.binary.architecture,
					image_base: report.binary.image_base
				} },
				counts,
				coverage: pageViewCoverage(view.offset, items.length, total)
			});
		};
	})))();
}

//#endregion
//#region dist/domain/analysisView/analysisView.js
var summaryViewSchema, facetViewSchema, indexSelectorSchema, nameSelectorSchema, pathSelectorSchema, nodeIdSelectorSchema, moduleItemViewSchema, sectionOrSymbolItemViewSchema, itemViewSchema, pageViewSchema, nativeViewSchema, analysisViewRequestSchema, inlineEvidenceInputSchema, analysisViewSourceSchema, inspectAnalysisViewInputSchema, coverageSchema, artifactSchema, layoutSummarySchema, javascriptSummarySchema, viewResultBase, summaryViewResultBase, gdbCommandSummaryViewResultSchema, objdumpSummaryViewResultSchema, fridaSessionStatusSummaryViewResultSchema, goBinarySummaryViewResultSchema, rustBinarySummaryViewResultSchema, rustBinaryPageViewResultSchema, binaryLayoutSummaryViewResultSchema, javascriptApplicationSummaryViewResultSchema, javascriptModuleReferencesViewResultSchema, javascriptFactsViewResultSchema, artifactInventorySummaryViewResultSchema, desktopApplicationSummaryViewResultSchema, wasmArtifactSummaryViewResultSchema, machoSummaryViewResultSchema, interfaceBuilderSummaryViewResultSchema, evmInterfaceSummaryViewResultSchema, managedArtifactSummaryViewResultSchema, managedMemberSummaryViewResultSchema, webNetworkCaptureSummaryViewResultSchema, androidPackageSummaryViewResultSchema, pcapCaptureSummaryViewResultSchema, dartAotSummaryViewResultSchema, modelArtifactSummaryViewResultSchema, modelArtifactPageViewResultSchema, il2cppMetadataSummaryViewResultSchema, nativeInventorySummaryViewResultSchema, nativeFunctionMatchingSummaryViewResultSchema, analysisViewResultSchema, sealAnalysisView, parentDigest, parseJavaScriptParent, unsupportedParent, parentArtifactPath, retainedViewProjectors, isGroupingView, projectGroupingView, projectAnalysisView;
function init_analysisView() {
	return (init_analysisView = __esmMin((() => {
		init_modelArtifactView();
		init_commandObservationView();
		init_fridaSessionStatusView();
		init_commandObservation();
		init_goBinaryView();
		init_rustBinaryView();
		init_nativeFunctionMatchingView();
		init_protobufCaptureView();
		init_nativeInventoryView();
		init_nativeInventory();
		init_localPath();
		init_desktopApplicationView();
		init_desktopApplication();
		init_javascriptModuleReferences();
		init_javascriptApplicationCoverage();
		init_javascriptFactsView();
		init_javascriptSourceSelection();
		init_analysisErrorCore();
		init_analysisViewErrors();
		init_canonicalDigest();
		init_digests();
		init_evidence();
		init_jsonValue();
		init_result();
		init_binaryLayout();
		init_bundleResourceRoot();
		init_hopperValues();
		init_artifactGraph();
		init_artifactInspection();
		init_javascriptApplicationAnalysis();
		init_inputIssueProjection();
		init_binaryLayoutView();
		init_javascriptApplicationView();
		init_webNetworkApiSurfaceView();
		init_nativeFunctionView();
		init_evmInterfaceView();
		init_artifactInventoryView();
		init_managedArtifactView();
		init_managedMemberView();
		init_wasmArtifactView();
		init_machoView();
		init_interfaceBuilderView();
		init_webNetworkCaptureView();
		init_environmentManifestView();
		init_environmentStateView();
		init_pcapCaptureView();
		init_qlogCaptureView();
		init_androidPackageView();
		init_dartAotView();
		init_il2cppMetadataView();
		summaryViewSchema = z.strictObject({ kind: z.literal("summary") });
		facetViewSchema = z.strictObject({
			kind: z.literal("facet"),
			facet: z.enum(["mitigations", "linkage"])
		});
		indexSelectorSchema = z.strictObject({ index: z.number().int().nonnegative() });
		nameSelectorSchema = z.strictObject({ name: z.string() });
		pathSelectorSchema = z.strictObject({ path: z.string().describe("Exact observed module path or original source-map reference from a module page; an empty reference is valid.") });
		nodeIdSelectorSchema = z.strictObject({ node_id: prefixedDigestSchema("jag_node") });
		moduleItemViewSchema = z.strictObject({
			kind: z.literal("item"),
			collection: z.literal("modules"),
			selector: z.union([pathSelectorSchema, nodeIdSelectorSchema])
		});
		sectionOrSymbolItemViewSchema = z.strictObject({
			kind: z.literal("item"),
			collection: z.enum(["sections", "symbols"]),
			selector: z.union([indexSelectorSchema, nameSelectorSchema])
		});
		itemViewSchema = z.discriminatedUnion("collection", [moduleItemViewSchema, sectionOrSymbolItemViewSchema]);
		pageViewSchema = z.strictObject({
			kind: z.literal("page"),
			collection: z.enum([
				"sections",
				"symbols",
				"modules"
			]),
			offset: z.number().int().nonnegative(),
			limit: z.number().int().positive()
		});
		nativeViewSchema = z.strictObject({
			kind: z.literal("native"),
			facet: z.enum([
				"procedure",
				"pseudocode",
				"assembly",
				"basic_blocks",
				"comments",
				"callers",
				"callees",
				"incoming_references",
				"outgoing_references",
				"unresolved_calls",
				"referenced_strings",
				"referenced_names",
				"swift_string_literals",
				"swift_string_literal_omissions",
				"native_api",
				"value_flow_summary",
				"value_flow_operations",
				"value_flow_def_use",
				"value_flow_effects",
				"value_flow_parameters",
				"value_flow_parameter_uses"
			]),
			offset: z.number().int().nonnegative().default(0),
			limit: z.number().int().positive().default(64)
		});
		analysisViewRequestSchema = z.discriminatedUnion("kind", [
			nativeFunctionMatchingViewRequestSchema,
			summaryViewSchema,
			goBinaryViewRequestSchema,
			rustBinaryViewRequestSchema,
			desktopViewRequestSchema,
			facetViewSchema,
			itemViewSchema,
			pageViewSchema,
			javascriptModuleReferencesRequestSchema,
			javascriptFactsViewRequestSchema,
			nativeViewSchema,
			nativeInventoryViewRequestSchema,
			artifactInventoryViewRequestSchema,
			wasmViewRequestSchema,
			machoViewRequestSchema,
			interfaceBuilderViewRequestSchema,
			evmViewRequestSchema,
			managedViewRequestSchema,
			managedMembersViewRequestSchema,
			androidViewRequestSchema,
			apiSurfaceViewSchema,
			environmentManifestViewRequestSchema,
			environmentStateViewRequestSchema,
			captureViewRequestSchema,
			protobufViewRequestSchema,
			qlogViewRequestSchema,
			pcapViewRequestSchema,
			dartAotViewRequestSchema,
			il2cppMetadataViewRequestSchema,
			modelArtifactViewRequestSchema
		]);
		inlineEvidenceInputSchema = z.unknown().nonoptional();
		inlineEvidenceInputSchema._zod.processJSONSchema = evidenceSchema._zod.processJSONSchema;
		analysisViewSourceSchema = z.discriminatedUnion("kind", [
			z.strictObject({
				kind: z.literal("retained-evidence"),
				evidence_id: prefixedDigestSchema("ev")
			}),
			z.strictObject({
				kind: z.literal("inline"),
				evidence: inlineEvidenceInputSchema
			}),
			z.strictObject({
				kind: z.literal("evidence-file"),
				path: absoluteLocalPathStringSchema.describe("Absolute local path of one completed Evidence JSON file. REA reads and authenticates it, then projects it like retained Evidence, so large captures are not charged as inline input.")
			})
		]);
		inspectAnalysisViewInputSchema = z.strictObject({
			source: analysisViewSourceSchema,
			view: analysisViewRequestSchema
		});
		coverageSchema = z.strictObject({
			status: z.enum([
				"complete-within-view",
				"page",
				"empty"
			]),
			examined: z.number().int().nonnegative(),
			total: z.number().int().nonnegative(),
			next_offset: z.number().int().nonnegative().nullable(),
			exhausted: z.boolean()
		});
		artifactSchema = z.strictObject({
			path: z.string().describe("Selected artifact path, or the canonical resource root when resource-only Evidence has no executable subject."),
			sha256: digestSchema.nullable()
		});
		layoutSummarySchema = z.strictObject({
			bytes: z.number().int().nonnegative(),
			format: z.literal("elf"),
			architecture: z.strictObject({
				machine: z.literal("EM_X86_64"),
				bits: z.literal(64),
				byte_order: z.literal("little")
			}),
			image_type: z.enum([
				"ET_EXEC",
				"ET_DYN",
				"ET_REL"
			]),
			entry: z.strictObject({
				reported_value: z.string().min(1),
				meaning: z.enum([
					"linked-virtual-address",
					"not-applicable",
					"absent"
				]),
				execution_status: z.literal("unknown")
			}),
			counts: z.strictObject({
				sections: z.number().int().nonnegative(),
				segments: z.number().int().nonnegative(),
				symbols: z.number().int().nonnegative(),
				relocations: z.number().int().nonnegative()
			}),
			limitation_count: z.number().int().nonnegative()
		});
		javascriptSummarySchema = z.strictObject({
			input_path: z.string().min(1),
			format: z.enum(["asar", "directory"]),
			root_artifact_sha256: digestSchema,
			source_selection: javaScriptSourceSelectionSchema.exactOptional(),
			statistics: jsonObjectSchema,
			electron: jsonObjectSchema,
			coverage: jsonObjectSchema,
			limitation_count: z.number().int().nonnegative()
		});
		viewResultBase = {
			parent_evidence_id: prefixedDigestSchema("ev"),
			parent_operation: z.enum([
				"inspect_binary_layout",
				"inspect_go_binary",
				"gdb_console",
				"frida_session_status",
				"inspect_with_objdump",
				"inspect_desktop_application",
				"analyze_javascript_application",
				"analyze_function",
				"inspect_artifact",
				"inventory_artifact",
				"inspect_wasm_artifact",
				"inspect_macho",
				"decode_interface_builder",
				"inspect_evm_interface",
				"inspect_managed_artifact",
				"inspect_managed_members",
				"inspect_web_network_capture",
				"inspect_android_package",
				"inspect_pcap_capture",
				"inspect_dart_aot",
				"inspect_il2cpp_metadata",
				"inspect_model_artifact",
				...NATIVE_INVENTORY_OPERATIONS,
				"match_native_functions"
			]),
			parent_digest: digestSchema,
			view_digest: digestSchema,
			artifact: artifactSchema,
			coverage: coverageSchema,
			limitations: z.array(z.string()),
			unknowns: z.array(z.string())
		};
		summaryViewResultBase = {
			kind: z.literal("summary"),
			view: summaryViewSchema,
			...viewResultBase
		};
		gdbCommandSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...commandSummaryContext,
			parent_operation: z.literal("gdb_console"),
			artifact: artifactSchema.nullable(),
			summary: gdbCommandSummarySchema
		});
		objdumpSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...commandSummaryContext,
			parent_operation: z.literal("inspect_with_objdump"),
			artifact: artifactSchema.nullable(),
			summary: commandObservationSchema
		});
		fridaSessionStatusSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...fridaSessionStatusViewContext,
			parent_operation: z.literal("frida_session_status"),
			artifact: artifactSchema.nullable(),
			summary: fridaSessionStatusSummarySchema
		});
		goBinarySummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...goBinaryViewContextSchema.shape,
			parent_operation: z.literal("inspect_go_binary"),
			summary: goBinarySummarySchema
		});
		rustBinarySummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...rustBinaryViewContextSchema.shape,
			parent_operation: z.literal("inspect_rust_binary"),
			summary: rustBinarySummarySchema
		});
		rustBinaryPageViewResultSchema = z.strictObject({
			...viewResultBase,
			...rustBinaryViewContextSchema.shape,
			kind: z.literal("rust"),
			parent_operation: z.literal("inspect_rust_binary"),
			view: rustBinaryViewRequestSchema,
			rust: rustBinarySummarySchema,
			page: rustBinaryViewPageSchema
		});
		binaryLayoutSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			summary: layoutSummarySchema,
			parent_operation: z.literal("inspect_binary_layout")
		});
		javascriptApplicationSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			summary: javascriptSummarySchema,
			parent_operation: z.literal("analyze_javascript_application")
		});
		javascriptModuleReferencesViewResultSchema = z.strictObject({
			...viewResultBase,
			kind: z.literal("javascript"),
			view: javascriptModuleReferencesRequestSchema,
			parent_operation: z.literal("analyze_javascript_application"),
			rows: z.array(javascriptModuleReferenceSchema),
			source_coverage: javascriptApplicationSourceCoverageSchema
		});
		javascriptFactsViewResultSchema = z.strictObject({
			...viewResultBase,
			kind: z.literal("javascript-facts"),
			view: javascriptFactsViewRequestSchema,
			parent_operation: z.literal("analyze_javascript_application"),
			rows: z.array(javascriptFactRowSchema),
			source_coverage: javascriptApplicationSourceCoverageSchema
		});
		artifactInventorySummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.enum(["inspect_artifact", "inventory_artifact"]),
			summary: artifactInventorySummarySchema
		});
		desktopApplicationSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_desktop_application"),
			summary: desktopSummarySchema
		});
		wasmArtifactSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_wasm_artifact"),
			summary: wasmSummarySchema
		});
		machoSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_macho"),
			summary: machoSummarySchema
		});
		interfaceBuilderSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("decode_interface_builder"),
			resource_root: bundleResourceRootSchema.optional(),
			summary: interfaceBuilderSummarySchema
		});
		evmInterfaceSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_evm_interface"),
			summary: evmSummarySchema
		});
		managedArtifactSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_managed_artifact"),
			summary: managedSummarySchema
		});
		managedMemberSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_managed_members"),
			summary: managedMemberSummarySchema
		});
		webNetworkCaptureSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_web_network_capture"),
			summary: captureSummarySchema
		});
		androidPackageSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_android_package"),
			summary: androidPackageSummarySchema
		});
		pcapCaptureSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_pcap_capture"),
			summary: pcapSummarySchema
		});
		dartAotSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_dart_aot"),
			summary: dartAotSummarySchema
		});
		modelArtifactSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_model_artifact"),
			summary: modelArtifactSummarySchema
		});
		modelArtifactPageViewResultSchema = z.strictObject({
			kind: z.literal("model-artifact"),
			view: modelArtifactViewRequestSchema,
			items: modelArtifactViewItemsSchema,
			...viewResultBase,
			...modelArtifactViewContextSchema.shape,
			parent_operation: z.literal("inspect_model_artifact")
		});
		il2cppMetadataSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			parent_operation: z.literal("inspect_il2cpp_metadata"),
			summary: il2cppMetadataSummarySchema
		});
		nativeInventorySummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			...nativeInventoryViewContext,
			parent_operation: nativeInventoryOperationSchema,
			artifact: artifactSchema.nullable(),
			summary: nativeInventorySummarySchema
		});
		nativeFunctionMatchingSummaryViewResultSchema = z.strictObject({
			...summaryViewResultBase,
			artifact: z.null(),
			parent_operation: z.literal("match_native_functions"),
			summary: nativeFunctionMatchingViewContextSchema
		});
		analysisViewResultSchema = z.discriminatedUnion("kind", [
			z.strictObject({
				...viewResultBase,
				...nativeFunctionMatchingViewContextSchema.shape,
				kind: z.literal("function-matches"),
				artifact: z.null(),
				view: nativeFunctionMatchingViewRequestSchema,
				items: nativeFunctionMatchingViewItemsSchema,
				parent_operation: z.literal("match_native_functions")
			}),
			z.strictObject({
				...viewResultBase,
				...apiSurfaceFields,
				kind: z.literal("api-surface"),
				parent_operation: z.literal("inspect_web_network_capture"),
				view: apiSurfaceViewSchema,
				artifact: z.strictObject({
					path: z.string(),
					sha256: digestSchema.nullable()
				})
			}),
			z.strictObject({
				...viewResultBase,
				...environmentManifestFields,
				kind: z.literal("environment-manifest"),
				parent_operation: z.enum(["inspect_web_network_capture", "capture_browser_scenario"]),
				view: environmentManifestViewRequestSchema
			}),
			z.strictObject({
				...viewResultBase,
				...environmentStateFields,
				kind: z.literal("environment-state"),
				parent_operation: z.enum(["inspect_web_network_capture", "capture_browser_scenario"]),
				view: environmentStateViewRequestSchema
			}),
			z.discriminatedUnion("parent_operation", [
				gdbCommandSummaryViewResultSchema,
				objdumpSummaryViewResultSchema,
				fridaSessionStatusSummaryViewResultSchema,
				goBinarySummaryViewResultSchema,
				rustBinarySummaryViewResultSchema,
				binaryLayoutSummaryViewResultSchema,
				desktopApplicationSummaryViewResultSchema,
				javascriptApplicationSummaryViewResultSchema,
				artifactInventorySummaryViewResultSchema,
				wasmArtifactSummaryViewResultSchema,
				machoSummaryViewResultSchema,
				interfaceBuilderSummaryViewResultSchema,
				evmInterfaceSummaryViewResultSchema,
				managedArtifactSummaryViewResultSchema,
				managedMemberSummaryViewResultSchema,
				webNetworkCaptureSummaryViewResultSchema,
				androidPackageSummaryViewResultSchema,
				pcapCaptureSummaryViewResultSchema,
				dartAotSummaryViewResultSchema,
				il2cppMetadataSummaryViewResultSchema,
				modelArtifactSummaryViewResultSchema,
				nativeInventorySummaryViewResultSchema,
				nativeFunctionMatchingSummaryViewResultSchema
			]),
			z.strictObject({
				...viewResultBase,
				...nativeInventoryViewContext,
				kind: z.literal("native-inventory"),
				parent_operation: nativeInventoryOperationSchema,
				artifact: artifactSchema.nullable(),
				view: nativeInventoryViewRequestSchema,
				rows: z.array(nativeInventoryViewRowSchema)
			}),
			z.strictObject({
				kind: z.literal("protobuf"),
				view: protobufViewRequestSchema,
				items: protobufViewItemsSchema,
				...viewResultBase,
				...protobufViewContextSchema.shape,
				parent_operation: z.literal("inspect_web_network_capture")
			}),
			z.strictObject({
				kind: z.literal("capture"),
				view: captureViewRequestSchema,
				items: captureViewItemsSchema,
				...viewResultBase,
				parent_operation: z.literal("inspect_web_network_capture")
			}),
			z.strictObject({
				kind: z.literal("qlog"),
				view: qlogViewRequestSchema,
				page: qlogViewPageSchema,
				context: qlogViewContextSchema,
				...viewResultBase,
				parent_operation: z.literal("inspect_web_network_capture")
			}),
			z.strictObject({
				kind: z.literal("pcap"),
				view: pcapViewRequestSchema,
				page: pcapViewPageSchema,
				source_coverage: z.enum(["complete", "partial"]),
				...viewResultBase,
				parent_operation: z.literal("inspect_pcap_capture")
			}),
			z.strictObject({
				kind: z.literal("facet"),
				view: facetViewSchema,
				facet: jsonValueSchema,
				...viewResultBase
			}),
			z.strictObject({
				...viewResultBase,
				...goBinaryViewContextSchema.shape,
				kind: z.literal("go"),
				parent_operation: z.literal("inspect_go_binary"),
				view: goBinaryViewRequestSchema,
				page: goBinaryViewPageSchema
			}),
			rustBinaryPageViewResultSchema,
			z.strictObject({
				kind: z.literal("item"),
				view: itemViewSchema,
				item: jsonValueSchema,
				...viewResultBase
			}),
			z.strictObject({
				kind: z.literal("page"),
				view: pageViewSchema,
				items: z.array(jsonValueSchema),
				...viewResultBase
			}),
			javascriptModuleReferencesViewResultSchema,
			javascriptFactsViewResultSchema,
			z.strictObject({
				kind: z.literal("native"),
				view: nativeViewSchema,
				procedure_address: z.string().nullable(),
				item: jsonValueSchema,
				...viewResultBase
			}),
			z.strictObject({
				kind: z.literal("wasm"),
				view: wasmViewRequestSchema,
				item: wasmViewItemSchema,
				...viewResultBase
			}),
			z.strictObject({
				kind: z.literal("desktop-application"),
				view: desktopViewRequestSchema,
				items: desktopViewItemsSchema,
				...viewResultBase,
				source_coverage: desktopCoverageSchema,
				parent_operation: z.literal("inspect_desktop_application")
			}),
			z.strictObject({
				kind: z.literal("macho"),
				view: machoViewRequestSchema,
				item: machoViewItemSchema,
				...viewResultBase,
				...machoViewContextSchema.shape,
				parent_operation: z.literal("inspect_macho")
			}),
			z.strictObject({
				kind: z.literal("interface-builder"),
				view: interfaceBuilderViewRequestSchema,
				items: interfaceBuilderViewItemsSchema,
				...viewResultBase,
				resource_root: bundleResourceRootSchema.optional(),
				...interfaceBuilderViewContextSchema.shape,
				parent_operation: z.literal("decode_interface_builder")
			}),
			z.strictObject({
				kind: z.literal("evm"),
				view: evmViewRequestSchema,
				item: evmViewItemSchema,
				...viewResultBase,
				parent_operation: z.literal("inspect_evm_interface")
			}),
			z.strictObject({
				kind: z.literal("managed"),
				view: managedViewRequestSchema,
				item: managedViewItemSchema,
				...viewResultBase,
				...managedViewContextSchema.shape,
				parent_operation: z.literal("inspect_managed_artifact")
			}),
			z.strictObject({
				kind: z.literal("managed-members"),
				view: managedMembersViewRequestSchema,
				page: managedMembersViewPageSchema,
				...viewResultBase,
				...managedMembersViewContextSchema.shape,
				parent_operation: z.literal("inspect_managed_members")
			}),
			z.strictObject({
				kind: z.literal("android"),
				view: androidViewRequestSchema,
				item: androidManifestViewItemSchema,
				...viewResultBase,
				parent_operation: z.literal("inspect_android_package")
			}),
			z.strictObject({
				kind: z.literal("dart-aot"),
				view: dartAotViewRequestSchema,
				items: z.array(z.string()),
				...viewResultBase,
				...dartAotViewContextSchema.shape,
				parent_operation: z.literal("inspect_dart_aot")
			}),
			modelArtifactPageViewResultSchema,
			z.strictObject({
				kind: z.literal("il2cpp-metadata"),
				view: il2cppMetadataViewRequestSchema,
				items: il2cppMetadataViewItemsSchema,
				...viewResultBase,
				...il2cppMetadataViewContextSchema.shape,
				parent_operation: z.literal("inspect_il2cpp_metadata")
			}),
			z.strictObject({
				kind: z.literal("inventory"),
				view: artifactInventoryViewRequestSchema,
				source_coverage: artifactInventoryCoverageSchema.exactOptional(),
				manifest: artifactGraphManifestSchema,
				inventory_evidence_ids: z.array(prefixedDigestSchema("ev")).min(1),
				source_complete: z.boolean(),
				items: artifactInventoryItemsSchema,
				...viewResultBase
			})
		]);
		sealAnalysisView = (projection) => analysisViewResultSchema.parse({
			...projection,
			view_digest: digestCanonicalValue(projection, "Analysis view")
		});
		parentDigest = (evidenceId) => evidenceId.slice(3);
		parseJavaScriptParent = (input) => {
			try {
				const steps = parseOwnedJavaScriptApplicationAnalysisSteps(input);
				let step = steps.next();
				while (!step.done) step = steps.next();
				return ok(step.value);
			} catch (cause) {
				if (!(cause instanceof z.ZodError)) throw cause;
				return err(analysisInputErrorFromIssues(INSPECT_ANALYSIS_VIEW_OPERATION, cause.issues.map((issue) => ({
					...issue,
					path: [
						"source",
						"normalized_result",
						...issue.path
					]
				})), { source: { normalized_result: input } }, { cause }));
			}
		};
		unsupportedParent = (parent) => new AnalysisUnsupportedTargetError(INSPECT_ANALYSIS_VIEW_OPERATION, parentArtifactPath(parent), parent.operation === "capture_browser_scenario" ? `Parent Evidence operation "capture_browser_scenario" supports only the environment-manifest and environment-state views.` : `Parent Evidence operation ${JSON.stringify(parent.operation)} does not support analysis views. Use completed binary layout, JavaScript application, native function/inventory, artifact inventory/inspection, WASM, Mach-O, Interface Builder, EVM, managed artifact or member, Android package, Dart AOT, IL2CPP metadata, or web network capture Evidence.`);
		parentArtifactPath = (parent) => {
			if (typeof parent.normalizedResult === "object" && parent.normalizedResult !== null && "artifact" in parent.normalizedResult && typeof parent.normalizedResult.artifact === "object" && parent.normalizedResult.artifact !== null && "path" in parent.normalizedResult.artifact && typeof parent.normalizedResult.artifact.path === "string") return parent.normalizedResult.artifact.path;
			if (typeof parent.normalizedResult === "object" && parent.normalizedResult !== null && "input_path" in parent.normalizedResult && typeof parent.normalizedResult.input_path === "string") return parent.normalizedResult.input_path;
			return parent.evidenceId;
		};
		retainedViewProjectors = new Map([
			["frida_session_status", projectFridaSessionStatusView],
			["gdb_console", projectCommandObservationView],
			["inspect_with_objdump", projectCommandObservationView],
			["inspect_go_binary", projectGoBinaryView],
			["inspect_rust_binary", projectRustBinaryView],
			...NATIVE_INVENTORY_OPERATIONS.map((operation) => [operation, projectNativeInventoryView]),
			["inspect_desktop_application", projectDesktopApplicationView],
			["inspect_wasm_artifact", projectWasmArtifactView],
			["inspect_macho", projectMachoView],
			["decode_interface_builder", projectInterfaceBuilderView],
			["inspect_evm_interface", projectEvmInterfaceView],
			["inspect_managed_artifact", projectManagedArtifactView],
			["inspect_managed_members", projectManagedMemberView],
			["inspect_android_package", projectAndroidPackageView],
			["inspect_dart_aot", projectDartAotView],
			["inspect_il2cpp_metadata", projectIl2cppMetadataView],
			["inspect_model_artifact", projectModelArtifactView],
			["match_native_functions", projectNativeFunctionMatchingView],
			["inspect_artifact", projectArtifactInventoryView],
			["inventory_artifact", projectArtifactInventoryView]
		]);
		isGroupingView = (view) => view.kind === "api-surface" || view.kind === "environment-manifest" || view.kind === "environment-state";
		projectGroupingView = (parent, view, accumulators) => {
			if (view.kind === "api-surface") return projectWebNetworkApiSurfaceView(parent, view, accumulators.apiSurface);
			if (view.kind === "environment-manifest") return projectEnvironmentManifestView(parent, view, accumulators.manifest);
			return projectEnvironmentStateView(parent, view, accumulators.state);
		};
		projectAnalysisView = (parent, view, accumulators = {}) => {
			const digest = parentDigest(parent.evidenceId);
			if (!digestSchema.safeParse(digest).success) return err(analysisViewInputError([{
				path: ["source"],
				reason: "invalid_format",
				message: "Parent Evidence ID is not a digest-backed identifier."
			}]));
			if (isGroupingView(view)) {
				const grouped = projectGroupingView(parent, view, accumulators);
				return grouped.ok ? ok(sealAnalysisView(grouped.value)) : grouped;
			}
			if (parent.operation === "inspect_web_network_capture") {
				const projected = projectWebNetworkCaptureView(parent, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			if (parent.operation === "inspect_pcap_capture") {
				const projected = projectPcapCaptureView(parent, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			if (parent.operation === "inspect_binary_layout") {
				const layout = safeParseOwnedBinaryLayout(parent.normalizedResult);
				if (!layout.success) return err(analysisViewInputError([{
					path: ["source"],
					reason: "invalid_value",
					message: "Parent Evidence result does not match inspect_binary_layout."
				}]));
				const projected = projectBinaryLayoutView(parent, layout.data, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			if (parent.operation === "analyze_javascript_application") {
				const analysis = parseJavaScriptParent(parent.normalizedResult);
				if (!analysis.ok) return analysis;
				const projected = projectJavaScriptApplicationView(parent, analysis.value, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			if (parent.operation === "analyze_function") {
				const native = functionDossierSchema.safeParse(parent.normalizedResult);
				if (!native.success) return err(analysisInputErrorFromIssues(INSPECT_ANALYSIS_VIEW_OPERATION, native.error.issues.map((issue) => ({
					...issue,
					path: [
						"source",
						"normalized_result",
						...issue.path
					]
				})), { source: { normalized_result: parent.normalizedResult } }, { cause: native.error }));
				const projected = projectNativeFunctionView(parent, native.data, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			const project = retainedViewProjectors.get(parent.operation);
			if (project !== undefined) {
				const projected = project(parent, view);
				return projected.ok ? ok(sealAnalysisView(projected.value)) : projected;
			}
			return err(unsupportedParent(parent));
		};
	})))();
}

//#endregion
export { DEFAULT_WASM_COMMAND_TIMEOUT_MS, EnvironmentManifestAccumulator, EnvironmentStateAccumulator, IL2CPP_METADATA_MAGIC, IL2CPP_METADATA_VERSIONS, INSPECT_ANALYSIS_VIEW_OPERATION, MAX_FLUTTER_LIBRARY_PATH_BYTES, MAX_WASM_COMMAND_TIMEOUT_MS, RUST_AUDITABLE_FORMAT_VERSIONS, WASM_INTERFACE_REPRESENTATION_BYTES, WebNetworkApiSurfaceAccumulator, admitAnalysisViewData, analysisViewResultSchema, androidInputSchemas, androidPackageInspectionInputSchema, androidPackageSummaryViewResultSchema, androidRequestSchema, androidResultSchemas, artifactInventorySummaryViewResultSchema, binaryLayoutPayloadSchema, binaryLayoutSchema, binaryLayoutSummaryViewResultSchema, commandEvidenceDetailSchema, commandObservationSchema, cyclicDependencyIndices, dartAotInspectionInputSchema, dartAotSummaryViewResultSchema, demangleSwiftSchema, desktopApplicationSchema, desktopApplicationSummaryViewResultSchema, dexDescriptorSchema, evmInterfaceSchema, evmInterfaceSummaryViewResultSchema, flutterInputSchemas, flutterRequestSchema, flutterResultSchemas, fridaSessionObservationSchema, fridaSessionStatusInputSchema, fridaSessionStatusSchema, fridaSessionStatusSummaryViewResultSchema, gdbCommandResultSchema, gdbCommandSummaryViewResultSchema, goArchitectureForSubject, goBinarySchema, goBinarySummaryViewResultSchema, il2cppMetadataSchema, il2cppMetadataSectionNames, il2cppMetadataSummaryViewResultSchema, init_EnvironmentManifestAccumulator, init_EnvironmentStateAccumulator, init_WebNetworkApiSurfaceAccumulator, init_analysisView, init_analysisViewDataAdmission, init_analysisViewErrors, init_androidAnalysis, init_binaryLayout, init_commandObservation, init_desktopApplication, init_evmInterface, init_exactJsonNumber, init_flutterBuildAnalysis, init_fridaSessionStatus, init_functionMatching, init_goBinary, init_il2cppMetadata, init_modelArtifact, init_modelArtifactQuery, init_nativeInspection, init_pcapAnalysis, init_recordedResponseBody, init_rustBinary, init_rustBinaryQuery, init_scenarioCaptureRecords, init_solidityMetadata, init_wasmArtifact, init_wasmInterface, init_webNetworkRouteTemplates, inspectAnalysisViewInputSchema, inspectBinaryLayoutInputSchema, inspectDesktopApplicationInputSchema, inspectEvmInterfaceInputSchema, inspectGoBinaryInputSchema, inspectIl2cppMetadataInputSchema, inspectMachoSchema, inspectModelArtifactInputSchema, inspectPlistSchema, inspectRustBinaryRequestSchema, inspectSignatureSchema, inspectWasmArtifactInputSchema, interfaceBuilderSummaryViewResultSchema, isExactJsonNumber, isJsonLike, javascriptApplicationSummaryViewResultSchema, listArchitecturesSchema, machoSummaryViewResultSchema, managedArtifactSummaryViewResultSchema, managedMemberSummaryViewResultSchema, mediaTypeEssence, modelArtifactPageViewResultSchema, modelArtifactPartialSchema, modelArtifactSchema, modelArtifactSummaryViewResultSchema, nativeFunctionMatchingSchema, nativeFunctionMatchingSummaryViewResultSchema, nativeInventorySummaryViewResultSchema, objdumpSummaryViewResultSchema, parseExactJson, pcapCaptureSummaryViewResultSchema, pcapInputSchemas, pcapRequestSchema, pcapResultSchemas, projectAnalysisView, readRecordedRequestLine, readRecordedResponseBody, rustArchitectureForSubject, rustBinaryPageViewResultSchema, rustBinarySchema, rustBinarySummaryViewResultSchema, scenarioCaptureRecords, solidityMetadataSchema, wasmArtifactMatchesSubject, wasmArtifactSchema, wasmArtifactSummaryViewResultSchema, wasmInterfaceEntryRepresentationBytes, wasmInterfaceSchema, webNetworkCaptureSummaryViewResultSchema };