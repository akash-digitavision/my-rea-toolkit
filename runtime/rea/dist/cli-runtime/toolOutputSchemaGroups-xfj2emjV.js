import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisCancelledError, AnalysisInputError, AnalysisOutputError, PROVIDER_FAILURE_STAGES, PROVIDER_OPERATION_STATES, PROVIDER_RETRY_ACTIONS, analysisErrorProjectionSchema, init_analysisErrorCore, init_errorSchemas, init_jsonValue, init_providerOperationHealth, jsonValueSchema } from "./errorSchemas-BjJIu7zO.js";
import { BINARY_ARCHITECTURES as BINARY_ARCHITECTURES$1, IDENTIFIER_PATTERN, PROVIDER_REJECTION_CODES, RAW_ONLY_ARCHITECTURES, ZIP_PACKAGE_FORMATS, addressCoordinate, analysisBookmarkSchema, analysisProfileSchema, artifactExtractionResultSchema, artifactInspectionResultSchema, bundleResourceBoundResultSchema, bundleResourceRootSchema, canonicalJson as canonicalJson$1, cliMetadataGuidSchema, compareUnicodeCodePoints, compositeKey, decodeCanonicalBase64, digestSchema, electronFuseReportSchema, emptyArraySchema, err, evidenceBundleSchema, evidenceSchema, functionBodySchema, functionComparisonResultSchema, functionDossierSchema, functionInstructionWindowSchema, hasCompleteInventoryCoverage, init_addressCoordinate, init_analysisProfile, init_artifactGraph, init_artifactInspection, init_artifactInventoryEvidence, init_binaryTargetTypes, init_bundleResourceRoot, init_canonicalOrdering, init_comparisonSemantics, init_digests, init_electronFuses, init_emptyArraySchema, init_evidence, init_evidenceBundle, init_functionComparisonSchemas, init_hopperValues, init_interfaceBuilderGraph, init_localPath, init_machoCpuIdentity, init_managedApplicationGraph, init_managedArtifact, init_managedInspectionEvidence, init_nativeApiBoundary, init_nativeInstruction, init_nativeInventory, init_nativeInvestigationGraph, init_nativeValueTrace, init_objcSwiftMetadata, init_processCapture, init_processCaptureCoverage, init_providerSelection, init_relationshipCoverage, init_residualUnknown, init_result, init_stringPatterns, init_unicodeCodePointOrder, init_webScreenshot, init_zipPackageFormat, interfaceBuilderAnalysisSchema, localPathStringSchema, localVariableSchema, machoCpuSubtypeBase, managedApplicationGraphResultSchema, managedArtifactInspectionSchema, managedMemberInspectionSchema, managedNativeBoundaryInspectionSchema, nativeApiInspectionResultSchema, nativeCallTargetsSchema, nativeDispatchMetadataResultSchema, nativeInstructionSchema, nativeInventoryRowsSchemas, nativeInvestigationTraceSchema, nativeValueTraceSchema, objcClassImportIdentitySchema, ok, parseArtifactInventoryEvidence, parseEvidence, parseEvidenceBundle, parseManagedInspectionEvidence, prefixedDigestSchema, procedureClassificationSchema, procedureIdentitySchema, processCaptureSchema, processSourceTruncated, referenceEdgeSchema, relationshipCoverageSchema, residualUnknownSchema, serializeEvidenceBundle, uniqueSorted, unresolvedCallSchema, validateAnalysisProfileProvider } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { artifactInventorySummaryViewResultSchema, demangleSwiftSchema, init_analysisView, init_functionMatching, init_nativeInspection, inspectMachoSchema, inspectPlistSchema, inspectSignatureSchema, interfaceBuilderSummaryViewResultSchema, listArchitecturesSchema, machoSummaryViewResultSchema, managedArtifactSummaryViewResultSchema, managedMemberSummaryViewResultSchema, nativeFunctionMatchingSchema, nativeFunctionMatchingSummaryViewResultSchema, nativeInventorySummaryViewResultSchema } from "./analysisView-C5VMVK4R.js";
import { createHash } from "node:crypto";
import { z } from "zod";
import canonicalize from "canonicalize";
import { types } from "node:util";

//#region dist/domain/native/nativeAddress.js
var nativeAddressSchema, nativeAddressInputSchema, parseNativeAddress;
function init_nativeAddress() {
	return (init_nativeAddress = __esmMin((() => {
		nativeAddressSchema = z.string().regex(/^(?:(?:[A-Za-z0-9._~\x2d]|%[0-9A-F]{2})+:)?0x(?:0|[1-9a-f][0-9a-f]*)$/u);
		nativeAddressInputSchema = z.string().regex(/^(?:(?:[A-Za-z0-9._~\x2d]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$/u).transform((address) => {
			const separator = address.lastIndexOf(":") + 1;
			const space = address.slice(0, separator).replace(/%[0-9a-fA-F]{2}/gu, (escape) => escape.toUpperCase());
			return `${space}0x${BigInt(address.slice(separator)).toString(16)}`;
		});
		parseNativeAddress = (input) => nativeAddressInputSchema.parse(input);
	})))();
}

//#endregion
//#region dist/domain/native/nativeByteRead.js
var nativeByteReadSchema;
function init_nativeByteRead() {
	return (init_nativeByteRead = __esmMin((() => {
		nativeByteReadSchema = z.object({
			address: z.string(),
			requested_bytes: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
			returned_bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
			bytes_hex: z.string().regex(/^(?:[a-f0-9]{2})*$/u),
			complete: z.boolean()
		}).superRefine((value, context) => {
			if (value.returned_bytes * 2 !== value.bytes_hex.length || value.returned_bytes > value.requested_bytes || value.complete !== (value.returned_bytes === value.requested_bytes)) context.addIssue({
				code: "custom",
				message: "Read-byte length and completeness disagree"
			});
		});
	})))();
}

//#endregion
//#region dist/domain/native/procedureInfo.js
var procedureInfoSchema;
function init_procedureInfo() {
	return (init_procedureInfo = __esmMin((() => {
		init_hopperValues();
		procedureInfoSchema = z.object({
			name: z.string(),
			entrypoint: z.string(),
			basicblock_count: z.number().int().min(0),
			length: z.number().min(0),
			signature: z.string().nullable(),
			locals: z.array(localVariableSchema),
			classification: procedureClassificationSchema.nullable(),
			body: functionBodySchema
		});
	})))();
}

//#endregion
//#region dist/contracts/toolOutputSchemaPrimitives.js
var evidenceResultOf, lifecycleResultOf, requireOutputSchema, targetFormatSchema, targetKindSchema, providerCapabilityFacts, providerCapability, PROVIDER_EFFECT_NAMES, providerIdentity, providerCapabilityGroupFacts, providerCapabilityGroup, providerCapabilitySet, expandProviderCapabilities, processCoordinates, processLineageObservation, analysisRun, analysisActivity, providerOperationRequest, providerOperationHealth, providerRejectionCode, providerDiagnostics, providerAvailability, providerTargetSupport, clientFeatureNameSchema, clientFeatureAvailabilitySchema, toolAvailabilityMode, toolAvailabilityFacts, toolUnavailabilityReason, toolAvailability, TOOL_EFFECT_NAMES, TOOL_ANNOTATION_NAMES, toolAvailabilityGroupFacts, toolAvailabilityGroup, toolAvailabilityInventory, expandToolAvailability, sessionProvider, nullableText, addressList, addressedEntry, containingProcedureResolution, unavailable, availableMemoryPermissions, memoryRegionOutput, segmentOutput, procedureInfoOutput, symbolDiscoveryOutput, objcClassDiscoveryOutput, graphNode, functionDossierOutput;
function init_toolOutputSchemaPrimitives() {
	return (init_toolOutputSchemaPrimitives = __esmMin((() => {
		init_procedureInfo();
		init_hopperValues();
		init_analysisProfile();
		init_evidence();
		init_jsonValue();
		init_providerSelection();
		init_providerOperationHealth();
		init_errorSchemas();
		init_relationshipCoverage();
		init_zipPackageFormat();
		init_objcSwiftMetadata();
		evidenceResultOf = (schema) => z.strictObject({
			...evidenceSchema.shape,
			normalized_result: schema
		}).superRefine(validateAnalysisProfileProvider);
		lifecycleResultOf = (schema) => z.object({ result: schema });
		requireOutputSchema = (schemas, name) => {
			const schema = schemas[name];
			if (schema === undefined) throw new Error(`Missing output schema for ${name}`);
			return schema;
		};
		targetFormatSchema = z.enum([
			"hopper",
			"analysis-database",
			"mach-o",
			"mach-o-universal",
			"elf",
			"pe",
			"dos-mz",
			"dos-com",
			"raw-binary",
			...ZIP_PACKAGE_FORMATS,
			"asar",
			"godot-pck",
			"dmg",
			"pkg",
			"plist",
			"javascript",
			"source-map"
		]);
		targetKindSchema = z.enum([
			"executable",
			"database",
			"archive",
			"artifact"
		]);
		providerCapabilityFacts = {
			operation: z.string(),
			effects: z.object({
				mutates_artifact: z.boolean(),
				launches_process: z.boolean(),
				may_show_ui: z.boolean(),
				may_access_network: z.boolean(),
				may_write_filesystem: z.boolean(),
				changes_permissions: z.boolean(),
				requires_root: z.boolean()
			}),
			limitations: z.array(z.string())
		};
		providerCapability = z.discriminatedUnion("available", [z.object({
			...providerCapabilityFacts,
			available: z.literal(true),
			reason: z.null(),
			availability_code: z.null()
		}), z.object({
			...providerCapabilityFacts,
			available: z.literal(false),
			reason: z.string().nullable(),
			availability_code: z.enum(PROVIDER_REJECTION_CODES).nullable()
		})]);
		PROVIDER_EFFECT_NAMES = Object.keys(providerCapabilityFacts.effects.shape);
		providerIdentity = z.object({
			id: z.string(),
			name: z.string(),
			version: z.string().nullable()
		});
		providerCapabilityGroupFacts = {
			operations: z.array(z.string().min(1)).min(1),
			effects: z.array(providerCapabilityFacts.effects.keyof()),
			limitations: z.array(z.string())
		};
		providerCapabilityGroup = z.discriminatedUnion("available", [z.strictObject({
			...providerCapabilityGroupFacts,
			available: z.literal(true),
			reason: z.null(),
			availability_code: z.null()
		}), z.strictObject({
			...providerCapabilityGroupFacts,
			available: z.literal(false),
			reason: z.string().nullable(),
			availability_code: z.enum(PROVIDER_REJECTION_CODES).nullable()
		})]);
		providerCapabilitySet = z.strictObject({
			provider: providerIdentity,
			shared_limitations: z.array(z.string()),
			groups: z.array(providerCapabilityGroup)
		});
		expandProviderCapabilities = (sets) => sets.flatMap((set) => set.groups.flatMap((group) => group.operations.map((operation) => ({
			...providerCapability.parse({
				operation,
				available: group.available,
				reason: group.reason,
				availability_code: group.availability_code,
				effects: Object.fromEntries(PROVIDER_EFFECT_NAMES.map((name) => [name, group.effects.includes(name)])),
				limitations: [...set.shared_limitations, ...group.limitations]
			}),
			provider: set.provider
		}))));
		processCoordinates = {
			launcher_pid: z.number().int().min(1),
			process_group_id: z.number().int().min(1)
		};
		processLineageObservation = z.discriminatedUnion("status", [z.object({
			status: z.literal("unavailable"),
			observed_at: z.iso.datetime(),
			...processCoordinates,
			reason: z.string().min(1)
		}), z.object({
			status: z.literal("verified"),
			observed_at: z.iso.datetime(),
			...processCoordinates,
			launcher_parent_pid: z.number().int().min(0),
			descendants: z.array(z.object({
				pid: z.number().int().min(1),
				parent_pid: z.number().int().min(0),
				process_group_id: z.number().int().min(1)
			}))
		})]);
		analysisRun = z.object({
			run_id: z.string().uuid(),
			process_lineage: z.discriminatedUnion("status", [z.object({ status: z.literal("not_observed") }), z.object({
				status: z.literal("snapshots"),
				snapshots: z.array(z.object({
					provider: providerIdentity,
					observation: processLineageObservation
				}))
			})])
		}).nullable();
		analysisActivity = z.object({
			status: z.enum([
				"not_observed",
				"idle",
				"busy"
			]),
			providers: z.array(z.object({
				provider: providerIdentity,
				active: z.object({
					request_id: z.number().int().min(1),
					operation: z.string().min(1),
					elapsed_ms: z.number().int().min(0),
					caller_state: z.enum(["waiting", "cancelled"])
				}).nullable(),
				queued_requests: z.number().int().min(0)
			}))
		});
		providerOperationRequest = z.object({
			request_id: z.number().int().min(1),
			operation: z.string().min(1),
			stage: z.enum(PROVIDER_FAILURE_STAGES)
		});
		providerOperationHealth = z.object({
			state: z.enum(PROVIDER_OPERATION_STATES),
			stage: z.enum(PROVIDER_FAILURE_STAGES).nullable(),
			retry_action: z.enum(PROVIDER_RETRY_ACTIONS).nullable(),
			exit_code: z.number().int().nullable(),
			requests: z.array(providerOperationRequest)
		}).nullable();
		providerRejectionCode = z.enum(PROVIDER_REJECTION_CODES);
		providerDiagnostics = z.record(z.string(), jsonValueSchema);
		providerAvailability = z.discriminatedUnion("status", [
			z.object({
				status: z.literal("unknown"),
				code: z.null(),
				reason: z.string().min(1),
				diagnostics: providerDiagnostics
			}),
			z.object({
				status: z.literal("available"),
				code: z.null(),
				reason: z.null(),
				diagnostics: providerDiagnostics
			}),
			z.object({
				status: z.literal("unavailable"),
				code: providerRejectionCode,
				reason: z.string().min(1),
				diagnostics: providerDiagnostics
			})
		]);
		providerTargetSupport = z.discriminatedUnion("status", [
			z.object({
				status: z.literal("unknown"),
				code: z.null(),
				reason: z.string().min(1),
				diagnostics: providerDiagnostics
			}),
			z.object({
				status: z.literal("supported"),
				code: z.null(),
				reason: z.null(),
				diagnostics: providerDiagnostics
			}),
			z.object({
				status: z.literal("unsupported"),
				code: z.enum([
					"target_kind_unsupported",
					"target_format_unsupported",
					"architecture_unsupported",
					"target_role_unsupported",
					"managed_target_unsupported"
				]),
				reason: z.string().min(1),
				diagnostics: providerDiagnostics
			})
		]);
		clientFeatureNameSchema = z.enum([
			"elicitation_form",
			"elicitation_url",
			"roots",
			"sampling"
		]);
		clientFeatureAvailabilitySchema = z.object({
			elicitation_form: z.boolean(),
			elicitation_url: z.boolean(),
			roots: z.boolean(),
			sampling: z.boolean()
		});
		toolAvailabilityMode = z.discriminatedUnion("available", [z.object({
			name: z.string(),
			available: z.literal(true),
			missing_operations: z.array(z.string()).length(0),
			remediation: z.null()
		}), z.object({
			name: z.string(),
			available: z.literal(false),
			missing_operations: z.array(z.string()).min(1),
			remediation: z.string().nullable()
		})]);
		toolAvailabilityFacts = {
			name: z.string(),
			surface: z.string(),
			default_mode_available: z.boolean().optional(),
			modes: z.array(toolAvailabilityMode).optional(),
			client_requirements: z.object({
				required: z.array(clientFeatureNameSchema),
				optional: z.array(clientFeatureNameSchema),
				missing_required: z.array(clientFeatureNameSchema),
				missing_optional: z.array(clientFeatureNameSchema)
			}),
			effects: z.strictObject({
				mutatesTarget: z.boolean(),
				mutatesSession: z.boolean(),
				writesFilesystem: z.boolean(),
				launchesProcess: z.boolean(),
				accessesNetwork: z.boolean(),
				changesUiState: z.boolean(),
				mayDiscardData: z.boolean(),
				executesForeignCode: z.boolean(),
				mutatesDevice: z.boolean(),
				idempotent: z.boolean()
			}),
			annotations: z.object({
				read_only: z.boolean(),
				destructive: z.boolean(),
				idempotent: z.boolean(),
				open_world: z.boolean()
			})
		};
		toolUnavailabilityReason = z.enum([
			"client_capability_missing",
			"target_required",
			"provider_missing",
			"provider_unavailable",
			"target_unsupported",
			"unsupported_host"
		]);
		toolAvailability = z.discriminatedUnion("available", [z.object({
			...toolAvailabilityFacts,
			available: z.literal(true),
			reason: z.literal("available"),
			remediation: z.null()
		}), z.object({
			...toolAvailabilityFacts,
			available: z.literal(false),
			reason: toolUnavailabilityReason,
			remediation: z.string().nullable()
		})]);
		TOOL_EFFECT_NAMES = Object.keys(toolAvailabilityFacts.effects.shape);
		TOOL_ANNOTATION_NAMES = Object.keys(toolAvailabilityFacts.annotations.shape);
		toolAvailabilityGroupFacts = {
			names: z.array(z.string().min(1)).min(1),
			surface: toolAvailabilityFacts.surface,
			default_mode_available: toolAvailabilityFacts.default_mode_available,
			modes: toolAvailabilityFacts.modes,
			client_requirements: toolAvailabilityFacts.client_requirements.optional(),
			effects: z.array(toolAvailabilityFacts.effects.keyof()),
			annotations: z.array(toolAvailabilityFacts.annotations.keyof())
		};
		toolAvailabilityGroup = z.discriminatedUnion("available", [z.strictObject({
			...toolAvailabilityGroupFacts,
			available: z.literal(true),
			reason: z.literal("available"),
			remediation: z.null()
		}), z.strictObject({
			...toolAvailabilityGroupFacts,
			available: z.literal(false),
			reason: toolUnavailabilityReason,
			remediation: z.string().nullable()
		})]);
		toolAvailabilityInventory = z.strictObject({
			client_requirements: toolAvailabilityFacts.client_requirements,
			groups: z.array(toolAvailabilityGroup)
		});
		expandToolAvailability = (inventory) => inventory.groups.flatMap((group) => group.names.map((name) => toolAvailability.parse({
			...group,
			name,
			client_requirements: group.client_requirements ?? inventory.client_requirements,
			effects: Object.fromEntries(TOOL_EFFECT_NAMES.map((effect) => [effect, group.effects.includes(effect)])),
			annotations: Object.fromEntries(TOOL_ANNOTATION_NAMES.map((annotation) => [annotation, group.annotations.includes(annotation)]))
		})));
		sessionProvider = z.object({
			cleanup_pending: z.boolean(),
			capabilities: z.array(providerCapabilitySet),
			analysis_run: analysisRun,
			analysis_activity: analysisActivity,
			provider_operation_health: providerOperationHealth,
			analysis_provider_binding: z.object({
				provider: providerIdentity,
				selection_source: z.enum([
					"request",
					"environment",
					"auto-single-candidate"
				]),
				analysis_profile: analysisProfileSchema
			}).nullable(),
			analysis_provider_candidates: z.array(z.object({
				provider: providerIdentity,
				availability: providerAvailability,
				target_support: providerTargetSupport,
				selected: z.boolean(),
				capabilities: z.array(providerCapabilitySet)
			})),
			tool_availability: toolAvailabilityInventory,
			client_features: z.object({
				elicitation_form: z.boolean(),
				elicitation_url: z.boolean(),
				roots: z.boolean(),
				sampling: z.boolean()
			}),
			server_identity: z.object({
				package: z.object({
					name: z.string(),
					version: z.string(),
					root_path: z.string(),
					build_commit: z.string().nullable()
				}),
				server: z.object({
					name: z.string(),
					version: z.string(),
					started_at: z.string(),
					command_path: z.string().nullable()
				}),
				sdk: z.object({
					server: z.string(),
					client_test: z.string(),
					core: z.string()
				}),
				negotiated_protocol_version: z.string().nullable(),
				client: z.object({
					name: z.string(),
					version: z.string()
				}).nullable(),
				skill: z.object({
					name: z.string(),
					expected_version: z.string()
				}),
				catalog: z.strictObject({
					counts: z.strictObject({
						cli_commands: z.number().int().min(0),
						mcp_tools: z.number().int().min(0),
						mcp_prompts: z.number().int().min(0)
					}),
					digests: z.strictObject({
						tools_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
						prompts_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
						combined_sha256: z.string().regex(/^[a-f0-9]{64}$/u)
					})
				}),
				protocol_features: z.object({
					progress: z.boolean(),
					cancellation: z.boolean(),
					elicitation: z.boolean()
				}),
				alignment: z.object({
					state: z.enum([
						"aligned",
						"mcp_server_restart_required",
						"unknown"
					]),
					reasons: z.array(z.string()),
					remediation: z.string().nullable()
				})
			})
		}).passthrough();
		nullableText = z.string().nullable();
		addressList = z.array(z.string());
		addressedEntry = z.object({
			address: z.string(),
			name: z.string()
		});
		containingProcedureResolution = z.discriminatedUnion("found", [z.object({
			query_address: z.string(),
			found: z.literal(true),
			procedure: procedureIdentitySchema
		}), z.object({
			query_address: z.string(),
			found: z.literal(false),
			procedure: z.null(),
			reason: z.enum(["outside_segments", "not_in_procedure"])
		})]);
		unavailable = z.object({
			available: z.literal(false),
			reason: z.string()
		});
		availableMemoryPermissions = z.object({
			available: z.literal(true),
			source: z.literal("ghidra-memory-block")
		});
		memoryRegionOutput = z.object({
			name: z.string(),
			start: z.string(),
			end: z.string(),
			readable: z.boolean().nullable(),
			writable: z.boolean().nullable(),
			executable: z.boolean().nullable(),
			permissions: z.union([unavailable, availableMemoryPermissions]),
			provenance: z.enum(["hopper-public-python-api", "ghidra-memory-block"]),
			address_space: z.string().optional(),
			image_base: z.string().optional(),
			initialized: z.boolean().optional(),
			overlay: z.boolean().optional()
		});
		segmentOutput = evidenceResultOf(z.array(memoryRegionOutput.extend({ sections: z.array(memoryRegionOutput) })));
		procedureInfoOutput = evidenceResultOf(procedureInfoSchema);
		symbolDiscoveryOutput = (property) => evidenceResultOf(z.object({
			count: z.number().int().min(0),
			[property]: z.array(addressedEntry)
		}));
		objcClassDiscoveryOutput = evidenceResultOf(z.object({
			count: z.number().int().min(0),
			classes: z.array(addressedEntry.extend({ binding_identity: objcClassImportIdentitySchema.extend({ slot_addresses: z.array(z.string().min(1)).min(1) }).optional() })),
			identity_coverage: z.strictObject({
				status: z.enum([
					"complete",
					"partial",
					"unsupported",
					"not_requested",
					"unknown",
					"not_applicable"
				]),
				reason: z.string().nullable()
			})
		}));
		graphNode = z.discriminatedUnion("status", [z.object({
			address: z.string(),
			status: z.literal("ok"),
			calls: z.array(z.string()),
			relationship_coverage: relationshipCoverageSchema,
			limitations: z.array(z.string()).optional()
		}), z.object({
			address: z.string(),
			status: z.literal("error"),
			error: analysisErrorProjectionSchema
		})]);
		functionDossierOutput = evidenceResultOf(functionDossierSchema);
	})))();
}

//#endregion
//#region dist/contracts/toolEffects.js
var effects, evidence, nativeEvidence, browserEvidence, sessionEvidence, TOOL_EFFECTS, annotationsFromEffects, TARGET_CONTENT_FREE_TOOLS, toolReturnsTargetContent, toolContractMetadata;
function init_toolEffects() {
	return (init_toolEffects = __esmMin((() => {
		effects = (overrides = {}) => ({
			mutatesTarget: false,
			mutatesSession: false,
			writesFilesystem: false,
			launchesProcess: false,
			accessesNetwork: false,
			changesUiState: false,
			mayDiscardData: false,
			executesForeignCode: false,
			mutatesDevice: false,
			idempotent: true,
			...overrides
		});
		evidence = effects({ mutatesSession: true });
		nativeEvidence = effects({
			mutatesSession: true,
			launchesProcess: true
		});
		browserEvidence = effects({
			mutatesSession: true,
			accessesNetwork: true
		});
		sessionEvidence = effects({ mutatesSession: true });
		TOOL_EFFECTS = {
			list_cutter_sessions: effects({ accessesNetwork: true }),
			cutter_command: effects({
				mutatesTarget: true,
				executesForeignCode: true,
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				idempotent: false
			}),
			inspect_with_objdump: effects({
				mutatesSession: true,
				launchesProcess: true
			}),
			start_gdb_session: effects({
				launchesProcess: true,
				mutatesSession: true,
				idempotent: false
			}),
			gdb_console: effects({
				mutatesTarget: true,
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				executesForeignCode: true,
				idempotent: false
			}),
			gdb_session_status: effects(),
			start_rizin_debug_session: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				executesForeignCode: true,
				idempotent: false
			}),
			rizin_debug_command: effects({
				mutatesTarget: true,
				mutatesSession: true,
				executesForeignCode: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				mayDiscardData: true,
				idempotent: false
			}),
			rizin_debug_session_status: effects({ mutatesSession: true }),
			close_rizin_debug_session: effects({
				mutatesSession: true,
				launchesProcess: true,
				mutatesTarget: true,
				executesForeignCode: true
			}),
			close_gdb_session: effects({
				launchesProcess: true,
				mutatesSession: true,
				mutatesTarget: true,
				executesForeignCode: true,
				idempotent: false
			}),
			execute_rizin_command: effects({
				mutatesTarget: true,
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				mayDiscardData: true,
				executesForeignCode: true,
				idempotent: false
			}),
			inspect_desktop_application: evidence,
			inspect_go_binary: evidence,
			inspect_il2cpp_metadata: evidence,
			inspect_model_artifact: evidence,
			inspect_rust_binary: evidence,
			inspect_sqlite_database: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			inspect_packet_fields: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_packet_capture: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_signal_decoders: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			decode_signal_recording: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_wasm_artifact: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			inspect_evm_interface: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			inspect_web_network_capture: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			observe_web_execution: effects({
				mutatesTarget: true,
				mutatesSession: true,
				accessesNetwork: true,
				mayDiscardData: true,
				idempotent: false
			}),
			inspect_web_event_listeners: browserEvidence,
			trace_web_source_location: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			trace_web_module_imports: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			inspect_recorded_crash: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			inspect_binary_layout: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			list_frida_devices: effects({
				launchesProcess: true,
				accessesNetwork: true
			}),
			list_frida_processes: effects({
				launchesProcess: true,
				accessesNetwork: true
			}),
			start_frida_session: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				idempotent: false
			}),
			load_frida_script: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				executesForeignCode: true,
				idempotent: false
			}),
			resume_frida_session: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				executesForeignCode: true,
				idempotent: false
			}),
			unload_frida_script: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				idempotent: false
			}),
			frida_session_status: evidence,
			close_frida_session: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				idempotent: false
			}),
			instrument_with_frida: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				executesForeignCode: true,
				idempotent: false
			}),
			inspect_pe_resources: evidence,
			inspect_analysis_view: evidence,
			inspect_firmware_regions: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			extract_firmware: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				idempotent: false
			}),
			inspect_android_package: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_pcap_client: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_pcap_capture: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			identify_flutter_build: effects({
				mutatesSession: true,
				writesFilesystem: true
			}),
			inspect_dart_aot: effects({
				mutatesSession: true,
				writesFilesystem: true
			}),
			inspect_apktool_client: effects({
				mutatesSession: true,
				launchesProcess: true
			}),
			decode_android_resources: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_jeb_client: effects({
				mutatesSession: true,
				accessesNetwork: true
			}),
			open_jeb_project: effects({
				mutatesSession: true,
				accessesNetwork: true,
				idempotent: false
			}),
			list_jeb_units: effects({
				mutatesSession: true,
				accessesNetwork: true
			}),
			decompile_jeb_item: effects({
				mutatesSession: true,
				accessesNetwork: true
			}),
			inspect_adb_client: effects({
				mutatesSession: true,
				launchesProcess: true
			}),
			list_adb_devices: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			inspect_adb_device: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			list_adb_packages: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			pull_adb_package: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				accessesNetwork: true,
				idempotent: false
			}),
			read_adb_logcat: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			inspect_adb_package: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			pull_adb_file: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				accessesNetwork: true,
				idempotent: false
			}),
			push_adb_file: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			capture_adb_screen: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				accessesNetwork: true,
				idempotent: false
			}),
			list_adb_processes: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			list_adb_directory: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			list_adb_features: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			list_adb_services: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			inspect_adb_display: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			inspect_adb_window: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			read_adb_setting: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			collect_adb_bugreport: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				accessesNetwork: true,
				idempotent: false
			}),
			resolve_adb_packages: effects({
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true
			}),
			install_adb_package: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			uninstall_adb_package: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			start_adb_app: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			start_adb_activity: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			stop_adb_app: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				mutatesDevice: true,
				idempotent: false
			}),
			search_android_classes: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_android_class: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			inspect_android_method: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			trace_android_references: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			annotate_native_function: effects({
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true,
				mayDiscardData: true
			}),
			inspect_native_load_image: evidence,
			inspect_native_dispatch_metadata: evidence,
			trace_native_ui_action: evidence,
			trace_native_values: evidence,
			address_name: evidence,
			comment: evidence,
			current_address: evidence,
			current_procedure: evidence,
			current_document: evidence,
			goto_address: effects({
				mutatesSession: true,
				changesUiState: true
			}),
			inline_comment: evidence,
			list_bookmarks: evidence,
			list_documents: evidence,
			list_names: evidence,
			list_procedures: evidence,
			list_segments: evidence,
			list_strings: evidence,
			next_address: evidence,
			prev_address: evidence,
			procedure_address: evidence,
			procedure_assembly: evidence,
			procedure_callees: evidence,
			procedure_callers: evidence,
			procedure_info: evidence,
			read_function_instructions: evidence,
			inspect_native_instruction: evidence,
			inspect_native_data_type: evidence,
			resolve_native_call_targets: evidence,
			read_bytes: evidence,
			search_bytes: evidence,
			address_to_file_offset: evidence,
			procedure_references: evidence,
			procedure_pseudo_code: evidence,
			resolve_containing_procedure: evidence,
			search_procedures: evidence,
			search_strings: evidence,
			set_address_name: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			set_addresses_names: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			set_bookmark: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			set_comment: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			set_inline_comment: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			unset_bookmark: effects({
				mutatesTarget: true,
				mutatesSession: true,
				mayDiscardData: true
			}),
			xrefs: evidence,
			get_objc_classes: evidence,
			get_objc_protocols: evidence,
			batch_decompile: evidence,
			get_call_graph: evidence,
			analyze_swift_types: evidence,
			find_xrefs_to_name: evidence,
			binary_overview: evidence,
			analyze_function: evidence,
			inspect_native_api: effects({
				mutatesSession: true,
				idempotent: false
			}),
			trace_feature: effects({
				mutatesSession: true,
				idempotent: false
			}),
			trace_call_path: effects({
				mutatesSession: true,
				idempotent: false
			}),
			observe_native_ui: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			capture_native_ui_scenario: effects({
				writesFilesystem: true,
				mutatesTarget: true,
				mutatesSession: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				mayDiscardData: true,
				executesForeignCode: true,
				idempotent: false
			}),
			observe_native_calls: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				executesForeignCode: true,
				idempotent: false
			}),
			inspect_macho: nativeEvidence,
			inspect_signature: nativeEvidence,
			inspect_plist: nativeEvidence,
			list_architectures: nativeEvidence,
			demangle_swift: nativeEvidence,
			inspect_artifact: effects({
				mutatesSession: true,
				launchesProcess: true,
				writesFilesystem: true
			}),
			extract_artifact: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				idempotent: false
			}),
			decode_interface_builder: evidence,
			inspect_asset_catalog: nativeEvidence,
			inspect_keyed_archive: evidence,
			trace_dylib_resolution: evidence,
			inspect_managed_artifact: evidence,
			inspect_managed_members: evidence,
			inspect_managed_native_boundaries: evidence,
			compare_managed_members: sessionEvidence,
			verify_managed_native_boundaries: sessionEvidence,
			import_managed_reconstruction: sessionEvidence,
			project_managed_application_graph: sessionEvidence,
			list_browser_targets: browserEvidence,
			inspect_web_page: browserEvidence,
			analyze_web_bundle: browserEvidence,
			observe_web_session: browserEvidence,
			discover_webmcp_tools: browserEvidence,
			compare_web_captures: sessionEvidence,
			capture_web_screenshot: browserEvidence,
			compare_web_screenshots: sessionEvidence,
			capture_browser_scenario: effects({
				mutatesTarget: true,
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				mayDiscardData: true,
				executesForeignCode: true,
				idempotent: false
			}),
			list_electron_targets: browserEvidence,
			inspect_electron_page: browserEvidence,
			capture_electron_scenario: effects({
				mutatesTarget: true,
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				changesUiState: true,
				mayDiscardData: true,
				executesForeignCode: true,
				idempotent: false
			}),
			list_javascript_runtime_targets: browserEvidence,
			observe_javascript_runtime: browserEvidence,
			analyze_javascript_application: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true
			}),
			inspect_electron_fuses: evidence,
			export_web_scripts: effects({
				mutatesSession: true,
				writesFilesystem: true,
				idempotent: false
			}),
			reconcile_javascript_runtime: evidence,
			recover_javascript_sources: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				idempotent: false
			}),
			trace_application_feature: evidence,
			trace_javascript_semantics: evidence,
			compare_application_versions: evidence,
			compare_source_to_bundle: evidence,
			compare_javascript_export_shapes: evidence,
			build_reconstruction_obligation_ledger: evidence,
			evaluate_reconstruction_coverage: effects(),
			project_android_application_graph: evidence,
			project_apple_application_graph: evidence,
			project_harmony_application_graph: evidence,
			open_binary: effects({
				mutatesSession: true,
				launchesProcess: true
			}),
			open_bundle_resources: effects({ mutatesSession: true }),
			close_binary: effects({
				mutatesSession: true,
				writesFilesystem: true,
				mayDiscardData: true,
				idempotent: false
			}),
			binary_session: effects({ launchesProcess: true }),
			export_evidence_bundle: effects({
				writesFilesystem: true,
				mayDiscardData: true
			}),
			get_evidence_bundle: effects(),
			get_navigation_context: effects({ mutatesSession: true }),
			inspect_address_context: effects({ mutatesSession: true }),
			import_evidence_bundle: effects({ mutatesSession: true }),
			capture_process_scenario: effects({
				mutatesSession: true,
				writesFilesystem: true,
				launchesProcess: true,
				accessesNetwork: true,
				executesForeignCode: true,
				idempotent: false
			}),
			compare_process_captures: sessionEvidence,
			compare_artifacts: sessionEvidence,
			compare_wasm_interfaces: sessionEvidence,
			compare_functions: sessionEvidence,
			match_native_functions: sessionEvidence,
			compare_bundles: effects({ mutatesSession: true }),
			find_changed_behavior: sessionEvidence,
			build_call_path: sessionEvidence,
			correlate_static_and_runtime: sessionEvidence,
			verify_reconstruction: sessionEvidence,
			list_unknowns: effects(),
			record_unknown: effects({
				mutatesSession: true,
				idempotent: false
			}),
			update_unknown: effects({
				mutatesSession: true,
				idempotent: false
			}),
			verify_unknown_resolution: effects()
		};
		annotationsFromEffects = (value) => ({
			readOnlyHint: !(value.mutatesTarget || value.mutatesSession || value.writesFilesystem || value.launchesProcess || value.accessesNetwork || value.changesUiState || value.mayDiscardData || value.executesForeignCode || value.mutatesDevice),
			destructiveHint: value.mayDiscardData || value.executesForeignCode || value.mutatesDevice,
			idempotentHint: value.idempotent,
			openWorldHint: value.launchesProcess || value.accessesNetwork
		});
		TARGET_CONTENT_FREE_TOOLS = new Set(["export_evidence_bundle", "record_unknown"]);
		toolReturnsTargetContent = (name) => !TARGET_CONTENT_FREE_TOOLS.has(name);
		toolContractMetadata = (name) => {
			const audited = TOOL_EFFECTS[name];
			if (audited === undefined) throw new Error(`Missing effect audit for ${name}`);
			return {
				title: name.split("_").map((word) => word[0]?.toUpperCase() + word.slice(1)).join(" "),
				effects: audited,
				annotations: annotationsFromEffects(audited),
				returnsTargetContent: toolReturnsTargetContent(name)
			};
		};
	})))();
}

//#endregion
//#region dist/contracts/analysisDetail.js
var analysisDetailSchema, analysisDetailOutputSchemaOf;
function init_analysisDetail() {
	return (init_analysisDetail = __esmMin((() => {
		init_toolOutputSchemaPrimitives();
		analysisDetailSchema = z.enum(["complete", "summary"]).default("complete").describe("complete returns the complete analysis Evidence inline. summary retains that complete Evidence in this session and returns its inspect_analysis_view summary; inspect pages, items or facets through normalized_result.parent_evidence_id.");
		analysisDetailOutputSchemaOf = (analysis, summary) => evidenceResultOf(z.union([analysis, summary]));
	})))();
}

//#endregion
//#region dist/domain/evidenceRecordSummary.js
var evidenceRecordFiltersSchema, countSchema, nativeMetadataSchema, valueFlowMetadataSchema, nativeSummarySchema, evidenceBundleSummarySchema, nativeSummary, summarizeEvidenceBundle;
function init_evidenceRecordSummary() {
	return (init_evidenceRecordSummary = __esmMin((() => {
		init_digests();
		init_evidence();
		evidenceRecordFiltersSchema = z.strictObject({
			evidence_id: prefixedDigestSchema("ev").optional(),
			operation: z.string().min(1).optional(),
			target_sha256: digestSchema.optional(),
			analysis_profile_digest: digestSchema.optional(),
			procedure_address: z.string().min(1).optional()
		});
		countSchema = z.number().int().nonnegative();
		nativeMetadataSchema = z.object({
			procedure: z.object({
				address: z.string(),
				name: z.string().nullish()
			}),
			native_value_flow: z.unknown().optional()
		});
		valueFlowMetadataSchema = z.union([z.object({
			available: z.literal(true),
			truncated: z.boolean(),
			omitted_operations_lower_bound: countSchema.optional(),
			known_omitted_inputs: countSchema.optional(),
			known_omitted_edges: countSchema.optional()
		}), z.object({
			available: z.literal(false),
			reason: z.string()
		})]);
		nativeSummarySchema = z.discriminatedUnion("available", [z.strictObject({
			available: z.literal(true),
			procedure_address: z.string(),
			procedure_name: z.string().nullable(),
			value_flow: z.discriminatedUnion("status", [
				z.strictObject({
					status: z.literal("observed"),
					truncated: z.boolean(),
					omitted_operations_lower_bound: countSchema.nullable(),
					known_omitted_inputs: countSchema.nullable(),
					known_omitted_edges: countSchema.nullable()
				}),
				z.strictObject({
					status: z.literal("unavailable"),
					reason: z.string()
				}),
				z.strictObject({ status: z.literal("not-recorded") }),
				z.strictObject({
					status: z.literal("unknown"),
					reason: z.string()
				})
			])
		}), z.strictObject({
			available: z.literal(false),
			reason: z.enum(["different-operation", "not-recorded-or-incompatible"])
		})]);
		evidenceBundleSummarySchema = z.strictObject({
			kind: z.literal("evidence-bundle-summary"),
			filters: z.record(z.string(), z.string()),
			total_retained_records: countSchema,
			matching_records: countSchema,
			unknown_revisions: countSchema,
			records: z.array(z.strictObject({
				evidence_id: evidenceSchema.shape.evidence_id,
				subject: evidenceSchema.shape.subject,
				provider: evidenceSchema.shape.provider,
				operation: evidenceSchema.shape.operation,
				confidence: evidenceSchema.shape.confidence,
				authority: evidenceSchema.shape.authority,
				analysis_profile_digest: digestSchema.nullable(),
				retention: z.literal("complete-record"),
				limitation_count: countSchema,
				native_dossier: nativeSummarySchema
			}))
		});
		nativeSummary = (evidence) => {
			if (evidence.operation !== "analyze_function") return {
				available: false,
				reason: "different-operation"
			};
			const parsed = nativeMetadataSchema.safeParse(evidence.normalized_result);
			if (!parsed.success) return {
				available: false,
				reason: "not-recorded-or-incompatible"
			};
			const flow = valueFlowMetadataSchema.safeParse(parsed.data.native_value_flow);
			return {
				available: true,
				procedure_address: parsed.data.procedure.address,
				procedure_name: parsed.data.procedure.name ?? null,
				value_flow: parsed.data.native_value_flow == null ? { status: "not-recorded" } : !flow.success ? {
					status: "unknown",
					reason: "Value-flow metadata has an incompatible representation."
				} : flow.data.available ? {
					status: "observed",
					truncated: flow.data.truncated,
					omitted_operations_lower_bound: flow.data.omitted_operations_lower_bound ?? null,
					known_omitted_inputs: flow.data.known_omitted_inputs ?? null,
					known_omitted_edges: flow.data.known_omitted_edges ?? null
				} : {
					status: "unavailable",
					reason: flow.data.reason
				}
			};
		};
		summarizeEvidenceBundle = (bundle, filters = {}) => {
			const selectedFilters = {};
			for (const [field, value] of Object.entries(filters)) if (value !== undefined) selectedFilters[field] = value;
			const records = [];
			for (const evidence of bundle.records) {
				if (filters.evidence_id !== undefined && filters.evidence_id !== evidence.evidence_id || filters.operation !== undefined && filters.operation !== evidence.operation || filters.target_sha256 !== undefined && filters.target_sha256 !== evidence.subject?.digest.sha256 || filters.analysis_profile_digest !== undefined && filters.analysis_profile_digest !== evidence.analysis_profile?.digest) continue;
				const native = nativeSummary(evidence);
				if (filters.procedure_address !== undefined && (!native.available || filters.procedure_address !== native.procedure_address)) continue;
				records.push({
					evidence_id: evidence.evidence_id,
					subject: evidence.subject,
					provider: evidence.provider,
					operation: evidence.operation,
					confidence: evidence.confidence,
					authority: evidence.authority,
					analysis_profile_digest: evidence.analysis_profile?.digest ?? null,
					retention: "complete-record",
					limitation_count: evidence.limitations.length,
					native_dossier: native
				});
			}
			return {
				kind: "evidence-bundle-summary",
				filters: selectedFilters,
				total_retained_records: bundle.records.length,
				matching_records: records.length,
				unknown_revisions: bundle.unknowns.length,
				records
			};
		};
	})))();
}

//#endregion
//#region dist/domain/comparisonStatus.js
var comparisonStatusSchema$2;
function init_comparisonStatus() {
	return (init_comparisonStatus = __esmMin((() => {
		comparisonStatusSchema$2 = z.enum([
			"unchanged",
			"changed",
			"unknown"
		]);
	})))();
}

//#endregion
//#region dist/domain/bundleComparison.js
var evidenceIdSchema$9, classificationSchema, bundleComparisonInputSchema, bundleChangeSchema, bundleComparisonResultSchema, compareBundles, compareRecords, compareUnknowns, unknownChange, histories, historyEvidenceIds, bundleDigest, same, isPrefix, ascii, compareChanges;
function init_bundleComparison() {
	return (init_bundleComparison = __esmMin((() => {
		init_evidenceBundle();
		init_digests();
		init_comparisonStatus();
		init_localPath();
		evidenceIdSchema$9 = prefixedDigestSchema("ev");
		classificationSchema = z.enum([
			"added",
			"removed",
			"changed",
			"unknown",
			"history_advanced",
			"history_diverged"
		]);
		bundleComparisonInputSchema = z.strictObject({
			left_bundle_path: localPathStringSchema,
			right_bundle_path: localPathStringSchema,
			record_pairs: z.array(z.object({
				left_evidence_id: evidenceIdSchema$9,
				right_evidence_id: evidenceIdSchema$9
			})).default([])
		});
		bundleChangeSchema = z.object({
			entity: z.enum(["evidence", "residual_unknown"]),
			key: z.string().min(1),
			classification: classificationSchema,
			conclusion_kind: z.enum([
				"observed_change",
				"contradiction",
				"unresolved_branch"
			]),
			left_evidence_ids: z.array(evidenceIdSchema$9),
			right_evidence_ids: z.array(evidenceIdSchema$9),
			left_digest: digestSchema.nullable(),
			right_digest: digestSchema.nullable(),
			limitations: z.array(z.string())
		});
		bundleComparisonResultSchema = z.object({
			status: comparisonStatusSchema$2,
			left_bundle_sha256: digestSchema,
			right_bundle_sha256: digestSchema,
			summary: z.object({
				records_unchanged: z.number().int().min(0),
				records_added: z.number().int().min(0),
				records_removed: z.number().int().min(0),
				records_changed: z.number().int().min(0),
				unknowns_unchanged: z.number().int().min(0),
				unknowns_added: z.number().int().min(0),
				unknowns_removed: z.number().int().min(0),
				unknowns_advanced: z.number().int().min(0),
				unknowns_diverged: z.number().int().min(0),
				unresolved: z.number().int().min(0)
			}),
			changes: z.array(bundleChangeSchema),
			limitations: z.array(z.string())
		});
		compareBundles = (leftInput, rightInput, recordPairs = []) => {
			const left = parseEvidenceBundle(leftInput);
			const right = parseEvidenceBundle(rightInput);
			const leftDigest = bundleDigest(left);
			const rightDigest = bundleDigest(right);
			const recordResult = compareRecords(left, right, recordPairs);
			const unknownResult = compareUnknowns(left, right);
			const changes = [...recordResult.changes, ...unknownResult.changes].sort(compareChanges);
			const unresolved = changes.filter(({ conclusion_kind: kind }) => kind !== "observed_change").length;
			return bundleComparisonResultSchema.parse({
				status: unresolved > 0 ? "unknown" : changes.length > 0 ? "changed" : "unchanged",
				left_bundle_sha256: leftDigest,
				right_bundle_sha256: rightDigest,
				summary: {
					...recordResult.summary,
					...unknownResult.summary,
					unresolved
				},
				changes,
				limitations: changes.some(({ limitations }) => limitations.length > 0) ? ["EvidenceBundle has no inventory completeness marker; one-sided membership remains unknown."] : []
			});
		};
		compareRecords = (left, right, pairs) => {
			const leftIds = new Set(left.records.map(({ evidence_id: id }) => id));
			const rightIds = new Set(right.records.map(({ evidence_id: id }) => id));
			const pairedLeft = new Set();
			const pairedRight = new Set();
			const changes = [];
			let changed = 0;
			for (const pair of pairs) {
				if (!leftIds.has(pair.left_evidence_id)) throw new TypeError(`Explicit pair references missing left evidence ${pair.left_evidence_id}`);
				if (!rightIds.has(pair.right_evidence_id)) throw new TypeError(`Explicit pair references missing right evidence ${pair.right_evidence_id}`);
				if (pairedLeft.has(pair.left_evidence_id) || pairedRight.has(pair.right_evidence_id)) throw new TypeError("Explicit evidence pairs must be one-to-one");
				pairedLeft.add(pair.left_evidence_id);
				pairedRight.add(pair.right_evidence_id);
				if (pair.left_evidence_id === pair.right_evidence_id) continue;
				changed += 1;
				changes.push({
					entity: "evidence",
					key: `pair:${pair.left_evidence_id}:${pair.right_evidence_id}`,
					classification: "changed",
					conclusion_kind: "observed_change",
					left_evidence_ids: [pair.left_evidence_id],
					right_evidence_ids: [pair.right_evidence_id],
					left_digest: pair.left_evidence_id.slice(3),
					right_digest: pair.right_evidence_id.slice(3),
					limitations: []
				});
			}
			const common = [...leftIds].filter((id) => rightIds.has(id) && !pairedLeft.has(id) && !pairedRight.has(id));
			const removed = [...leftIds].filter((id) => !pairedLeft.has(id) && (!rightIds.has(id) || pairedRight.has(id)));
			const added = [...rightIds].filter((id) => !pairedRight.has(id) && (!leftIds.has(id) || pairedLeft.has(id)));
			for (const [ids, side] of [[removed, "left"], [added, "right"]]) for (const id of ids) changes.push({
				entity: "evidence",
				key: id,
				classification: "unknown",
				conclusion_kind: "unresolved_branch",
				left_evidence_ids: side === "left" ? [id] : [],
				right_evidence_ids: side === "right" ? [id] : [],
				left_digest: side === "left" ? id.slice(3) : null,
				right_digest: side === "right" ? id.slice(3) : null,
				limitations: ["EvidenceBundle has no inventory completeness marker; one-sided membership may reflect incomplete capture."]
			});
			return {
				changes,
				summary: {
					records_unchanged: common.length + pairs.length - changed,
					records_added: 0,
					records_removed: 0,
					records_changed: changed
				}
			};
		};
		compareUnknowns = (left, right) => {
			const leftHistories = histories(left.unknowns);
			const rightHistories = histories(right.unknowns);
			const ids = [...new Set([...leftHistories.keys(), ...rightHistories.keys()])];
			const changes = [];
			const summary = {
				unknowns_unchanged: 0,
				unknowns_added: 0,
				unknowns_removed: 0,
				unknowns_advanced: 0,
				unknowns_diverged: 0
			};
			for (const id of ids) {
				const leftHistory = leftHistories.get(id);
				const rightHistory = rightHistories.get(id);
				if (leftHistory === undefined || rightHistory === undefined) {
					changes.push(unknownChange(id, "unknown", leftHistory, rightHistory));
					continue;
				}
				const leftDigests = leftHistory.map(({ revision_digest: digest }) => digest);
				const rightDigests = rightHistory.map(({ revision_digest: digest }) => digest);
				if (same(leftDigests, rightDigests)) {
					summary.unknowns_unchanged += 1;
					continue;
				}
				const advanced = isPrefix(leftDigests, rightDigests) || isPrefix(rightDigests, leftDigests);
				summary[advanced ? "unknowns_advanced" : "unknowns_diverged"] += 1;
				changes.push(unknownChange(id, advanced ? "history_advanced" : "history_diverged", leftHistory, rightHistory));
			}
			return {
				changes,
				summary
			};
		};
		unknownChange = (id, classification, left, right) => ({
			entity: "residual_unknown",
			key: id,
			classification,
			conclusion_kind: classification === "history_diverged" ? "contradiction" : classification === "history_advanced" ? "observed_change" : "unresolved_branch",
			left_evidence_ids: historyEvidenceIds(left ?? []),
			right_evidence_ids: historyEvidenceIds(right ?? []),
			left_digest: left?.at(-1)?.revision_digest ?? null,
			right_digest: right?.at(-1)?.revision_digest ?? null,
			limitations: left === undefined || right === undefined ? ["EvidenceBundle has no inventory completeness marker; one-sided history membership remains unknown."] : []
		});
		histories = (unknowns) => {
			const output = new Map();
			for (const unknown of unknowns) {
				const history = output.get(unknown.unknown_id) ?? [];
				history.push(unknown);
				output.set(unknown.unknown_id, history);
			}
			return output;
		};
		historyEvidenceIds = (history) => [...new Set(history.flatMap((item) => [
			...item.supporting_evidence_ids,
			...item.contradicting_evidence_ids,
			...item.mutation_evidence_ids,
			...item.resolution?.evidence_ids ?? []
		]))].sort(ascii);
		bundleDigest = (bundle) => createHash("sha256").update(serializeEvidenceBundle(bundle)).digest("hex");
		same = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);
		isPrefix = (shorter, longer) => shorter.length < longer.length && shorter.every((value, index) => value === longer[index]);
		ascii = (left, right) => left < right ? -1 : left > right ? 1 : 0;
		compareChanges = (left, right) => ascii([
			left.entity,
			left.key,
			left.classification,
			left.left_digest ?? "",
			left.right_digest ?? ""
		].join("\0"), [
			right.entity,
			right.key,
			right.classification,
			right.left_digest ?? "",
			right.right_digest ?? ""
		].join("\0"));
	})))();
}

//#endregion
//#region dist/domain/process/processObservation.js
var comparableTerminalFrame, processObservationSourceSchema, processObservationLocationSchema, comparableProcessObservationPayload, createProcessObservation, atMilliseconds, isSafeMillisecond, processObservationSubject, projectedRecord, projectProcessObservation;
function init_processObservation() {
	return (init_processObservation = __esmMin((() => {
		init_jsonValue();
		comparableTerminalFrame = (frame) => ({
			sequence: frame.sequence,
			at_ms: frame.at_ms,
			data: frame.data
		});
		processObservationSourceSchema = z.enum([
			"terminal_raw",
			"terminal_rendered",
			"interaction",
			"lifecycle",
			"process",
			"filesystem"
		]);
		processObservationLocationSchema = z.strictObject({
			collection: z.enum([
				"frames",
				"rendered_frames",
				"interaction_events",
				"lifecycle",
				"process_samples",
				"filesystem_checkpoints"
			]),
			index: z.number().int().nonnegative(),
			capture_order: z.number().int().nonnegative()
		});
		comparableProcessObservationPayload = (value, ignoredFields = []) => {
			if (ignoredFields.length === 0 || typeof value !== "object" || value === null || Array.isArray(value)) return value;
			return Object.fromEntries(Object.entries(value).filter(([name]) => !ignoredFields.includes(name)));
		};
		createProcessObservation = (input) => ({
			event_id: `obs.${input.location.collection}.${String(input.location.index)}`,
			source: input.source,
			source_sequence: input.source_sequence,
			capture_order: input.location.capture_order,
			captured_at_ms: input.captured_at_ms,
			subject_id: input.subject_id,
			location: input.location,
			payload: jsonValueSchema.parse(input.payload)
		});
		atMilliseconds = (value) => {
			if (typeof value !== "object" || value === null) return null;
			if ("at_ms" in value && isSafeMillisecond(value.at_ms)) return value.at_ms;
			if ("dispatched_at_ms" in value && isSafeMillisecond(value.dispatched_at_ms)) return value.dispatched_at_ms;
			return null;
		};
		isSafeMillisecond = (value) => typeof value === "number" && Number.isSafeInteger(value);
		processObservationSubject = (source, value) => {
			if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
			if (source === "process" && "pid" in value && typeof value.pid === "number") return `process:${String(value.pid)}`;
			if (source === "filesystem" && "name" in value && typeof value.name === "string") return `checkpoint:${value.name}`;
			return null;
		};
		projectedRecord = (capture, location) => {
			const projected = (() => {
				switch (location.collection) {
					case "frames": {
						const frame = capture.frames[location.index];
						return {
							source: "terminal_raw",
							value: frame === undefined ? undefined : comparableTerminalFrame(frame)
						};
					}
					case "rendered_frames": return {
						source: "terminal_rendered",
						value: capture.rendered_frames[location.index]
					};
					case "interaction_events": return {
						source: "interaction",
						value: capture.interaction_events[location.index]
					};
					case "lifecycle": return location.index === 0 ? {
						source: "lifecycle",
						value: {
							event: "exit",
							...capture.exit
						}
					} : location.index === 1 ? {
						source: "lifecycle",
						value: {
							event: "settlement",
							...capture.settlement
						}
					} : null;
					case "process_samples": return {
						source: "process",
						value: capture.process_samples[location.index]
					};
					case "filesystem_checkpoints": return {
						source: "filesystem",
						value: capture.filesystem_checkpoints[location.index]
					};
				}
			})();
			if (projected === null || projected.value === undefined) return null;
			const payload = jsonValueSchema.parse(projected.value);
			return {
				source: projected.source,
				captured_at_ms: atMilliseconds(payload),
				subject_id: processObservationSubject(projected.source, payload),
				payload
			};
		};
		projectProcessObservation = (capture, location) => {
			const projected = projectedRecord(capture, location);
			if (projected === null) return null;
			return createProcessObservation({
				source: projected.source,
				source_sequence: location.index,
				captured_at_ms: projected.captured_at_ms,
				subject_id: projected.subject_id,
				location,
				payload: projected.payload
			});
		};
	})))();
}

//#endregion
//#region dist/domain/process/processTraceSpecification.js
var processTraceIdentifierSchema, cardinalitySchema, eventDeclarationSchema, partialOrderLanguageSchema, finiteTraceTokenSchema, finiteTraceLanguageSchema, specificationShapeSchema, canonicalTraceJson, processTraceCardinalityBounds, addReferenceIssue, pairKey, buildAdjacency, validateNotBefore, classifyGraph, collectReachable, validateUnorderedGroups, validateTotalOrderRelations, addUnorderedConflictIssues, validatePartialOrderRelations, validatePartialOrder, countVariantEvents, validateFiniteTraces, processTraceSpecificationSchema;
function init_processTraceSpecification() {
	return (init_processTraceSpecification = __esmMin((() => {
		init_stringPatterns();
		init_jsonValue();
		init_processObservation();
		processTraceIdentifierSchema = z.string().regex(IDENTIFIER_PATTERN);
		cardinalitySchema = z.discriminatedUnion("kind", [
			z.strictObject({ kind: z.literal("required") }),
			z.strictObject({ kind: z.literal("optional") }),
			z.strictObject({
				kind: z.literal("exact"),
				count: z.number().int().min(0)
			}),
			z.strictObject({
				kind: z.literal("range"),
				min: z.number().int().min(0),
				max: z.number().int().min(0)
			}).refine(({ min, max }) => min <= max, {
				message: "cardinality min must not exceed max",
				path: ["min"]
			})
		]);
		eventDeclarationSchema = z.strictObject({
			id: processTraceIdentifierSchema,
			source: processObservationSourceSchema,
			exact: jsonValueSchema,
			ignore_fields: z.array(z.enum([
				"sequence",
				"at_ms",
				"scheduled_at_ms",
				"dispatched_at_ms",
				"elapsed_ms"
			])).refine((values) => new Set(values).size === values.length, { message: "ignored event fields must be unique" }).optional(),
			cardinality: cardinalitySchema.default({ kind: "required" })
		});
		partialOrderLanguageSchema = z.strictObject({
			kind: z.literal("partial_order"),
			happens_before: z.array(z.strictObject({
				before: processTraceIdentifierSchema,
				after: processTraceIdentifierSchema
			})).default([]),
			not_before: z.array(z.strictObject({
				event: processTraceIdentifierSchema,
				anchor: processTraceIdentifierSchema
			})).default([]),
			unordered_groups: z.array(z.strictObject({ events: z.array(processTraceIdentifierSchema).min(2) })).default([]),
			prefix: z.array(processTraceIdentifierSchema).default([]),
			suffix: z.array(processTraceIdentifierSchema).default([])
		});
		finiteTraceTokenSchema = z.union([processTraceIdentifierSchema, z.strictObject({ unordered: z.array(processTraceIdentifierSchema).min(2) })]);
		finiteTraceLanguageSchema = z.strictObject({
			kind: z.literal("finite_traces"),
			variants: z.array(z.strictObject({
				id: processTraceIdentifierSchema,
				trace: z.array(finiteTraceTokenSchema)
			})).min(1)
		});
		specificationShapeSchema = z.strictObject({
			events: z.array(eventDeclarationSchema).min(1),
			language: z.discriminatedUnion("kind", [partialOrderLanguageSchema, finiteTraceLanguageSchema])
		});
		canonicalTraceJson = (value) => {
			const serialized = canonicalize(value);
			if (serialized === undefined) throw new TypeError("Trace specification contains a non-JSON value");
			return serialized;
		};
		processTraceCardinalityBounds = (cardinality) => {
			switch (cardinality.kind) {
				case "required": return [1, 1];
				case "optional": return [0, 1];
				case "exact": return [cardinality.count, cardinality.count];
				case "range": return [cardinality.min, cardinality.max];
			}
		};
		addReferenceIssue = (context, known, id, path) => {
			if (!known.has(id)) context.addIssue({
				code: "custom",
				message: `unknown event id: ${id}`,
				path
			});
		};
		pairKey = (left, right) => left <= right ? `${left}\0${right}` : `${right}\0${left}`;
		buildAdjacency = (language, context, known) => {
			const adjacency = new Map([...known].map((id) => [id, new Set()]));
			for (const [index, edge] of language.happens_before.entries()) {
				const path = [
					"language",
					"happens_before",
					index
				];
				addReferenceIssue(context, known, edge.before, [...path, "before"]);
				addReferenceIssue(context, known, edge.after, [...path, "after"]);
				if (edge.before === edge.after) context.addIssue({
					code: "custom",
					message: "happens-before edges must reference distinct events",
					path
				});
				adjacency.get(edge.before)?.add(edge.after);
			}
			return adjacency;
		};
		validateNotBefore = (language, context, known) => {
			const pairs = new Set();
			for (const [index, constraint] of language.not_before.entries()) {
				const path = [
					"language",
					"not_before",
					index
				];
				addReferenceIssue(context, known, constraint.event, [...path, "event"]);
				addReferenceIssue(context, known, constraint.anchor, [...path, "anchor"]);
				if (constraint.event === constraint.anchor) context.addIssue({
					code: "custom",
					message: "not-before constraints must reference distinct events",
					path
				});
				const key = pairKey(constraint.event, constraint.anchor);
				if (pairs.has(key)) context.addIssue({
					code: "custom",
					message: "not-before event pairs must be declared once",
					path
				});
				pairs.add(key);
			}
			return pairs;
		};
		classifyGraph = (ids, adjacency) => {
			const incoming = new Map(ids.map((id) => [id, 0]));
			let hasUnknownSuccessor = false;
			for (const successors of adjacency.values()) for (const successor of successors) {
				const count = incoming.get(successor);
				if (count === undefined) hasUnknownSuccessor = true;
				else incoming.set(successor, count + 1);
			}
			const ready = [...incoming].flatMap(([id, count]) => count === 0 ? [id] : []);
			const order = [];
			let unique = true;
			while (ready.length > 0) {
				if (ready.length !== 1) unique = false;
				const current = ready.pop();
				if (current === undefined) continue;
				order.push(current);
				for (const successor of adjacency.get(current) ?? []) {
					const count = incoming.get(successor);
					if (count === undefined) continue;
					incoming.set(successor, count - 1);
					if (count === 1) ready.push(successor);
				}
			}
			if (order.length !== incoming.size) return { kind: "cyclic" };
			if (unique && order.length === ids.length && !hasUnknownSuccessor) {
				return {
					kind: "total-order",
					rank: new Map(order.map((id, index) => [id, index]))
				};
			}
			const reverseAdjacency = new Map([...incoming.keys()].map((id) => [id, new Set()]));
			for (const [before, successors] of adjacency) for (const after of successors) reverseAdjacency.get(after)?.add(before);
			return {
				kind: "partial-order",
				reverseAdjacency
			};
		};
		collectReachable = (origin, adjacency) => {
			const seen = new Set();
			const pending = [...adjacency.get(origin) ?? []];
			while (pending.length > 0) {
				const current = pending.pop();
				if (current === undefined || seen.has(current)) continue;
				seen.add(current);
				for (const successor of adjacency.get(current) ?? []) pending.push(successor);
			}
			return seen;
		};
		validateUnorderedGroups = (language, context, known) => {
			const memberships = new Map();
			const groups = [];
			const repeatedMemberships = new Map();
			for (const [groupIndex, group] of language.unordered_groups.entries()) {
				const path = [
					"language",
					"unordered_groups",
					groupIndex
				];
				const uniqueIds = new Set();
				const repeatedIds = new Set();
				for (const id of group.events) {
					if (uniqueIds.has(id)) repeatedIds.add(id);
					else uniqueIds.add(id);
				}
				groups.push(uniqueIds);
				for (const id of repeatedIds) {
					const groupIndexes = repeatedMemberships.get(id) ?? new Set();
					groupIndexes.add(groupIndex);
					repeatedMemberships.set(id, groupIndexes);
				}
				if (uniqueIds.size !== group.events.length) context.addIssue({
					code: "custom",
					message: "unordered groups must not repeat event ids",
					path: [...path, "events"]
				});
				for (const [eventIndex, id] of group.events.entries()) addReferenceIssue(context, known, id, [
					...path,
					"events",
					eventIndex
				]);
				const overlaps = new Map();
				for (const id of uniqueIds) {
					const priorGroups = memberships.get(id) ?? new Set();
					for (const prior of priorGroups) overlaps.set(prior, (overlaps.get(prior) ?? 0) + 1);
					priorGroups.add(groupIndex);
					memberships.set(id, priorGroups);
				}
				if ([...overlaps.values()].some((count) => count > 1)) context.addIssue({
					code: "custom",
					message: "unordered event pairs must be declared once",
					path
				});
			}
			const markSharedGroups = (left, right, conflicts) => {
				if (left === right) {
					for (const groupIndex of repeatedMemberships.get(left) ?? []) conflicts[groupIndex] = true;
					return;
				}
				const rightGroups = memberships.get(right);
				for (const group of memberships.get(left) ?? []) if (rightGroups?.has(group) === true) conflicts[group] = true;
			};
			return {
				groups,
				hasPair(left, right) {
					if (left === right) return memberships.has(left);
					const rightGroups = memberships.get(right);
					for (const group of memberships.get(left) ?? []) if (rightGroups?.has(group) === true) return true;
					return false;
				},
				markDeclaredPairConflicts(pairs, conflicts) {
					for (const key of pairs) {
						const separator = key.indexOf("\0");
						const left = key.slice(0, separator);
						const right = key.slice(separator + 1);
						markSharedGroups(left, right, conflicts);
					}
				},
				markSharedGroups
			};
		};
		validateTotalOrderRelations = (language, graph, unorderedGroups, notBeforePairs, context) => {
			for (const [index, constraint] of language.not_before.entries()) {
				const before = graph.rank.get(constraint.event);
				const after = graph.rank.get(constraint.anchor);
				if (before !== undefined && after !== undefined && before < after) context.addIssue({
					code: "custom",
					message: "not-before constraint conflicts with happens-before order",
					path: [
						"language",
						"not_before",
						index
					]
				});
			}
			const conflicts = new Array(language.unordered_groups.length).fill(false);
			for (const [groupIndex, group] of unorderedGroups.groups.entries()) {
				let comparableEvents = 0;
				for (const id of group) if (graph.rank.has(id) && ++comparableEvents === 2) {
					conflicts[groupIndex] = true;
					break;
				}
			}
			unorderedGroups.markDeclaredPairConflicts(notBeforePairs, conflicts);
			addUnorderedConflictIssues(conflicts, context);
		};
		addUnorderedConflictIssues = (conflicts, context) => {
			for (const [groupIndex, conflict] of conflicts.entries()) if (conflict) context.addIssue({
				code: "custom",
				message: "ordered events cannot also be declared unordered",
				path: [
					"language",
					"unordered_groups",
					groupIndex
				]
			});
		};
		validatePartialOrderRelations = (ids, language, adjacency, graph, unorderedGroups, notBeforePairs, context) => {
			let missingPairCount = 0;
			let firstMissingPair = "";
			const groupConflicts = new Array(language.unordered_groups.length).fill(false);
			unorderedGroups.markDeclaredPairConflicts(notBeforePairs, groupConflicts);
			const notBeforeConflictFlags = new Uint8Array(language.not_before.length);
			const constraintsBySource = new Map();
			for (const [index, constraint] of language.not_before.entries()) {
				const indexes = constraintsBySource.get(constraint.event) ?? [];
				indexes.push(index);
				constraintsBySource.set(constraint.event, indexes);
			}
			for (const [leftIndex, leftId] of ids.entries()) {
				const forward = collectReachable(leftId, adjacency);
				const backward = collectReachable(leftId, graph.reverseAdjacency);
				for (const constraintIndex of constraintsBySource.get(leftId) ?? []) {
					const constraint = language.not_before[constraintIndex];
					if (constraint !== undefined && forward.has(constraint.anchor)) notBeforeConflictFlags[constraintIndex] = 1;
				}
				for (let rightIndex = leftIndex + 1; rightIndex < ids.length; rightIndex++) {
					const rightId = ids[rightIndex];
					if (rightId === undefined) continue;
					const sameEvent = leftId === rightId;
					const ordered = !sameEvent && (forward.has(rightId) || backward.has(rightId));
					const key = pairKey(leftId, rightId);
					const notBefore = notBeforePairs.has(key);
					const unordered = unorderedGroups.hasPair(leftId, rightId);
					if (ordered || notBefore) {
						if (!sameEvent) unorderedGroups.markSharedGroups(leftId, rightId, groupConflicts);
					}
					if (!ordered && !notBefore && !unordered) {
						if (missingPairCount === 0) firstMissingPair = `${leftId}/${rightId}`;
						missingPairCount++;
					}
				}
			}
			for (const [index, conflict] of notBeforeConflictFlags.entries()) if (conflict === 1) context.addIssue({
				code: "custom",
				message: "not-before constraint conflicts with happens-before order",
				path: [
					"language",
					"not_before",
					index
				]
			});
			addUnorderedConflictIssues(groupConflicts, context);
			if (missingPairCount > 0) context.addIssue({
				code: "custom",
				message: missingPairCount === 1 ? `event pair ${firstMissingPair} must be explicitly ordered or unordered` : `${String(missingPairCount)} event pairs must be explicitly ordered or unordered; first undeclared pair: ${firstMissingPair}`,
				path: ["language"]
			});
		};
		validatePartialOrder = (specification, context) => {
			if (specification.language.kind !== "partial_order") return;
			const ids = specification.events.map(({ id }) => id);
			const known = new Set(ids);
			const adjacency = buildAdjacency(specification.language, context, known);
			const graph = classifyGraph(ids, adjacency);
			if (graph.kind === "cyclic") context.addIssue({
				code: "custom",
				message: "happens-before graph must be acyclic",
				path: ["language"]
			});
			const notBeforePairs = validateNotBefore(specification.language, context, known);
			const unorderedGroups = validateUnorderedGroups(specification.language, context, known);
			if (graph.kind === "total-order") {
				validateTotalOrderRelations(specification.language, graph, unorderedGroups, notBeforePairs, context);
			} else if (graph.kind === "partial-order") {
				validatePartialOrderRelations(ids, specification.language, adjacency, graph, unorderedGroups, notBeforePairs, context);
			}
			for (const [kind, values] of [["prefix", specification.language.prefix], ["suffix", specification.language.suffix]]) for (const [index, id] of values.entries()) addReferenceIssue(context, known, id, [
				"language",
				kind,
				index
			]);
		};
		countVariantEvents = (trace) => {
			const counts = new Map();
			for (const token of trace) for (const id of typeof token === "string" ? [token] : token.unordered) counts.set(id, (counts.get(id) ?? 0) + 1);
			return counts;
		};
		validateFiniteTraces = (specification, context) => {
			if (specification.language.kind !== "finite_traces") return;
			const known = new Set(specification.events.map(({ id }) => id));
			const variantIds = new Set();
			const variantTraces = new Set();
			for (const [variantIndex, variant] of specification.language.variants.entries()) {
				const variantPath = [
					"language",
					"variants",
					variantIndex
				];
				if (variantIds.has(variant.id)) context.addIssue({
					code: "custom",
					message: "finite trace variant ids must be unique",
					path: [...variantPath, "id"]
				});
				variantIds.add(variant.id);
				const canonicalTrace = canonicalTraceJson(variant.trace);
				if (variantTraces.has(canonicalTrace)) context.addIssue({
					code: "custom",
					message: "finite trace variants must not duplicate a trace",
					path: [...variantPath, "trace"]
				});
				variantTraces.add(canonicalTrace);
				for (const [tokenIndex, token] of variant.trace.entries()) {
					const values = typeof token === "string" ? [token] : token.unordered;
					for (const [eventIndex, id] of values.entries()) addReferenceIssue(context, known, id, [
						...variantPath,
						"trace",
						tokenIndex,
						...typeof token === "string" ? [] : ["unordered", eventIndex]
					]);
				}
				const counts = countVariantEvents(variant.trace);
				for (const event of specification.events) {
					const [minimum, maximum] = processTraceCardinalityBounds(event.cardinality);
					const count = counts.get(event.id) ?? 0;
					if (count < minimum || count > maximum) context.addIssue({
						code: "custom",
						message: `variant ${variant.id} violates ${event.id} cardinality`,
						path: [...variantPath, "trace"]
					});
				}
			}
		};
		processTraceSpecificationSchema = specificationShapeSchema.superRefine((specification, context) => {
			const ids = new Set();
			const predicates = new Set();
			const ignoredFieldsBySource = new Map();
			for (const [index, event] of specification.events.entries()) {
				if (ids.has(event.id)) context.addIssue({
					code: "custom",
					message: "event ids must be unique",
					path: [
						"events",
						index,
						"id"
					]
				});
				ids.add(event.id);
				const ignoredFields = [...event.ignore_fields ?? []].sort();
				if (ignoredFields.length > 0 && (typeof event.exact !== "object" || event.exact === null || Array.isArray(event.exact))) context.addIssue({
					code: "custom",
					message: "ignored schedule fields require an exact object payload",
					path: [
						"events",
						index,
						"ignore_fields"
					]
				});
				const ignoredKey = canonicalTraceJson(ignoredFields);
				const priorIgnoredKey = ignoredFieldsBySource.get(event.source);
				if (priorIgnoredKey !== undefined && priorIgnoredKey !== ignoredKey) context.addIssue({
					code: "custom",
					message: "events from one source must use the same ignored schedule fields",
					path: [
						"events",
						index,
						"ignore_fields"
					]
				});
				ignoredFieldsBySource.set(event.source, ignoredKey);
				if (ignoredFields.some((field) => typeof event.exact === "object" && event.exact !== null && !Array.isArray(event.exact) && field in event.exact)) context.addIssue({
					code: "custom",
					message: "exact payload must omit every ignored schedule field",
					path: [
						"events",
						index,
						"exact"
					]
				});
				const predicate = `${event.source}\0${canonicalTraceJson(comparableProcessObservationPayload(event.exact, ignoredFields))}`;
				if (predicates.has(predicate)) context.addIssue({
					code: "custom",
					message: "exact event predicates must not overlap",
					path: ["events", index]
				});
				predicates.add(predicate);
			}
			validatePartialOrder(specification, context);
			validateFiniteTraces(specification, context);
		});
	})))();
}

//#endregion
//#region dist/domain/rawBinary.js
var BINARY_ARCHITECTURES, binaryArchitectureSchema, RAW_BINARY_ENTRY_POINT, rawBinaryEntryPointSchema, parseRawBinaryEntryPoint, validateRawBinaryLength, addressWidth, admitRawBinary, rawBinarySelectionError;
function init_rawBinary() {
	return (init_rawBinary = __esmMin((() => {
		init_result();
		BINARY_ARCHITECTURES = [
			"x86",
			"x86_64",
			"arm",
			"arm64",
			"6502",
			"m68k"
		];
		binaryArchitectureSchema = z.enum(BINARY_ARCHITECTURES);
		RAW_BINARY_ENTRY_POINT = /^0x[0-9A-Fa-f]{1,16}$/u;
		rawBinaryEntryPointSchema = z.string().regex(RAW_BINARY_ENTRY_POINT, { message: "entry_point must be a hexadecimal address of the form 0x…" });
		parseRawBinaryEntryPoint = (value) => {
			if (!RAW_BINARY_ENTRY_POINT.test(value)) return err("entry_point must be a hexadecimal address of the form 0x…");
			const parsed = BigInt(value);
			return ok({
				source: value,
				canonical: `0x${parsed.toString(16)}`,
				value: parsed
			});
		};
		validateRawBinaryLength = (length) => Number.isSafeInteger(length) && length >= 1 ? ok(null) : err("raw-binary requires at least one file byte");
		addressWidth = (architecture) => architecture === "6502" ? 65535n : architecture === "x86" || architecture === "arm" || architecture === "m68k" ? 4294967295n : 18446744073709551615n;
		admitRawBinary = (input) => {
			const architecture = binaryArchitectureSchema.safeParse(input.architecture);
			if (!architecture.success) return err({
				reason: "raw-binary format requires architecture (x86, x86_64, arm, arm64, 6502, or m68k)",
				constraint: "load_selection_rejected"
			});
			if (typeof input.entryPoint !== "string") return err({
				reason: "raw-binary format requires entry_point as a hexadecimal address of the form 0x…",
				constraint: "load_selection_rejected"
			});
			const entry = parseRawBinaryEntryPoint(input.entryPoint);
			if (!entry.ok) return err({
				reason: entry.error,
				constraint: "load_selection_rejected"
			});
			if ((architecture.data === "arm" || architecture.data === "arm64") && entry.value.value % 4n !== 0n) return err({
				reason: `raw-binary ${architecture.data} entry_point ${entry.value.canonical} must be 4-byte aligned`,
				constraint: "load_selection_rejected"
			});
			if (architecture.data === "m68k" && entry.value.value % 2n !== 0n) return err({
				reason: `raw-binary m68k entry_point ${entry.value.canonical} must be 2-byte aligned`,
				constraint: "load_selection_rejected"
			});
			const length = validateRawBinaryLength(input.fileBytes);
			if (!length.ok) return err({
				reason: length.error,
				constraint: "file_format_rejected"
			});
			const last = entry.value.value + BigInt(input.fileBytes) - 1n;
			const max = addressWidth(architecture.data);
			if (entry.value.value > max || last > max) return err({
				reason: `raw-binary mapping from ${entry.value.canonical} must fit in the ${architecture.data} address width`,
				constraint: "load_selection_rejected"
			});
			return ok({
				architecture: architecture.data,
				entryPoint: entry.value.canonical,
				entryPointSource: entry.value.source
			});
		};
		rawBinarySelectionError = (input) => {
			const hasArchitecture = input.architecture !== undefined;
			const hasEntry = input.entryPoint !== undefined;
			if (input.format === "raw-binary") {
				if (!hasArchitecture || !hasEntry) return "format=raw-binary requires architecture and entry_point";
				return undefined;
			}
			if (hasArchitecture || hasEntry) return "architecture and entry_point apply only with format=raw-binary";
			return undefined;
		};
	})))();
}

//#endregion
//#region dist/domain/pngHeader.js
var PNG_SIGNATURE, IHDR_TYPE, readPngHeaderDimensions;
function init_pngHeader() {
	return (init_pngHeader = __esmMin((() => {
		PNG_SIGNATURE = Buffer.from([
			137,
			80,
			78,
			71,
			13,
			10,
			26,
			10
		]);
		IHDR_TYPE = Buffer.from("IHDR");
		readPngHeaderDimensions = (bytes) => {
			if (bytes.byteLength < 24 || !bytes.subarray(0, 8).equals(PNG_SIGNATURE) || bytes.readUInt32BE(8) !== 13 || !bytes.subarray(12, 16).equals(IHDR_TYPE)) return undefined;
			const width = bytes.readUInt32BE(16);
			const height = bytes.readUInt32BE(20);
			return width === 0 || height === 0 || width > 2147483647 || height > 2147483647 ? undefined : {
				width,
				height
			};
		};
	})))();
}

//#endregion
//#region dist/domain/native/nativeUiObservation.js
var scope, nativeUiObservationInputSchema, nativeUiScenarioInputSchema, nativeUiScreenshotSchema, nativeUiSnapshotSchema, nativeUiResultSchema;
function init_nativeUiObservation() {
	return (init_nativeUiObservation = __esmMin((() => {
		init_webScreenshot();
		init_pngHeader();
		scope = {
			pid: z.number().int().positive(),
			window_id: z.number().int().positive(),
			screenshot: z.boolean().default(true),
			accessibility: z.boolean().default(true),
			max_nodes: z.number().int().positive().safe().default(500).describe("Maximum accessibility nodes per capture; increase for large windows.")
		};
		nativeUiObservationInputSchema = z.strictObject(scope);
		nativeUiScenarioInputSchema = z.strictObject({
			...scope,
			steps: z.array(z.discriminatedUnion("kind", [
				z.strictObject({
					kind: z.literal("click"),
					path: z.array(z.number().int().nonnegative()).max(32)
				}),
				z.strictObject({
					kind: z.literal("scroll"),
					path: z.array(z.number().int().nonnegative()).max(32),
					direction: z.enum(["increment", "decrement"])
				}),
				z.strictObject({
					kind: z.literal("key-entry"),
					path: z.array(z.number().int().nonnegative()).max(32),
					text: z.string()
				}),
				z.strictObject({
					kind: z.literal("wait"),
					milliseconds: z.number().int().min(0).max(18e4).describe("Wait duration in milliseconds, within the 180-second operation deadline.")
				})
			])).min(1)
		});
		nativeUiScreenshotSchema = z.strictObject({
			mime_type: z.literal("image/png"),
			base64: z.string().min(4).describe("Canonical base64 encoding of PNG bytes; the decoded bytes must have a PNG signature and IHDR chunk."),
			sha256: z.string().regex(/^[a-f0-9]{64}$/u).describe("SHA-256 digest of the decoded PNG bytes."),
			width: z.number().int().positive().describe("Must equal the width encoded in the PNG IHDR chunk."),
			height: z.number().int().positive().describe("Must equal the height encoded in the PNG IHDR chunk.")
		}).superRefine((screenshot, context) => {
			const bytes = decodeCanonicalBase64(screenshot.base64);
			if (bytes === undefined) {
				context.addIssue({
					code: "custom",
					message: "Invalid canonical PNG base64"
				});
				return;
			}
			if (createHash("sha256").update(bytes).digest("hex") !== screenshot.sha256) context.addIssue({
				code: "custom",
				message: "PNG screenshot digest mismatch"
			});
			const dimensions = readPngHeaderDimensions(bytes);
			if (dimensions === undefined) {
				context.addIssue({
					code: "custom",
					message: "Screenshot bytes are not a PNG image"
				});
				return;
			}
			if (dimensions.width !== screenshot.width || dimensions.height !== screenshot.height) context.addIssue({
				code: "custom",
				message: "PNG screenshot dimensions mismatch"
			});
		});
		nativeUiSnapshotSchema = z.strictObject({
			window: z.strictObject({
				pid: z.number().int().positive(),
				window_id: z.number().int().positive(),
				executable: z.string(),
				launch_time: z.number(),
				title: z.string()
			}),
			nodes: z.array(z.strictObject({
				path: z.array(z.number().int().nonnegative()),
				role: z.string().nullable(),
				title: z.string().nullable(),
				value: z.string().nullable(),
				actions: z.array(z.string()),
				children_count: z.number().int().nonnegative().nullable()
			})),
			truncated: z.boolean(),
			screenshot: nativeUiScreenshotSchema.nullable(),
			gaps: z.array(z.string())
		});
		nativeUiResultSchema = z.strictObject({
			target_sha256: z.string(),
			initial: nativeUiSnapshotSchema,
			steps: z.array(z.strictObject({
				index: z.number().int().nonnegative(),
				kind: z.string(),
				before: nativeUiSnapshotSchema,
				after: nativeUiSnapshotSchema.nullable(),
				outcome: z.enum([
					"completed",
					"failed",
					"cancelled"
				]),
				reason: z.string().nullable()
			})),
			restore: z.literal("leave-as-is"),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeCallObservation.js
var hexSchema, nativeString, objcName, functionBreakpoint, objcMethodBreakpoint, nativeCallBreakpointSchema, nativeCallObservationInputSchema, nativeCodeLocationSchema, nativeCallEventSchema, nativeCapturedOutputSchema, nativeCallObservationResultSchema;
function init_nativeCallObservation() {
	return (init_nativeCallObservation = __esmMin((() => {
		init_localPath();
		hexSchema = z.string().regex(/^0x[0-9a-f]+$/u);
		nativeString = z.string().regex(/^[^\x00]*$/u, "Native launch and breakpoint strings cannot contain NUL");
		objcName = nativeString.min(1).regex(/^[^\s\x5b\x5d]+$/u, "Use the bare name without spaces or brackets");
		functionBreakpoint = {
			kind: z.literal("function"),
			name: nativeString.min(1).describe("Exact symbol name, such as `open`, a C++ or mangled Swift symbol, or `-[NSString length]`.")
		};
		objcMethodBreakpoint = {
			kind: z.literal("objc-method"),
			selector: objcName.describe("Selector such as `dataTaskWithRequest:completionHandler:`.")
		};
		nativeCallBreakpointSchema = z.discriminatedUnion("kind", [z.strictObject({
			...functionBreakpoint,
			module: nativeString.min(1).optional().describe("Image file name that defines the symbol, such as `libsystem_kernel.dylib`; omit to match every image.")
		}), z.strictObject({
			...objcMethodBreakpoint,
			class_name: objcName.optional().describe("Implementing class; omit to match every class."),
			method_type: z.enum([
				"instance",
				"class",
				"any"
			]).default("any")
		})]);
		nativeCallObservationInputSchema = z.strictObject({
			breakpoints: z.array(nativeCallBreakpointSchema).min(1),
			arguments: z.array(nativeString).default([]),
			environment: z.record(z.string().min(1).regex(/^[^=\x00]+$/u, "Environment names cannot contain '=' or NUL"), z.string().regex(/^[^\x00]*$/u, "Environment values cannot contain NUL")).default({}).describe("Overrides on top of the environment REA runs with."),
			working_directory: localPathStringSchema.optional(),
			duration_ms: z.number().int().min(100).max(6e5).default(1e4).describe("Observation window; the process is killed if it is still running."),
			max_events: z.number().int().min(1).max(1e5).default(1e3).describe("Stop observing and kill the process after this many recorded entries."),
			argument_registers: z.number().int().min(0).max(8).default(4).describe("Integer argument registers to record per entry (arm64 has 8, x86_64 has 6)."),
			backtrace_frames: z.number().int().min(0).max(64).default(0).describe("Caller frames to record per entry.")
		});
		nativeCodeLocationSchema = z.strictObject({
			load_address: hexSchema,
			file_address: hexSchema.nullable(),
			module: z.string().nullable(),
			module_path: z.string().nullable(),
			symbol: z.string().nullable()
		});
		nativeCallEventSchema = z.strictObject({
			sequence: z.number().int().nonnegative(),
			elapsed_ms: z.number().nonnegative(),
			thread_id: z.number().int().nonnegative(),
			breakpoint_index: z.number().int().nonnegative(),
			...nativeCodeLocationSchema.shape,
			/** Dynamic class of an instance-method receiver, read without running code. */
			receiver_class: z.string().nullable(),
			/** Selector string read from the `_cmd` register of an Objective-C method. */
			selector: z.string().nullable(),
			registers: z.array(z.strictObject({
				name: z.string(),
				value: hexSchema
			})),
			backtrace: z.array(nativeCodeLocationSchema)
		});
		nativeCapturedOutputSchema = z.strictObject({
			text: z.string(),
			/** Bytes observed by the bridge, not a total when complete is false. */
			bytes: z.number().int().nonnegative(),
			truncated: z.boolean(),
			complete: z.boolean()
		});
		nativeCallObservationResultSchema = z.strictObject({
			target: z.strictObject({
				path: z.string(),
				sha256: z.string().regex(/^[0-9a-f]{64}$/u),
				architecture: z.string(),
				arguments: z.array(z.string()),
				environment: z.record(z.string(), z.string()),
				working_directory: z.string().nullable(),
				launch_identity: z.strictObject({
					/** A pathname hash does not verify the bytes mapped into the process. */
					loaded_image_sha256: z.null(),
					file_device: z.string().nullable(),
					file_inode: z.string().nullable(),
					selected_file_sha256: z.string().regex(/^[0-9a-f]{64}$/u).nullable(),
					module_path: z.string().nullable(),
					module_uuid: z.string().nullable(),
					stable: z.boolean()
				})
			}),
			debugger: z.strictObject({
				path: z.string(),
				sha256: z.string().regex(/^[0-9a-f]{64}$/u),
				version: z.string().nullable()
			}),
			process: z.strictObject({
				pid: z.number().int().positive(),
				outcome: z.enum([
					"exited",
					"duration-elapsed",
					"event-limit",
					"stop-limit",
					"resource-limit"
				]),
				exit_status: z.number().int().nullable(),
				exit_description: z.string().nullable(),
				/** REA confirmed the process is gone when observation ended. */
				terminated: z.boolean(),
				elapsed_ms: z.number().nonnegative(),
				stdout: nativeCapturedOutputSchema,
				stderr: nativeCapturedOutputSchema,
				/** Signal and exception stops LLDB reported; the process continued past each. */
				other_stops: z.array(z.string())
			}),
			breakpoints: z.array(z.strictObject({
				index: z.number().int().nonnegative(),
				request: z.discriminatedUnion("kind", [z.strictObject({
					...functionBreakpoint,
					module: z.string().nullable()
				}), z.strictObject({
					...objcMethodBreakpoint,
					class_name: z.string().nullable(),
					method_type: z.enum([
						"instance",
						"class",
						"any"
					])
				})]),
				location_count: z.number().int().nonnegative(),
				locations: z.array(nativeCodeLocationSchema)
			})),
			events: z.array(nativeCallEventSchema),
			coverage: z.strictObject({
				status: z.enum(["complete", "partial"]),
				event_limit_reached: z.boolean(),
				resource_limit_reached: z.boolean(),
				/** Aggregate breakpoint-location metadata exhausted its retained-byte budget. */
				breakpoint_locations_truncated: z.boolean().optional(),
				/** Requests that matched no code in any image loaded while observing. */
				unresolved_breakpoints: z.array(z.number().int().nonnegative())
			}),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/native/bytePattern.js
var bytePatternFields, hexDigit, readBytePair, nextPairOffset, countBytePairs, validateBytePatternValue, validateBytePattern, coverageBlock, byteSearchResultSchema;
function init_bytePattern() {
	return (init_bytePattern = __esmMin((() => {
		init_addressCoordinate();
		init_analysisErrorCore();
		init_result();
		bytePatternFields = {
			pattern: z.string().describe("Hexadecimal byte pairs or ?? whole-byte wildcards, with optional whitespace between complete pairs; no leading or trailing whitespace. At least one bit must be constrained after applying the mask."),
			mask: z.string().optional().describe("Hexadecimal mask byte pairs, with optional whitespace between complete pairs; no leading or trailing whitespace. Must contain the same number of bytes as pattern.")
		};
		hexDigit = (code) => {
			if (code >= 48 && code <= 57) return code - 48;
			if (code >= 65 && code <= 70) return code - 55;
			if (code >= 97 && code <= 102) return code - 87;
			return undefined;
		};
		readBytePair = (value, offset) => {
			if (value[offset] === "?" && value[offset + 1] === "?") return "wildcard";
			const high = hexDigit(value.charCodeAt(offset));
			const low = hexDigit(value.charCodeAt(offset + 1));
			return high === undefined || low === undefined ? undefined : high * 16 + low;
		};
		nextPairOffset = (value, offset) => {
			const end = offset + 2;
			let next = end;
			while (next < value.length && /\s/u.test(value[next])) next += 1;
			return next === value.length && next !== end ? -1 : next;
		};
		countBytePairs = (value, field) => {
			let count = 0;
			for (let offset = 0; offset < value.length;) {
				const byte = readBytePair(value, offset);
				if (byte === undefined || field === "mask" && byte === "wildcard") return undefined;
				count += 1;
				offset = nextPairOffset(value, offset);
				if (offset < 0) return undefined;
			}
			return count === 0 ? undefined : count;
		};
		validateBytePatternValue = (pattern, mask) => {
			const invalid = (field, message) => err(new AnalysisInputError("search_bytes", undefined, [{
				path: [field],
				reason: "invalid_value",
				message
			}]));
			const patternCount = countBytePairs(pattern, "pattern");
			if (patternCount === undefined) return invalid("pattern", "Use hexadecimal byte pairs or ?? wildcards");
			const maskCount = mask === undefined ? undefined : countBytePairs(mask, "mask");
			if (mask !== undefined && maskCount === undefined) return invalid("mask", "Use hexadecimal mask byte pairs");
			if (maskCount !== undefined && maskCount !== patternCount) return invalid("mask", "Mask length must equal pattern length");
			let patternOffset = 0;
			let maskOffset = 0;
			for (let index = 0; index < patternCount; index += 1) {
				const byte = readBytePair(pattern, patternOffset);
				const selected = mask === undefined ? 255 : readBytePair(mask, maskOffset);
				if (typeof byte === "number" && typeof selected === "number" && selected !== 0) return ok(null);
				patternOffset = nextPairOffset(pattern, patternOffset);
				if (mask !== undefined) maskOffset = nextPairOffset(mask, maskOffset);
			}
			return invalid("pattern", "Pattern must constrain at least one bit");
		};
		validateBytePattern = (value, context) => {
			const parsed = validateBytePatternValue(value.pattern, value.mask);
			if (!parsed.ok) for (const issue of parsed.error.issues) context.addIssue({
				code: "custom",
				path: [...issue.path],
				message: issue.message ?? "Invalid byte pattern"
			});
		};
		coverageBlock = z.strictObject({
			segment: z.string(),
			start: z.string(),
			end: z.string(),
			bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
		}).superRefine((value, context) => {
			const start = addressCoordinate(value.start);
			const end = addressCoordinate(value.end);
			if (start === null || end === null || start.space !== end.space || start.offset > end.offset || end.offset - start.offset + 1n !== BigInt(value.bytes)) context.addIssue({
				code: "custom",
				message: "Byte coverage must equal its inclusive address range in one space"
			});
		});
		byteSearchResultSchema = z.strictObject({
			matches: z.array(z.strictObject({
				address: z.string(),
				segment: z.string(),
				file_offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable(),
				procedure: z.strictObject({
					address: z.string(),
					name: z.string()
				}).nullable()
			})).max(1e3),
			searched: z.strictObject({
				blocks: z.array(coverageBlock),
				bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
				skipped_uninitialized: z.array(coverageBlock),
				skipped_not_loaded: z.array(coverageBlock)
			}),
			complete: z.boolean(),
			next_cursor: z.string().min(1).nullable()
		}).superRefine((value, context) => {
			if (value.complete !== (value.next_cursor === null) || value.searched.bytes !== value.searched.blocks.reduce((sum, block) => sum + block.bytes, 0)) context.addIssue({
				code: "custom",
				message: "Byte search coverage and continuation disagree"
			});
			const ranges = value.searched.blocks.map((block) => ({
				segment: block.segment,
				start: addressCoordinate(block.start),
				end: addressCoordinate(block.end)
			}));
			for (const [index, match] of value.matches.entries()) {
				const address = addressCoordinate(match.address);
				if (address === null || !ranges.some((range) => range.segment === match.segment && range.start !== null && range.end !== null && range.start.space === address.space && range.end.space === address.space && range.start.offset <= address.offset && address.offset <= range.end.offset)) context.addIssue({
					code: "custom",
					path: [
						"matches",
						index,
						"address"
					],
					message: "Byte match must lie within reported searched coverage in the same segment and address space"
				});
			}
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeFunctionAnnotations.js
var nativeFunctionAnnotationsInputSchema, nativeFunctionAnnotationsSchema;
function init_nativeFunctionAnnotations() {
	return (init_nativeFunctionAnnotations = __esmMin((() => {
		init_hopperValues();
		nativeFunctionAnnotationsInputSchema = z.strictObject({
			procedure: z.string().min(1),
			name: z.string().min(1).optional(),
			comment: z.string().optional().describe("Regular entry comment; empty text clears it"),
			inline_comment: z.string().optional().describe("Inline entry comment; empty text clears it")
		}).refine((value) => value.name !== undefined || value.comment !== undefined || value.inline_comment !== undefined, "Supply at least one annotation change");
		nativeFunctionAnnotationsSchema = z.strictObject({
			annotations: z.strictObject({
				address: z.string().min(1),
				name: z.string().min(1),
				comment: z.string().nullable(),
				inline_comment: z.string().nullable()
			}),
			dossier: functionDossierSchema,
			effects: z.strictObject({
				scope: z.literal("session-analysis-database"),
				source_bytes_modified: z.literal(false),
				persists_after_close: z.literal(false)
			})
		}).superRefine((value, context) => {
			if (value.annotations.address !== value.dossier.procedure.address || value.annotations.name !== value.dossier.procedure.name) context.addIssue({
				code: "custom",
				message: "Annotation readback disagrees with refreshed function identity"
			});
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeMetadataRecovery.js
var address$1, relatedType, nativeMetadataRecoverySchema, nativeMetadataRecoverySummarySchema;
function init_nativeMetadataRecovery() {
	return (init_nativeMetadataRecovery = __esmMin((() => {
		address$1 = z.string().regex(/^0x[0-9a-f]+$/u);
		relatedType = z.strictObject({
			address: address$1,
			type: z.string().nullable()
		});
		nativeMetadataRecoverySchema = z.strictObject({
			format: z.literal("dotnet-nativeaot"),
			/** Identifies parser-only facts without claiming Ghidra defined a DataType. */
			source: z.enum(["analysis-database", "read-only-derived-overlay"]).optional(),
			status: z.enum(["complete", "partial"]),
			header_address: address$1,
			format_major: z.number().int().nonnegative(),
			format_minor: z.number().int().nonnegative(),
			method_table_address: address$1,
			name_origin: z.enum(["generated", "inferred"]),
			original_name: z.null(),
			base_size_bytes: z.number().int().nonnegative(),
			related_type: relatedType.nullable(),
			interfaces: z.array(relatedType),
			virtual_slots: z.array(z.strictObject({
				slot: z.number().int().nonnegative(),
				slot_address: address$1,
				target_address: address$1.nullable(),
				procedure_name: z.string().nullable(),
				basis: z.literal("method-table-pointer")
			})),
			derived_memory: z.strictObject({
				address: address$1,
				size_bytes: z.number().int().nonnegative(),
				sha256: z.string().regex(/^[a-f0-9]{64}$/u),
				file_offset: z.null()
			}).nullable(),
			truncated: z.boolean().optional(),
			virtual_slots_omitted: z.number().int().nonnegative().optional(),
			interfaces_omitted: z.number().int().nonnegative().optional(),
			output_budget_bytes: z.number().int().nonnegative().optional(),
			diagnostics: z.array(z.string()),
			limitations: z.array(z.string())
		});
		nativeMetadataRecoverySummarySchema = z.strictObject({
			format: z.literal("dotnet-nativeaot"),
			analysis_mode: z.literal("read-only-derived-overlay").optional(),
			status: z.enum([
				"complete",
				"partial",
				"not_applicable"
			]),
			reason: z.string().nullable(),
			analysis_artifact_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			header_address: address$1.nullable(),
			discovery: z.enum(["symbol", "signature-heuristic"]).nullable(),
			format_major: z.number().int().nonnegative().nullable(),
			format_minor: z.number().int().nonnegative().nullable(),
			method_tables: z.number().int().nonnegative(),
			types: z.array(relatedType),
			frozen_strings: z.array(z.strictObject({
				address: address$1,
				value: z.string()
			})).optional(),
			truncated: z.boolean().optional(),
			types_omitted: z.number().int().nonnegative().optional(),
			frozen_strings_omitted: z.number().int().nonnegative().optional(),
			output_budget_bytes: z.number().int().nonnegative().optional(),
			derived_overlay: z.strictObject({
				address: address$1,
				size_bytes: z.number().int().nonnegative(),
				sha256: z.string().regex(/^[a-f0-9]{64}$/u)
			}).nullable().optional(),
			derived_memory: nativeMetadataRecoverySchema.shape.derived_memory,
			coverage: z.strictObject({
				frozen_object_candidates: z.number().int().nonnegative().optional(),
				frozen_objects_annotated: z.number().int().nonnegative().optional(),
				pointer_candidates_examined: z.number().int().nonnegative().optional(),
				pointer_slots_examined: z.number().int().nonnegative().optional(),
				scan_bytes_examined: z.number().int().nonnegative().optional(),
				scan_bytes_omitted: z.number().int().nonnegative().optional(),
				rtr_signature_scan_bytes_examined: z.number().int().nonnegative().optional(),
				rtr_signature_scan_bytes_omitted: z.number().int().nonnegative().optional(),
				method_table_validation_items_examined: z.number().int().nonnegative().optional(),
				work_units_examined: z.number().int().nonnegative().optional(),
				method_tables_recovered: z.number().int().nonnegative().optional(),
				frozen_string_candidates: z.number().int().nonnegative().optional(),
				frozen_scan_bytes_examined: z.number().int().nonnegative().optional(),
				frozen_scan_bytes_omitted: z.number().int().nonnegative().optional(),
				frozen_string_data_bytes_examined: z.number().int().nonnegative().optional(),
				source_bytes_examined: z.number().int().nonnegative().optional(),
				source_bytes_omitted: z.number().int().nonnegative().optional(),
				source_byte_budget_bytes: z.number().int().nonnegative().optional(),
				work_budget_units: z.number().int().nonnegative().optional(),
				working_memory_budget_bytes: z.number().int().nonnegative().optional(),
				working_memory_bytes_peak: z.number().int().nonnegative().optional(),
				truncation_reason: z.enum([
					"source-byte-budget",
					"work-unit-budget",
					"working-memory-budget",
					"response-budget"
				]).optional(),
				basis: z.enum([
					"rehydrated-pointer-candidates-and-committed-instance-types",
					"raw-image-pointer-scan",
					"raw-image-and-rehydrated-pointer-scan",
					"unsupported-layout",
					"no-rtr-header"
				])
			}).nullable(),
			diagnostics: z.array(z.string()),
			limitations: z.array(z.string())
		});
	})))();
}

//#endregion
//#region dist/domain/native/nativeLoadImage.js
var integer, digest, hexBytes, address, nativeLoadImageObservationSchema, nativeLoadImageCheckSchema, nativeLoadImageSchema, nativeLoadImagePartialObservationSchema;
function init_nativeLoadImage() {
	return (init_nativeLoadImage = __esmMin((() => {
		init_nativeMetadataRecovery();
		init_jsonValue();
		init_rawBinary();
		integer = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
		digest = z.string().regex(/^[a-f0-9]{64}$/u);
		hexBytes = z.string().regex(/^(?:[a-f0-9]{2})*$/u);
		address = z.string().min(1);
		nativeLoadImageObservationSchema = z.strictObject({
			metadata_recovery: z.array(nativeMetadataRecoverySummarySchema).optional(),
			executable_format: z.string().min(1),
			language_id: z.string().min(1),
			compiler_spec_id: z.string().min(1),
			image_base: address,
			default_address_space: z.string().min(1),
			source_files: z.array(z.strictObject({
				name: z.string(),
				size: integer,
				original_sha256: digest,
				modified_sha256: digest
			})),
			mappings: z.array(z.strictObject({
				block: z.string(),
				start: address,
				end: address,
				address_space: z.string().min(1),
				initialized: z.boolean(),
				loaded: z.boolean(),
				overlay: z.boolean(),
				length: integer.min(1),
				source_file_index: integer.nullable(),
				file_offset: integer.nullable(),
				sha256: digest.nullable()
			})),
			relocations: z.array(z.strictObject({
				address,
				segment: integer.max(65535).nullable(),
				offset: integer.max(65535).nullable(),
				status: z.string().min(1),
				type: z.number().int(),
				values: z.array(z.number().int().min(Number.MIN_SAFE_INTEGER).max(Number.MAX_SAFE_INTEGER)),
				original_bytes_hex: hexBytes.nullable(),
				memory_bytes_hex: hexBytes.nullable()
			})),
			entry_points: z.array(address),
			entry_context: z.array(z.strictObject({
				address,
				registers: z.array(z.strictObject({
					name: z.string().min(1),
					value_hex: z.string().regex(/^0x[a-f0-9]+$/u).nullable()
				}))
			}))
		});
		nativeLoadImageCheckSchema = z.strictObject({
			name: z.string().min(1),
			matched: z.boolean(),
			expected: jsonValueSchema,
			observed: jsonValueSchema,
			file_offset: integer.nullable(),
			address: address.nullable()
		});
		nativeLoadImageSchema = z.union([
			z.strictObject({
				status: z.literal("unsupported"),
				reason: z.string().min(1),
				observations: nativeLoadImageObservationSchema,
				limitations: z.array(z.string().min(1))
			}),
			z.strictObject({
				status: z.enum(["verified", "mismatch"]),
				format: z.enum(["dos-mz", "dos-com"]),
				target_sha256: digest,
				load_segment: integer.max(65535),
				header_bytes: integer,
				module_bytes: integer,
				overlay_bytes: integer,
				entry: z.strictObject({
					relative_segment: integer.max(65535),
					offset: integer.max(65535),
					linear_address: address
				}),
				observations: nativeLoadImageObservationSchema,
				checks: z.array(nativeLoadImageCheckSchema),
				limitations: z.array(z.string().min(1))
			}),
			z.strictObject({
				status: z.enum(["verified", "mismatch"]),
				format: z.literal("raw-binary"),
				target_sha256: digest,
				architecture: binaryArchitectureSchema,
				language_id: z.string().min(1),
				compiler_spec_id: z.string().min(1),
				base_address: address,
				file_bytes: integer.min(1),
				entry: z.strictObject({
					address,
					file_offset: z.literal(0)
				}),
				observations: nativeLoadImageObservationSchema,
				checks: z.array(nativeLoadImageCheckSchema),
				limitations: z.array(z.string().min(1))
			})
		]);
		nativeLoadImagePartialObservationSchema = z.discriminatedUnion("stage", [z.strictObject({
			kind: z.literal("native-load-image"),
			stage: z.literal("measured"),
			observations: nativeLoadImageObservationSchema
		}), z.strictObject({
			kind: z.literal("native-load-image"),
			stage: z.literal("completed"),
			result: nativeLoadImageSchema
		})]);
	})))();
}

//#endregion
//#region dist/domain/native/nativeDataType.js
var nativeDataTypeInputSchema, nativeDataTypeSchema;
function init_nativeDataType() {
	return (init_nativeDataType = __esmMin((() => {
		init_nativeMetadataRecovery();
		nativeDataTypeInputSchema = z.strictObject({
			type: z.string().min(1).optional(),
			address: z.string().min(1).optional(),
			document: z.string().optional()
		}).refine((value) => value.type === undefined !== (value.address === undefined), "Supply exactly one of type or address");
		nativeDataTypeSchema = z.strictObject({
			status: z.enum(["available", "unavailable"]),
			reason: z.string().nullable(),
			id: z.string().nullable(),
			name: z.string().nullable(),
			kind: z.enum([
				"struct",
				"union",
				"enum",
				"pointer",
				"array",
				"typedef",
				"scalar",
				"unsupported",
				"unavailable"
			]),
			source: z.literal("analysis-database"),
			source_archive: z.string().nullable(),
			address: z.string().nullable(),
			size_bytes: z.number().int().nonnegative().nullable(),
			alignment_bytes: z.number().int().positive().nullable(),
			packing_enabled: z.boolean().nullable(),
			referenced_type: z.string().nullable(),
			array_count: z.number().int().nonnegative().nullable(),
			array_stride_bytes: z.number().int().nonnegative().nullable(),
			fields: z.array(z.strictObject({
				ordinal: z.number().int().nonnegative(),
				name: z.string().nullable(),
				offset_bytes: z.number().int().nonnegative(),
				size_bytes: z.number().int().nonnegative().nullable(),
				type_id: z.string(),
				bit_size: z.number().int().nonnegative().nullable(),
				bit_offset: z.number().int().nonnegative().nullable(),
				status: z.enum(["observed", "unsupported"]),
				flexible_tail: z.literal("unknown")
			})),
			members: z.array(z.strictObject({
				name: z.string(),
				value: z.string()
			})),
			total_fields: z.number().int().nonnegative(),
			truncated: z.boolean(),
			limitations: z.array(z.string()),
			metadata_recovery: nativeMetadataRecoverySchema.optional()
		});
	})))();
}

//#endregion
//#region dist/domain/process/processTraceEvaluation.js
var matchedEventSchema, sideResultShape, sideResultSchema, diagnosticSchema, processTraceComparisonResultSchema, scopesFor, unknownSide, failure, evaluateFiniteTrace, collectRecords, matchRecords, cardinalityFailure, evaluateOrderingConstraints, boundaryFailure, evaluatePartialOrder, evaluateMatchedTrace, evaluateProcessTraceSide;
function init_processTraceEvaluation() {
	return (init_processTraceEvaluation = __esmMin((() => {
		init_processCaptureCoverage();
		init_processObservation();
		init_processTraceSpecification();
		matchedEventSchema = z.strictObject({
			event_id: processTraceIdentifierSchema,
			location: processObservationLocationSchema
		});
		sideResultShape = {
			satisfied_constraints: z.array(z.string()),
			raw_trace: z.array(matchedEventSchema)
		};
		sideResultSchema = z.union([z.strictObject({
			...sideResultShape,
			status: z.literal("pass"),
			matched_variant: processTraceIdentifierSchema.nullable()
		}), z.strictObject({
			...sideResultShape,
			status: z.enum(["fail", "unknown"]),
			matched_variant: z.null()
		})]);
		diagnosticSchema = z.strictObject({
			kind: z.enum([
				"journal",
				"predicate",
				"cardinality",
				"edge",
				"prefix",
				"suffix",
				"trace"
			]),
			side: z.enum(["left", "right"]),
			message: z.string(),
			event_ids: z.array(processTraceIdentifierSchema),
			locations: z.array(processObservationLocationSchema)
		});
		processTraceComparisonResultSchema = z.strictObject({
			verdict: z.enum([
				"equivalent",
				"different",
				"nonconforming",
				"unknown"
			]),
			left: sideResultSchema,
			right: sideResultSchema,
			diagnostic: diagnosticSchema.nullable()
		});
		scopesFor = (sources) => new Set([...sources].map((source) => {
			if (source.startsWith("terminal_")) return "terminal";
			if (source === "lifecycle") return "exit";
			if (source === "filesystem") return "filesystem";
			if (source === "process") return "process";
			return "interaction";
		}));
		unknownSide = (rawTrace = []) => ({
			status: "unknown",
			matched_variant: null,
			satisfied_constraints: [],
			raw_trace: rawTrace
		});
		failure = (input) => ({
			result: {
				status: "fail",
				matched_variant: null,
				satisfied_constraints: [],
				raw_trace: input.rawTrace
			},
			diagnostic: {
				kind: input.kind,
				message: input.message,
				event_ids: [...input.eventIds],
				locations: [...input.locations]
			}
		});
		evaluateFiniteTrace = (ids, language) => {
			let bestPrefix = -1;
			const bestEventIds = new Set();
			const bestLocationIndexes = new Set();
			const recordMismatch = (offset, missing, unexpected) => {
				if (offset > bestPrefix) {
					bestPrefix = offset;
					bestEventIds.clear();
					bestLocationIndexes.clear();
				}
				if (offset !== bestPrefix) return;
				for (const eventId of missing) bestEventIds.add(eventId);
				for (const { id, index } of unexpected) {
					bestEventIds.add(id);
					bestLocationIndexes.add(index);
				}
			};
			for (const variant of language.variants) {
				let offset = 0;
				let mismatched = false;
				for (const token of variant.trace) {
					const expected = typeof token === "string" ? [token] : token.unordered;
					const actual = ids.slice(offset, offset + expected.length);
					const remaining = new Map();
					for (const eventId of expected) remaining.set(eventId, (remaining.get(eventId) ?? 0) + 1);
					const unexpected = [];
					for (const [index, eventId] of actual.entries()) {
						const count = remaining.get(eventId) ?? 0;
						if (count === 0) unexpected.push({
							id: eventId,
							index: offset + index
						});
						else if (count === 1) remaining.delete(eventId);
						else remaining.set(eventId, count - 1);
					}
					const missing = [...remaining].flatMap(([eventId, count]) => Array.from({ length: count }, () => eventId));
					if (missing.length > 0 || unexpected.length > 0 || actual.length < expected.length) {
						recordMismatch(offset, missing, unexpected);
						mismatched = true;
						break;
					}
					offset += expected.length;
				}
				if (mismatched) continue;
				if (offset === ids.length) return {
					status: "pass",
					variant: variant.id
				};
				const unexpected = ids[offset];
				recordMismatch(offset, [], unexpected === undefined ? [] : [{
					id: unexpected,
					index: offset
				}]);
			}
			return {
				status: "fail",
				eventIds: [...bestEventIds],
				locationIndexes: [...bestLocationIndexes]
			};
		};
		collectRecords = (capture, sources) => {
			const records = [];
			for (const location of capture.event_journal) {
				const record = projectProcessObservation(capture, location);
				if (record !== null && sources.has(record.source)) records.push({
					source: record.source,
					payload: record.payload,
					location
				});
			}
			return records;
		};
		matchRecords = (records, specification) => {
			const rawTrace = [];
			const locationsById = new Map();
			const ignoredFieldsBySource = new Map();
			const eventsByKey = new Map();
			for (const event of specification.events) {
				const ignoredFields = event.ignore_fields ?? [];
				ignoredFieldsBySource.set(event.source, ignoredFields);
				eventsByKey.set(`${event.source}\0${canonicalTraceJson(comparableProcessObservationPayload(event.exact, ignoredFields))}`, event);
			}
			for (const record of records) {
				const match = eventsByKey.get(`${record.source}\0${canonicalTraceJson(comparableProcessObservationPayload(record.payload, ignoredFieldsBySource.get(record.source)))}`);
				if (match === undefined) return failure({
					kind: "predicate",
					message: "Observed event does not match any declared exact predicate.",
					eventIds: [],
					locations: [record.location],
					rawTrace
				});
				rawTrace.push({
					event_id: match.id,
					location: record.location
				});
				const locations = locationsById.get(match.id) ?? [];
				locations.push(record.location);
				locationsById.set(match.id, locations);
			}
			return {
				rawTrace,
				locationsById
			};
		};
		cardinalityFailure = (trace, specification) => {
			for (const event of specification.events) {
				const [minimum, maximum] = processTraceCardinalityBounds(event.cardinality);
				const locations = trace.locationsById.get(event.id) ?? [];
				if (locations.length < minimum || locations.length > maximum) return failure({
					kind: "cardinality",
					message: `${event.id} observed ${String(locations.length)} times; expected ${String(minimum)}..${String(maximum)}.`,
					eventIds: [event.id],
					locations,
					rawTrace: trace.rawTrace
				});
			}
			return null;
		};
		evaluateOrderingConstraints = (trace, language) => {
			const satisfied = [];
			const failures = [];
			for (const edge of language.happens_before) {
				const before = trace.locationsById.get(edge.before) ?? [];
				const after = trace.locationsById.get(edge.after) ?? [];
				const lastBefore = before.at(-1);
				const firstAfter = after[0];
				if (lastBefore === undefined && firstAfter !== undefined) failures.push({
					kind: "edge",
					message: `${edge.before} is required when ${edge.after} occurs.`,
					eventIds: [edge.before, edge.after],
					locations: [firstAfter],
					rawTrace: trace.rawTrace
				});
				else if (lastBefore !== undefined && firstAfter !== undefined && lastBefore.capture_order >= firstAfter.capture_order) failures.push({
					kind: "edge",
					message: `${edge.before} must happen before ${edge.after}.`,
					eventIds: [edge.before, edge.after],
					locations: [lastBefore, firstAfter],
					rawTrace: trace.rawTrace
				});
				else satisfied.push(`happens_before:${edge.before}:${edge.after}`);
			}
			for (const constraint of language.not_before) {
				const events = trace.locationsById.get(constraint.event) ?? [];
				const anchors = trace.locationsById.get(constraint.anchor) ?? [];
				const firstEvent = events[0];
				const firstAnchor = anchors[0];
				if (firstEvent !== undefined && firstAnchor === undefined) failures.push({
					kind: "edge",
					message: `${constraint.anchor} is required when ${constraint.event} occurs.`,
					eventIds: [constraint.event, constraint.anchor],
					locations: [firstEvent],
					rawTrace: trace.rawTrace
				});
				else if (firstEvent !== undefined && firstAnchor !== undefined && firstEvent.capture_order < firstAnchor.capture_order) failures.push({
					kind: "edge",
					message: `${constraint.event} must not occur before ${constraint.anchor}.`,
					eventIds: [constraint.event, constraint.anchor],
					locations: [firstEvent, firstAnchor],
					rawTrace: trace.rawTrace
				});
				else satisfied.push(`not_before:${constraint.event}:${constraint.anchor}`);
			}
			if (failures.length === 0) return {
				failure: null,
				satisfied
			};
			const unique = (values, key) => [...new Map(values.map((value) => [key(value), value])).values()];
			return {
				failure: failure({
					kind: "edge",
					message: failures.map(({ message }) => message).join(" "),
					eventIds: unique(failures.flatMap(({ eventIds }) => eventIds), String),
					locations: unique(failures.flatMap(({ locations }) => locations), ({ collection, index }) => `${collection}:${String(index)}`),
					rawTrace: trace.rawTrace
				}),
				satisfied
			};
		};
		boundaryFailure = (trace, kind, expected) => {
			const ids = trace.rawTrace.map(({ event_id }) => event_id);
			const actual = kind === "prefix" ? ids.slice(0, expected.length) : expected.length === 0 ? [] : ids.slice(-expected.length);
			if (canonicalTraceJson(actual) === canonicalTraceJson(expected)) return null;
			const locations = kind === "prefix" ? trace.rawTrace.slice(0, expected.length) : trace.rawTrace.slice(-expected.length);
			return failure({
				kind,
				message: `Observed trace does not satisfy the declared ${kind}.`,
				eventIds: expected,
				locations: locations.map(({ location }) => location),
				rawTrace: trace.rawTrace
			});
		};
		evaluatePartialOrder = (trace, language) => {
			const ordering = evaluateOrderingConstraints(trace, language);
			if (ordering.failure !== null) return ordering.failure;
			const prefixFailure = boundaryFailure(trace, "prefix", language.prefix);
			if (prefixFailure !== null) return prefixFailure;
			const suffixFailure = boundaryFailure(trace, "suffix", language.suffix);
			if (suffixFailure !== null) return suffixFailure;
			const satisfied = ordering.satisfied;
			satisfied.push(...language.unordered_groups.map(({ events }) => `unordered:${events.join(":")}`));
			if (language.prefix.length > 0) satisfied.push(`prefix:${language.prefix.join(":")}`);
			if (language.suffix.length > 0) satisfied.push(`suffix:${language.suffix.join(":")}`);
			return {
				result: {
					status: "pass",
					matched_variant: null,
					satisfied_constraints: satisfied,
					raw_trace: trace.rawTrace
				},
				diagnostic: null
			};
		};
		evaluateMatchedTrace = (trace, specification) => {
			const invalidCardinality = cardinalityFailure(trace, specification);
			if (invalidCardinality !== null) return invalidCardinality;
			if (specification.language.kind === "partial_order") return evaluatePartialOrder(trace, specification.language);
			const ids = trace.rawTrace.map(({ event_id }) => event_id);
			const evaluation = evaluateFiniteTrace(ids, specification.language);
			return evaluation.status === "fail" ? failure({
				kind: "trace",
				message: "Observed events do not match any finite trace variant.",
				eventIds: evaluation.eventIds,
				locations: evaluation.locationIndexes.flatMap((index) => {
					const location = trace.rawTrace[index]?.location;
					return location === undefined ? [] : [location];
				}),
				rawTrace: trace.rawTrace
			}) : {
				result: {
					status: "pass",
					matched_variant: evaluation.variant,
					satisfied_constraints: [`variant:${evaluation.variant}`],
					raw_trace: trace.rawTrace
				},
				diagnostic: null
			};
		};
		evaluateProcessTraceSide = (capture, specification) => {
			const sources = new Set(specification.events.map(({ source }) => source));
			const relevantScopes = scopesFor(sources);
			const incomplete = [...sources].some((source) => processSourceTruncated(capture, source)) || capture.residual_unknowns.some(({ scope }) => relevantScopes.has(scope));
			if (capture.event_journal.length === 0) return {
				result: unknownSide(),
				diagnostic: {
					kind: "journal",
					message: "Capture has no cross-source event journal.",
					event_ids: [],
					locations: []
				}
			};
			const matched = matchRecords(collectRecords(capture, sources), specification);
			if (incomplete) return {
				result: unknownSide("rawTrace" in matched ? matched.rawTrace : matched.result.raw_trace),
				diagnostic: null
			};
			return "rawTrace" in matched ? evaluateMatchedTrace(matched, specification) : matched;
		};
	})))();
}

//#endregion
//#region dist/domain/process/processTraceDimensionProjection.js
var dimensionsForTraceSources, traceCoversObservedDimension;
function init_processTraceDimensionProjection() {
	return (init_processTraceDimensionProjection = __esmMin((() => {
		dimensionsForTraceSources = (sources) => {
			const dimensions = new Set();
			for (const source of sources) {
				if (source.startsWith("terminal_")) dimensions.add("terminal");
				else if (source === "interaction") dimensions.add("interaction");
				else if (source === "lifecycle") dimensions.add("exit");
				else if (source === "filesystem") dimensions.add("filesystem");
				else if (source === "process") dimensions.add("process");
			}
			return dimensions;
		};
		traceCoversObservedDimension = (dimension, sources, left, right) => {
			const any = (leftValues, rightValues) => leftValues.length > 0 || rightValues.length > 0;
			switch (dimension) {
				case "terminal": return (!any(left.frames, right.frames) || sources.has("terminal_raw")) && (!any(left.rendered_frames, right.rendered_frames) || sources.has("terminal_rendered"));
				case "interaction": return sources.has("interaction");
				case "exit": return sources.has("lifecycle");
				case "filesystem": return sources.has("filesystem");
				case "process": return sources.has("process");
			}
		};
	})))();
}

//#endregion
//#region dist/domain/process/processTraceComparison.js
var compareProcessTraces, processTraceOutcomesDiffer;
function init_processTraceComparison() {
	return (init_processTraceComparison = __esmMin((() => {
		init_processTraceEvaluation();
		init_processTraceSpecification();
		compareProcessTraces = (left, right, specificationInput) => {
			const specification = processTraceSpecificationSchema.parse(specificationInput);
			const leftEvaluation = evaluateProcessTraceSide(left, specification);
			const rightEvaluation = evaluateProcessTraceSide(right, specification);
			const diagnostic = leftEvaluation.diagnostic === null ? rightEvaluation.diagnostic === null ? null : {
				side: "right",
				...rightEvaluation.diagnostic
			} : {
				side: "left",
				...leftEvaluation.diagnostic
			};
			const outcomesDiffer = leftEvaluation.result.status !== rightEvaluation.result.status || JSON.stringify(leftEvaluation.result.raw_trace.map(({ event_id }) => event_id)) !== JSON.stringify(rightEvaluation.result.raw_trace.map(({ event_id }) => event_id));
			return processTraceComparisonResultSchema.parse({
				verdict: leftEvaluation.result.status === "unknown" || rightEvaluation.result.status === "unknown" ? "unknown" : leftEvaluation.result.status === "pass" && rightEvaluation.result.status === "pass" ? "equivalent" : outcomesDiffer ? "different" : "nonconforming",
				left: leftEvaluation.result,
				right: rightEvaluation.result,
				diagnostic
			});
		};
		processTraceOutcomesDiffer = (comparison) => comparison.left.status !== comparison.right.status || JSON.stringify(comparison.left.raw_trace.map(({ event_id }) => event_id)) !== JSON.stringify(comparison.right.raw_trace.map(({ event_id }) => event_id));
	})))();
}

//#endregion
//#region dist/domain/process/processComparison.js
var OPERATION, comparisonStatusSchema$1, PROCESS_COMPARISON_DIMENSIONS, deriveProcessComparisonStatus, processCaptureComparisonSchema, terminalObservations, filesystemObservations, sameJsonValue, processDimensionObservations, classifyCollection, hasUnknown, EVENT_TIME_FIELD, eventTime, firstCollectionDivergence, chooseFirstDivergence, assertComparable, differingContractFields, LOCATION_SOURCES, applyTraceVerdict, compareDimensions, compareProcessCaptures;
function init_processComparison() {
	return (init_processComparison = __esmMin((() => {
		init_processCaptureCoverage();
		init_processObservation();
		init_analysisErrorCore();
		init_jsonValue();
		init_processTraceEvaluation();
		init_processTraceDimensionProjection();
		init_processTraceComparison();
		OPERATION = "compare_process_captures";
		comparisonStatusSchema$1 = z.enum([
			"unchanged",
			"added",
			"removed",
			"changed",
			"truncated",
			"unknown",
			"contradiction"
		]);
		PROCESS_COMPARISON_DIMENSIONS = [
			"terminal",
			"interaction",
			"exit",
			"filesystem",
			"process"
		];
		deriveProcessComparisonStatus = (dimensions) => {
			if (dimensions.includes("truncated")) return "truncated";
			if (dimensions.some((status) => [
				"changed",
				"added",
				"removed"
			].includes(status))) return "changed";
			return dimensions.includes("unknown") ? "unknown" : "unchanged";
		};
		processCaptureComparisonSchema = z.object({
			status: comparisonStatusSchema$1,
			terminal: comparisonStatusSchema$1,
			interaction: comparisonStatusSchema$1,
			exit: comparisonStatusSchema$1,
			filesystem: comparisonStatusSchema$1,
			process: comparisonStatusSchema$1,
			first_divergence: z.discriminatedUnion("status", [
				z.object({ status: z.literal("none") }),
				z.object({
					status: z.literal("unknown"),
					reason: z.string()
				}),
				z.object({
					status: z.literal("found"),
					dimension: z.enum([
						"terminal",
						"interaction",
						"exit",
						"filesystem",
						"process"
					]),
					index: z.number().int().nonnegative(),
					left_at_ms: z.number().int().nonnegative().nullable(),
					right_at_ms: z.number().int().nonnegative().nullable(),
					left: jsonValueSchema.nullable(),
					right: jsonValueSchema.nullable()
				})
			]),
			trace: processTraceComparisonResultSchema.optional(),
			limitations: z.array(z.string())
		}).superRefine((comparison, context) => {
			const expected = deriveProcessComparisonStatus(PROCESS_COMPARISON_DIMENSIONS.map((dimension) => comparison[dimension]));
			if (comparison.status !== expected) context.addIssue({
				code: "custom",
				message: "Process comparison status contradicts its dimensions",
				path: ["status"]
			});
		});
		terminalObservations = (capture) => [...capture.frames.map((frame) => ({
			kind: "raw",
			...comparableTerminalFrame(frame)
		})), ...capture.rendered_frames.map((frame) => ({
			kind: "rendered",
			...frame
		}))].sort((left, right) => {
			const time = left.at_ms - right.at_ms;
			if (time !== 0) return time;
			if (left.kind !== right.kind) return left.kind === "raw" ? -1 : 1;
			return left.sequence - right.sequence;
		});
		filesystemObservations = (capture) => capture.filesystem_checkpoints;
		sameJsonValue = (left, right) => {
			const encodedLeft = canonicalize(left);
			return encodedLeft !== undefined && encodedLeft === canonicalize(right);
		};
		processDimensionObservations = (capture, dimension) => {
			switch (dimension) {
				case "terminal": return terminalObservations(capture);
				case "interaction": return capture.interaction_events;
				case "exit": return [{
					...capture.exit,
					settlement: capture.settlement
				}];
				case "filesystem": return filesystemObservations(capture);
				case "process": return capture.process_samples;
			}
		};
		classifyCollection = (left, right) => {
			if (sameJsonValue(left, right)) return "unchanged";
			if (left.length === 0) return "added";
			if (right.length === 0) return "removed";
			return "changed";
		};
		hasUnknown = (capture, scope) => capture.residual_unknowns.some((item) => item.scope === scope);
		EVENT_TIME_FIELD = {
			terminal: "at_ms",
			interaction: "dispatched_at_ms",
			exit: "at_ms",
			filesystem: "at_ms",
			process: "at_ms"
		};
		eventTime = (dimension, value) => {
			if (typeof value !== "object" || value === null) return null;
			const time = Reflect.get(value, EVENT_TIME_FIELD[dimension]);
			return typeof time === "number" && Number.isSafeInteger(time) && time >= 0 ? time : null;
		};
		firstCollectionDivergence = (dimension, left, right) => {
			const length = Math.max(left.length, right.length);
			for (let index = 0; index < length; index += 1) {
				const leftValue = left[index] ?? null;
				const rightValue = right[index] ?? null;
				if (sameJsonValue(leftValue, rightValue)) continue;
				return {
					status: "found",
					dimension,
					index,
					left_at_ms: eventTime(dimension, leftValue),
					right_at_ms: eventTime(dimension, rightValue),
					left: jsonValueSchema.parse(leftValue),
					right: jsonValueSchema.parse(rightValue)
				};
			}
			return null;
		};
		chooseFirstDivergence = (candidates) => {
			const found = candidates.filter((candidate) => candidate !== null);
			return found.sort((left, right) => {
				const leftTime = Math.min(left.left_at_ms ?? Number.MAX_SAFE_INTEGER, left.right_at_ms ?? Number.MAX_SAFE_INTEGER);
				const rightTime = Math.min(right.left_at_ms ?? Number.MAX_SAFE_INTEGER, right.right_at_ms ?? Number.MAX_SAFE_INTEGER);
				return leftTime - rightTime;
			})[0] ?? { status: "none" };
		};
		assertComparable = (left, right, options) => {
			if (left.manifest.comparison_contract_sha256 !== right.manifest.comparison_contract_sha256) {
				const fields = differingContractFields(left.manifest.comparison_contract, right.manifest.comparison_contract);
				throw new AnalysisInputError(OPERATION, undefined, [{
					path: ["right"],
					reason: "invalid_value",
					message: `Process captures have incompatible comparison contracts${fields.length === 0 ? "" : `; these scenario fields differ: ${fields.join(", ")}`}. Capture both scenarios with the same values for these fields, then compare them.`,
					expected: fields
				}]);
			}
			if (options.maxCaptureAgeMs === undefined) return;
			const maxCaptureAgeMs = options.maxCaptureAgeMs;
			const now = (options.now ?? Date.now)();
			const stale = [["left", left], ["right", right]].flatMap(([side, { manifest }]) => {
				const age = now - Date.parse(manifest.completed_at);
				return age > maxCaptureAgeMs ? [`${side} completed at ${manifest.completed_at} (${String(age)} ms ago)`] : [];
			});
			if (stale.length > 0) throw new AnalysisInputError(OPERATION, undefined, [{
				path: ["max_capture_age_ms"],
				reason: "out_of_range",
				message: `Process capture exceeds max_capture_age_ms ${String(maxCaptureAgeMs)}: ${stale.join("; ")}. Recapture the stale scenario or raise max_capture_age_ms.`
			}]);
		};
		differingContractFields = (left, right) => [...new Set([...Object.keys(left), ...Object.keys(right)])].filter((field) => !Object.hasOwn(left, field) || !Object.hasOwn(right, field) || canonicalize(left[field]) !== canonicalize(right[field])).sort();
		LOCATION_SOURCES = {
			frames: "terminal_raw",
			rendered_frames: "terminal_rendered",
			interaction_events: "interaction",
			lifecycle: "lifecycle",
			process_samples: "process",
			filesystem_checkpoints: "filesystem"
		};
		applyTraceVerdict = (dimensions, specification, trace, captures) => {
			const traceShowsDifference = processTraceOutcomesDiffer(trace);
			const traceStatus = trace.verdict === "unknown" ? "unknown" : trace.verdict === "equivalent" || !traceShowsDifference ? "unchanged" : "changed";
			const sources = new Set(specification.events.map(({ source }) => source));
			const covered = dimensionsForTraceSources(sources);
			const diagnosticSources = new Set([...specification.events.filter(({ id }) => trace.diagnostic?.event_ids.includes(id) === true).map(({ source }) => source), ...(trace.diagnostic?.locations ?? []).map(({ collection }) => LOCATION_SOURCES[collection])]);
			const attributed = diagnosticSources.size > 0 ? dimensionsForTraceSources(diagnosticSources) : covered;
			const statusFor = (dimension) => {
				const exact = dimensions[dimension];
				if (!covered.has(dimension)) return exact;
				if (trace.verdict === "nonconforming") return exact;
				if (trace.verdict === "different") return traceShowsDifference && attributed.has(dimension) ? "changed" : exact;
				if (trace.verdict === "unknown" && [
					"changed",
					"added",
					"removed"
				].includes(exact)) return exact;
				return traceCoversObservedDimension(dimension, sources, captures[0], captures[1]) ? traceStatus : exact;
			};
			return {
				terminal: statusFor("terminal"),
				interaction: statusFor("interaction"),
				exit: statusFor("exit"),
				filesystem: statusFor("filesystem"),
				process: statusFor("process")
			};
		};
		compareDimensions = (left, right, sameNormalization) => {
			const classify = (scope, leftValues, rightValues, source) => !sameNormalization || hasUnknown(left, scope) || hasUnknown(right, scope) || processSourceTruncated(left, source) || processSourceTruncated(right, source) ? "unknown" : classifyCollection(leftValues, rightValues);
			return {
				terminal: classify("terminal", terminalObservations(left), terminalObservations(right), "terminal_rendered"),
				interaction: classify("interaction", left.interaction_events, right.interaction_events, "interaction"),
				exit: hasUnknown(left, "exit") || hasUnknown(right, "exit") ? "unknown" : sameJsonValue({
					exit: left.exit,
					settlement: left.settlement
				}, {
					exit: right.exit,
					settlement: right.settlement
				}) ? "unchanged" : "changed",
				filesystem: classify("filesystem", filesystemObservations(left), filesystemObservations(right), "filesystem"),
				process: classify("process", left.process_samples, right.process_samples, "process")
			};
		};
		compareProcessCaptures = (left, right, options = {}) => {
			assertComparable(left, right, options);
			const sameNormalization = sameJsonValue(left.normalization, right.normalization);
			const exactDimensions = compareDimensions(left, right, sameNormalization);
			const trace = options.traceSpecification === undefined ? undefined : compareProcessTraces(left, right, options.traceSpecification);
			const dimensions = trace === undefined || options.traceSpecification === undefined ? exactDimensions : applyTraceVerdict(exactDimensions, options.traceSpecification, trace, [left, right]);
			const divergenceCandidates = PROCESS_COMPARISON_DIMENSIONS.map((dimension) => dimensions[dimension] === "unknown" ? null : firstCollectionDivergence(dimension, processDimensionObservations(left, dimension), processDimensionObservations(right, dimension)));
			const observedFirstDivergence = chooseFirstDivergence(divergenceCandidates.map((candidate) => candidate !== null && trace?.verdict === "equivalent" && dimensions[candidate.dimension] === "unchanged" ? null : candidate));
			const firstDivergence = left.truncated || right.truncated ? {
				status: "unknown",
				reason: "Incomplete observations prevent locating the first divergence; unaffected dimensions retain their comparisons."
			} : trace?.verdict === "equivalent" && deriveProcessComparisonStatus(PROCESS_COMPARISON_DIMENSIONS.map((dimension) => dimensions[dimension])) === "unchanged" ? { status: "none" } : observedFirstDivergence.status === "found" ? observedFirstDivergence : !sameNormalization || left.residual_unknowns.length > 0 || right.residual_unknowns.length > 0 ? {
				status: "unknown",
				reason: "Residual unknowns prevent proving that no divergence occurred."
			} : observedFirstDivergence;
			const observedStatus = deriveProcessComparisonStatus(PROCESS_COMPARISON_DIMENSIONS.map((dimension) => dimensions[dimension]));
			return {
				status: observedStatus,
				...dimensions,
				first_divergence: firstDivergence,
				...trace === undefined ? {} : { trace },
				limitations: [
					...left.limitations,
					...right.limitations,
					...left.residual_unknowns.map(({ reason }) => reason),
					...right.residual_unknowns.map(({ reason }) => reason),
					...sameNormalization ? [] : ["Capture normalization rules differ."]
				]
			};
		};
	})))();
}

//#endregion
//#region dist/domain/apple/dyldPaths.js
var MAX_SYMLINK_HOPS, resolveTreePath, segmentsOf, directoryOf, joinPath, expandPrefix, COMPATIBLE_ARCHITECTURES, compatibleSlice;
function init_dyldPaths() {
	return (init_dyldPaths = __esmMin((() => {
		init_machoCpuIdentity();
		MAX_SYMLINK_HOPS = 32;
		resolveTreePath = async (view, input) => {
			const pending = segmentsOf(input);
			const resolved = [];
			let last;
			let hops = 0;
			while (pending.length > 0) {
				const segment = pending.shift() ?? "";
				if (segment === ".") continue;
				if (segment === "..") {
					if (resolved.length === 0) return { kind: "escapes" };
					resolved.pop();
					last = { kind: "directory" };
					continue;
				}
				const path = [...resolved, segment].join("/");
				const entry = await view.entry(path);
				if (entry === undefined) return { kind: "absent" };
				if (entry.kind === "symlink") {
					hops += 1;
					if (hops > MAX_SYMLINK_HOPS) return { kind: "absent" };
					if (entry.target.startsWith("/")) return { kind: "escapes" };
					pending.unshift(...segmentsOf(entry.target));
					continue;
				}
				if (entry.kind === "file" && pending.length > 0) return { kind: "absent" };
				resolved.push(segment);
				last = entry;
			}
			return last?.kind === "file" ? {
				kind: "file",
				path: resolved.join("/")
			} : { kind: "not-file" };
		};
		segmentsOf = (path) => {
			const segments = path.split("/").filter((segment) => segment !== "");
			if (path.endsWith("/")) segments.push(".");
			return segments;
		};
		directoryOf = (path) => {
			const index = path.lastIndexOf("/");
			return index < 0 ? "" : path.slice(0, index);
		};
		joinPath = (directory, rest) => directory === "" ? rest : rest === "" ? directory : `${directory}/${rest}`;
		expandPrefix = (raw, context) => {
			const variable = /^@(executable_path|loader_path)(?:\/(.*))?$/u.exec(raw);
			if (variable !== null) {
				const rest = variable[2] ?? "";
				if (variable[1] === "loader_path") return {
					scope: "target",
					path: joinPath(context.ownerDirectory, rest)
				};
				return context.executable === null ? {
					scope: "undetermined",
					path: raw
				} : {
					scope: "target",
					path: joinPath(directoryOf(context.executable), rest)
				};
			}
			if (raw.startsWith("/")) {
				const lookupPath = context.rootRelativePath(raw);
				return lookupPath === undefined ? {
					scope: "outside",
					path: raw
				} : {
					scope: "target",
					path: raw,
					lookupPath
				};
			}
			return {
				scope: "undetermined",
				path: raw
			};
		};
		COMPATIBLE_ARCHITECTURES = { x86_64h: ["x86_64h", "x86_64"] };
		compatibleSlice = (slices, process) => {
			for (const architecture of COMPATIBLE_ARCHITECTURES[process.architecture] ?? [process.architecture]) {
				const slice = slices.find((item) => item.architecture === architecture && (process.architecture !== "arm64e" || item.cpu_type === process.cpu_type && machoCpuSubtypeBase(item.cpu_subtype) === machoCpuSubtypeBase(process.cpu_subtype)));
				if (slice !== undefined) return slice;
			}
			return undefined;
		};
	})))();
}

//#endregion
//#region dist/domain/apple/dyldEnvironment.js
var embeddedDyldOverrides, overrideEffect, isFrameworkInstallName, hasApplicableDyldOverrides;
function init_dyldEnvironment() {
	return (init_dyldEnvironment = __esmMin((() => {
		embeddedDyldOverrides = (environment, platforms) => {
			const overrides = [];
			for (const setting of environment) {
				const delimiter = setting.indexOf("=");
				if (delimiter <= 0) continue;
				const variable = setting.slice(0, delimiter);
				const value = setting.slice(delimiter + 1);
				const effect = overrideEffect(variable, value);
				if (effect === undefined) continue;
				if (variable === "DYLD_ROOT_PATH" && platforms.length > 0 && platforms.every((platform) => platform >= 1 && platform <= 12) && !platforms.some((platform) => [
					7,
					8,
					9,
					12
				].includes(platform))) continue;
				overrides.push({
					variable,
					value,
					...effect
				});
			}
			return overrides;
		};
		overrideEffect = (variable, value) => {
			switch (variable) {
				case "DYLD_LIBRARY_PATH": return {
					phase: "override",
					scope: "library"
				};
				case "DYLD_FRAMEWORK_PATH": return {
					phase: "override",
					scope: "framework"
				};
				case "DYLD_FALLBACK_LIBRARY_PATH": return {
					phase: "fallback",
					scope: "library"
				};
				case "DYLD_FALLBACK_FRAMEWORK_PATH": return {
					phase: "fallback",
					scope: "framework"
				};
				case "DYLD_VERSIONED_LIBRARY_PATH":
				case "DYLD_VERSIONED_FRAMEWORK_PATH":
				case "DYLD_IMAGE_SUFFIX": return /[^:]/u.test(value) ? {
					phase: "override",
					scope: "all"
				} : undefined;
				case "DYLD_INSERT_LIBRARIES": return value === "" ? undefined : {
					phase: "override",
					scope: "all"
				};
				case "DYLD_ROOT_PATH":
				case "DYLD_OVERLAY_PATH": return value === "" ? undefined : {
					phase: "override",
					scope: "prefix"
				};
				default: return undefined;
			}
		};
		isFrameworkInstallName = (name, overrides) => {
			const separator = name.lastIndexOf(".framework/");
			if (separator < 0) return false;
			const framework = name.slice(0, separator).split("/").at(-1);
			const leaf = name.slice(name.lastIndexOf("/") + 1);
			return leaf === framework || overrides.some(({ variable, value }) => variable === "DYLD_IMAGE_SUFFIX" && leaf === `${framework}${value}`);
		};
		hasApplicableDyldOverrides = (overrides, installName, ordinarySearchFoundImage) => {
			const kind = isFrameworkInstallName(installName, overrides) ? "framework" : "library";
			return overrides.some(({ phase, scope }) => (phase === "override" || !ordinarySearchFoundImage) && (scope === "all" || scope === kind || scope === "prefix" && !installName.startsWith("@")));
		};
	})))();
}

//#endregion
//#region dist/domain/apple/dylibResolutionFindings.js
var isLazyLoadCommand, deriveFindings, unresolvedFinding, missingCandidateExplanation, candidateRejection, dependencyPhrase, lazyConsequence, DYLIB_RESOLUTION_LIMITATIONS;
function init_dylibResolutionFindings() {
	return (init_dylibResolutionFindings = __esmMin((() => {
		isLazyLoadCommand = (command) => command === "LC_LAZY_LOAD_DYLIB" || command === "LC_LAZY_LOAD_DYLIB_INFO";
		deriveFindings = (edges, roots) => {
			const findings = [];
			edges.forEach((edge, index) => {
				if (edge.resolution.status === "unresolved") findings.push(unresolvedFinding(edge, index));
				const resolvedAt = edge.candidates.findIndex(({ outcome }) => outcome === "resolved");
				const earlier = edge.candidates.slice(0, Math.max(resolvedAt, 0)).filter(({ source, outcome }) => source === "rpath" && outcome === "absent").map(({ path }) => path);
				if (resolvedAt > 0 && earlier.length > 0) findings.push({
					kind: "earlier-rpath-candidate-absent",
					edge_index: index,
					image: edge.loader,
					basis: "derived",
					explanation: `The modeled dyld search checks ${earlier.join(", ")} before ${edge.resolution.image ?? edge.install_name}. A compatible Mach-O placed at an earlier modeled path could take precedence over that fallback, subject to unmodeled search inputs and code-signing library validation; library validation is not evaluated here (see inspect_signature).${edge.loader_conditional ? " This loader loads only conditionally; if it never loads, this search never occurs." : ""}${edge.resolution.status === "conditional" ? " Unmodeled environment overrides or earlier unknown candidates may take precedence; placing an image at this rpath does not establish which image dyld will load." : ""}`
				});
			});
			for (const { image, slice } of roots) {
				const { architecture } = slice;
				const environment = slice.dyld_environment;
				if (environment.length > 0) findings.push({
					kind: "dyld-environment-present",
					edge_index: null,
					image,
					basis: "derived",
					explanation: slice.file_type === "execute" ? `${image} (${architecture}) sets dyld environment variables through LC_DYLD_ENVIRONMENT (${environment.join(", ")}); any image-selection overrides they request are not modeled. Diagnostic settings alone do not alter resolution.` : `${image} (${architecture}) contains LC_DYLD_ENVIRONMENT (${environment.join(", ")}). Dyld reads these commands only from the main executable; entries in this non-executable root are observations and do not alter resolution.`
				});
			}
			return findings;
		};
		unresolvedFinding = (edge, index) => {
			const base = {
				edge_index: index,
				image: edge.loader,
				basis: "derived"
			};
			const lazy = isLazyLoadCommand(edge.command);
			const missing = missingCandidateExplanation(edge, dependencyPhrase(edge, lazy));
			const when = edge.loader_conditional ? `. ${edge.loader} loads only conditionally; if it loads, ` : "; ";
			if (lazy) return {
				...base,
				kind: "lazy-load-unresolved",
				explanation: `${missing}${when}${lazyConsequence(edge.weak)}`
			};
			return edge.weak ? {
				...base,
				kind: "weak-load-unresolved",
				explanation: `${missing}${when}dyld continues without it.`
			} : {
				...base,
				kind: "required-load-unresolved",
				explanation: `${missing}${when}dyld would fail to load this required dependency for ${edge.root} (${edge.architecture}) unless the image is supplied elsewhere.`
			};
		};
		missingCandidateExplanation = (edge, dependency) => {
			const present = edge.candidates.flatMap(({ outcome, resolved_path }) => resolved_path === null ? [] : [{
				outcome,
				path: resolved_path
			}]);
			if (present.length === 0) return `No candidate for ${dependency} exists in the analyzed root`;
			const descriptions = present.map(({ outcome, path }) => `${path} (${candidateRejection(outcome)})`);
			return `No usable candidate for ${dependency} exists in the analyzed root; found ${descriptions.join(", ")}`;
		};
		candidateRejection = (outcome) => {
			switch (outcome) {
				case "not-mach-o": return "not a Mach-O image";
				case "malformed": return "malformed";
				case "architecture-missing": return "missing the process architecture";
				case "not-loadable": return "not a loadable dylib";
				case "platform-mismatch": return "incompatible with the process platform";
				case "unsupported": return "unsupported by the parser";
				case "resolved": return "loadable";
				case "absent": return "absent";
				case "outside-target": return "outside the analyzed root";
				case "escapes-target": return "escapes the analyzed root";
				case "undetermined": return "of undetermined loadability";
			}
		};
		dependencyPhrase = (edge, lazy) => {
			if (lazy && edge.weak) return `lazily loaded weak dependency ${edge.install_name}`;
			if (lazy) return `lazily loaded ${edge.install_name}`;
			if (edge.weak) return `weak dependency ${edge.install_name}`;
			return edge.install_name;
		};
		lazyConsequence = (weak) => weak ? "dyld loads it on first use and continues if it is absent." : "dyld loads it on first use, which would fail unless the image is supplied elsewhere.";
		DYLIB_RESOLUTION_LIMITATIONS = [
			"LC_LAZY_LOAD_DYLIB and LC_LAZY_LOAD_DYLIB_INFO dependencies are resolved but not traversed, because dyld loads them only on first use.",
			"Slices are matched by dyld's graded architectures (an x86_64h process also loads x86_64). arm64e processes that disable pointer authentication can also load arm64 slices; that fallback is not modeled.",
			"Absolute install names and rpaths are outside the analyzed root and are not evaluated, including /System and /usr/lib libraries that the dyld shared cache usually provides.",
			"Leaf and relative install names depend on dyld fallback paths, DYLD_* variables, and the working directory; they are undetermined.",
			"Load order follows dyld's dependents-first traversal in load-command order. An image reached through several chains is resolved once per process, with the rpath stack and conditionality of the first chain; a later @rpath request whose install name matches an already loaded image reuses it.",
			"@loader_path uses each image's symlink-resolved path within the analyzed root.",
			"Code-signing checks that can reject a found image, such as library validation and the hardened runtime, are not evaluated.",
			"Dylib compatibility versions are not compared. Apple's linker documentation describes a load-time rejection when an image's compatibility version is older than the loader requires, but dyld on macOS 26 was observed to load such an image."
		];
	})))();
}

//#endregion
//#region dist/domain/apple/dylibResolution.js
var ROOT_RELATIVE_PATH, rootRelativePathSchema, dylibResolutionInputSchema, dependencyCommandSchema, IMPLICIT_MACOS_PLATFORM, MACOS_DYLD_IMPLICIT_PLATFORM_CPU_TYPES, dependencySchema, machoSliceSchema, candidateSchema, edgeSchema, findingSchema$1, imageSchema, dylibResolutionResultSchema, expandCandidatePath, appendRpath, candidateTemplates, evaluateCandidate, platformLoadability, imageLoadabilityForPlatform, isKnownPlatform, imageFacts, resolution, resolveDependency, traceProcess, projectTraceResult, traceDylibLoading, withoutDependencies, compare;
function init_dylibResolution() {
	return (init_dylibResolution = __esmMin((() => {
		init_analysisErrorCore();
		init_dyldPaths();
		init_digests();
		init_dyldEnvironment();
		init_dylibResolutionFindings();
		ROOT_RELATIVE_PATH = /^(?:[^\x2f\\\x00.][^\x2f\\\x00]*|\.[^\x2f\\\x00.][^\x2f\\\x00]*|\.\.[^\x2f\\\x00]+)(?:\x2f(?:[^\x2f\\\x00.][^\x2f\\\x00]*|\.[^\x2f\\\x00.][^\x2f\\\x00]*|\.\.[^\x2f\\\x00]+))*$/u;
		rootRelativePathSchema = z.string().min(1).regex(ROOT_RELATIVE_PATH, "Use a normalized path relative to the analyzed root, without a leading or trailing '/', '//', or '.' and '..' segments");
		dylibResolutionInputSchema = z.strictObject({
			roots: z.array(rootRelativePathSchema).min(1).optional(),
			architecture: z.enum([
				"arm64",
				"arm64e",
				"x86_64"
			]).optional()
		});
		dependencyCommandSchema = z.enum([
			"LC_LOAD_DYLIB",
			"LC_LOAD_WEAK_DYLIB",
			"LC_REEXPORT_DYLIB",
			"LC_LAZY_LOAD_DYLIB",
			"LC_LAZY_LOAD_DYLIB_INFO",
			"LC_LOAD_UPWARD_DYLIB"
		]);
		IMPLICIT_MACOS_PLATFORM = 1;
		MACOS_DYLD_IMPLICIT_PLATFORM_CPU_TYPES = new Set([
			7,
			16777223,
			16777228
		]);
		dependencySchema = z.strictObject({
			command: dependencyCommandSchema,
			encoding: z.enum([
				"dylib_command",
				"dylib_use_command",
				"lazy_load_dylib_info"
			]),
			install_name: z.string(),
			weak: z.boolean(),
			upward: z.boolean(),
			reexport: z.boolean(),
			delayed_init: z.boolean(),
			/**
			* Null for `lazy_load_dylib_info`: that payload has no version fields.
			* Classic dylib commands still carry both versions.
			*/
			current_version: z.string().nullable(),
			compatibility_version: z.string().nullable()
		});
		machoSliceSchema = z.strictObject({
			architecture: z.string().min(1),
			/** Physical identity observed in the thin header and, for FAT, its table. */
			slice_offset: z.number().int().nonnegative(),
			slice_size: z.number().int().positive(),
			cpu_type: z.number().int().nonnegative(),
			cpu_subtype: z.number().int().nonnegative(),
			fat_cpu_type: z.number().int().nonnegative().nullable(),
			fat_cpu_subtype: z.number().int().nonnegative().nullable(),
			fat_alignment_exponent: z.number().int().nonnegative().nullable(),
			file_type: z.enum([
				"execute",
				"dylib",
				"bundle",
				"other"
			]),
			file_type_code: z.number().int().nonnegative(),
			/** Raw LC_BUILD_VERSION platform number; null means no such command was observed. */
			platform: z.number().int().nonnegative().nullable(),
			/** Every distinct build platform declared by LC_BUILD_VERSION/version-min commands. */
			platforms: z.array(z.number().int().nonnegative()),
			install_name: z.string().nullable(),
			dependencies: z.array(dependencySchema),
			rpaths: z.array(z.string()),
			dyld_environment: z.array(z.string()),
			code_signature_present: z.boolean()
		});
		candidateSchema = z.strictObject({
			path: z.string(),
			source: z.enum([
				"literal",
				"executable_path",
				"loader_path",
				"rpath",
				"already-loaded"
			]),
			rpath: z.string().nullable(),
			rpath_owner: z.string().nullable(),
			outcome: z.enum([
				"resolved",
				"absent",
				"not-mach-o",
				"malformed",
				"unsupported",
				"architecture-missing",
				"not-loadable",
				"platform-mismatch",
				"outside-target",
				"escapes-target",
				"undetermined"
			]),
			resolved_path: z.string().nullable(),
			platform_basis: z.enum(["macos-dyld-implicit"]).optional()
		});
		edgeSchema = z.strictObject({
			root: z.string(),
			architecture: z.string(),
			loader: z.string(),
			via: z.array(z.string()),
			...dependencySchema.shape,
			candidates: z.array(candidateSchema),
			resolution: z.strictObject({
				status: z.enum([
					"resolved",
					"conditional",
					"unresolved",
					"undetermined"
				]),
				image: z.string().nullable()
			}),
			install_name_matches: z.boolean().nullable(),
			/**
			* The loader was reached through a conditional edge, so it might not load;
			* this edge describes what happens only if it does.
			*/
			loader_conditional: z.boolean()
		});
		findingSchema$1 = z.strictObject({
			kind: z.enum([
				"required-load-unresolved",
				"weak-load-unresolved",
				"lazy-load-unresolved",
				"earlier-rpath-candidate-absent",
				"dyld-environment-present"
			]),
			edge_index: z.number().int().nonnegative().nullable(),
			image: z.string().nullable(),
			basis: z.literal("derived"),
			explanation: z.string().min(1)
		});
		imageSchema = z.strictObject({
			path: z.string(),
			sha256: digestSchema,
			parse_status: z.enum([
				"parsed",
				"malformed",
				"unsupported"
			]),
			reason: z.string().nullable(),
			slices: z.array(machoSliceSchema.omit({ dependencies: true }))
		});
		dylibResolutionResultSchema = z.strictObject({
			root_path: z.string(),
			target_sha256: digestSchema,
			roots: z.array(z.strictObject({
				image: z.string(),
				architecture: z.string()
			})),
			images: z.array(imageSchema),
			edges: z.array(edgeSchema),
			findings: z.array(findingSchema$1),
			coverage: z.strictObject({
				status: z.enum(["complete", "partial"]),
				unparsed_images: z.array(z.string()),
				roots_without_architecture: z.array(z.string())
			}),
			limitations: z.array(z.string().min(1))
		});
		expandCandidatePath = (raw, ownerDirectory, context) => expandPrefix(raw, {
			ownerDirectory,
			executable: context.executable,
			rootRelativePath: (absolutePath) => context.view.rootRelativePath(absolutePath)
		});
		appendRpath = (base, rest) => {
			if (base === "") return rest;
			if (base === "/") return `/${rest}`;
			return `${base.replace(/\/+$/u, "")}/${rest}`;
		};
		candidateTemplates = (dependency, loader, context) => {
			const name = dependency.install_name;
			if (!name.startsWith("@rpath/")) {
				const source = name.startsWith("@executable_path") ? "executable_path" : name.startsWith("@loader_path") ? "loader_path" : "literal";
				return [{
					expansion: expandCandidatePath(name, directoryOf(loader), context),
					source,
					rpath: null,
					rpathOwner: null
				}];
			}
			const rest = name.slice("@rpath/".length);
			const owners = [...context.loaded.get(loader)?.chain ?? [loader]].reverse();
			return owners.flatMap((owner) => (context.loaded.get(owner)?.slice.rpaths ?? []).map((rpath) => {
				const base = expandCandidatePath(rpath, directoryOf(owner), context);
				const lookupPath = base.scope === "target" ? base.lookupPath : undefined;
				const expansion = {
					scope: base.scope,
					path: base.scope === "outside" || lookupPath !== undefined ? appendRpath(base.path, rest) : `${base.path}${base.path === "" ? "" : "/"}${rest}`,
					...lookupPath === undefined ? {} : { lookupPath: appendRpath(lookupPath, rest) }
				};
				return {
					expansion,
					source: "rpath",
					rpath,
					rpathOwner: owner
				};
			}));
		};
		evaluateCandidate = async (template, context) => {
			const base = {
				path: template.expansion.path,
				source: template.source,
				rpath: template.rpath,
				rpath_owner: template.rpathOwner
			};
			if (template.expansion.scope === "outside") return {
				...base,
				outcome: "outside-target",
				resolved_path: null
			};
			if (template.expansion.scope === "undetermined") return {
				...base,
				outcome: "undetermined",
				resolved_path: null
			};
			const lookup = await resolveTreePath(context.view, template.expansion.lookupPath ?? template.expansion.path);
			if (lookup.kind === "escapes") return {
				...base,
				outcome: "escapes-target",
				resolved_path: null
			};
			if (lookup.kind !== "file") return {
				...base,
				outcome: "absent",
				resolved_path: null
			};
			const facts = await imageFacts(context, lookup.path);
			let outcome;
			if (facts.status !== "parsed") outcome = facts.status;
			else {
				const slice = compatibleSlice(facts.slices, context.processIdentity);
				if (slice === undefined) outcome = "architecture-missing";
				else if (slice.file_type_code !== 6) outcome = "not-loadable";
				else {
					const platformResult = platformLoadability(context, slice);
					outcome = platformResult.outcome === "compatible" ? "resolved" : platformResult.outcome === "incompatible" ? "platform-mismatch" : "undetermined";
					if (outcome === "undetermined") context.unknownPlatformCandidates.add(lookup.path);
					if (platformResult.basis !== undefined) {
						context.implicitMacOSPlatformCandidates.add(lookup.path);
						return {
							...base,
							outcome,
							resolved_path: lookup.path,
							platform_basis: platformResult.basis
						};
					}
				}
			}
			return {
				...base,
				outcome,
				resolved_path: lookup.path
			};
		};
		platformLoadability = (context, image) => {
			const { platforms: processPlatforms } = context;
			const { file_type_code: fileType, platforms: imagePlatforms } = image;
			let effectiveImagePlatforms = imagePlatforms;
			let basis;
			if (imagePlatforms.length === 0) {
				if (context.executable !== null && processPlatforms.length === 1 && processPlatforms[0] === IMPLICIT_MACOS_PLATFORM && MACOS_DYLD_IMPLICIT_PLATFORM_CPU_TYPES.has(image.cpu_type)) {
					effectiveImagePlatforms = [IMPLICIT_MACOS_PLATFORM];
					basis = "macos-dyld-implicit";
				} else return { outcome: "unknown" };
			}
			if (processPlatforms.length === 0) return { outcome: "unknown" };
			const outcomes = processPlatforms.map((processPlatform) => imageLoadabilityForPlatform(processPlatform, effectiveImagePlatforms, fileType, image.architecture));
			if (outcomes.every((outcome) => outcome === "compatible")) return {
				outcome: "compatible",
				...basis === undefined ? {} : { basis }
			};
			if (outcomes.every((outcome) => outcome === "incompatible")) return {
				outcome: "incompatible",
				...basis === undefined ? {} : { basis }
			};
			return {
				outcome: "unknown",
				...basis === undefined ? {} : { basis }
			};
		};
		imageLoadabilityForPlatform = (processPlatform, imagePlatforms, fileType, architecture) => {
			if (imagePlatforms.includes(processPlatform)) return "compatible";
			if (processPlatform === 6 && imagePlatforms.includes(1)) return "compatible";
			if (processPlatform === 2 && imagePlatforms.includes(6)) return "compatible";
			if (processPlatform === 2 && imagePlatforms.includes(11)) return "compatible";
			if (processPlatform === 7 && imagePlatforms.includes(12)) return "compatible";
			if (processPlatform === 1 && fileType === 2 && imagePlatforms.includes(6)) return "compatible";
			if (processPlatform === 2 && imagePlatforms.includes(1) && architecture.startsWith("arm64") || [
				7,
				8,
				9
			].includes(processPlatform) && imagePlatforms.includes(1)) return "unknown";
			if (isKnownPlatform(processPlatform) && imagePlatforms.every(isKnownPlatform)) return "incompatible";
			return "unknown";
		};
		isKnownPlatform = (platform) => platform >= 1 && platform <= 12;
		imageFacts = async (context, path) => {
			const known = context.images.get(path);
			if (known !== undefined) return known;
			const facts = await context.view.image(path);
			context.images.set(path, facts);
			return facts;
		};
		resolution = (candidates) => {
			let external = false;
			for (const candidate of candidates) {
				if (candidate.outcome === "resolved") return {
					status: external ? "conditional" : "resolved",
					image: candidate.resolved_path
				};
				if (candidate.outcome === "outside-target" || candidate.outcome === "escapes-target" || candidate.outcome === "unsupported" || candidate.outcome === "undetermined") external = true;
			}
			return {
				status: external ? "undetermined" : "unresolved",
				image: null
			};
		};
		resolveDependency = async (dependency, loader, context) => {
			const current = context.loaded.get(loader);
			const chain = current?.chain ?? [loader];
			const loaded = dependency.install_name.startsWith("@rpath/") ? context.byInstallName.get(dependency.install_name) : undefined;
			const candidates = [];
			if (loaded !== undefined) candidates.push({
				path: dependency.install_name,
				source: "already-loaded",
				rpath: null,
				rpath_owner: null,
				outcome: "resolved",
				resolved_path: loaded
			});
			else for (const template of candidateTemplates(dependency, loader, context)) {
				const candidate = await evaluateCandidate(template, context);
				candidates.push(candidate);
				if (candidate.outcome === "resolved") break;
			}
			const modeled = resolution(candidates);
			const searchUnknown = loaded === undefined && hasApplicableDyldOverrides(context.searchOverrides, dependency.install_name, modeled.image !== null);
			if (searchUnknown) context.environmentRoots.add(context.root);
			const searched = searchUnknown ? {
				...modeled,
				status: modeled.image === null ? "undetermined" : "conditional"
			} : modeled;
			const resolved = loaded !== undefined && context.loaded.get(loaded)?.conditional === true && searched.status === "resolved" ? {
				...searched,
				status: "conditional"
			} : searched;
			const image = resolved.image === null ? undefined : context.images.get(resolved.image);
			const slice = image?.status === "parsed" ? compatibleSlice(image.slices, context.processIdentity) : undefined;
			return {
				root: context.root,
				architecture: context.processIdentity.architecture,
				loader,
				via: [...chain],
				...dependency,
				candidates,
				resolution: resolved,
				install_name_matches: slice === undefined || slice.install_name === null ? null : slice.install_name === dependency.install_name,
				loader_conditional: current?.conditional ?? false
			};
		};
		traceProcess = async (context, rootSlice, signal) => {
			const edges = [];
			context.loaded.set(context.root, {
				slice: rootSlice,
				chain: [context.root],
				conditional: false
			});
			if (rootSlice.install_name !== null && rootSlice.install_name.startsWith("@rpath/")) context.byInstallName.set(rootSlice.install_name, context.root);
			const pending = [context.root];
			while (pending.length > 0) {
				if (signal?.aborted) throw new AnalysisCancelledError("trace_dylib_resolution", { cause: signal.reason });
				const loader = pending.pop() ?? "";
				const current = context.loaded.get(loader);
				if (current === undefined) continue;
				const created = [];
				for (const dependency of current.slice.dependencies) {
					const edge = await resolveDependency(dependency, loader, context);
					edges.push(edge);
					if (isLazyLoadCommand(dependency.command)) continue;
					const image = edge.resolution.image;
					if (image === null || context.loaded.has(image)) continue;
					const facts = context.images.get(image);
					const slice = facts?.status === "parsed" ? compatibleSlice(facts.slices, context.processIdentity) : undefined;
					if (slice === undefined) continue;
					context.loaded.set(image, {
						slice,
						chain: [...current.chain, image],
						conditional: current.conditional || edge.resolution.status === "conditional"
					});
					if (slice.install_name !== null && slice.install_name.startsWith("@rpath/") && !context.byInstallName.has(slice.install_name)) context.byInstallName.set(slice.install_name, image);
					created.push(image);
				}
				pending.push(...created.reverse());
			}
			return edges;
		};
		projectTraceResult = (input) => {
			const reported = [...input.images.entries()].filter(([, facts]) => facts.status !== "not-mach-o").sort(([left], [right]) => compare(left, right));
			const unparsed = reported.filter(([, facts]) => facts.status !== "parsed").map(([path]) => path);
			return {
				roots: input.roots,
				images: reported.map(([path, facts]) => ({
					path,
					parse_status: facts.status === "not-mach-o" ? "unsupported" : facts.status,
					reason: facts.status === "parsed" || facts.status === "not-mach-o" ? null : facts.reason,
					slices: facts.status === "parsed" ? facts.slices.map(withoutDependencies) : []
				})),
				edges: [...input.edges],
				findings: deriveFindings(input.edges, input.rootSlices),
				coverage: {
					status: unparsed.length === 0 && input.withoutArchitecture.length === 0 && input.environmentRoots.size === 0 && input.unknownPlatformCandidates.size === 0 ? "complete" : "partial",
					unparsed_images: unparsed,
					roots_without_architecture: [...input.withoutArchitecture]
				},
				limitations: [
					...DYLIB_RESOLUTION_LIMITATIONS,
					...input.environmentRoots.size === 0 ? [] : [`Roots ${[...input.environmentRoots].join(", ")} request applicable image-selection inputs through LC_DYLD_ENVIRONMENT that are not modeled; affected dependencies or inserted images remain uncertain.`],
					...input.unknownPlatformCandidates.size === 0 ? [] : [`In-root dylib candidates ${[...input.unknownPlatformCandidates].sort(compare).join(", ")} have unknown platform compatibility and are not treated as incompatible. Their dependent graphs may be incomplete.`],
					...input.implicitMacOSPlatformCandidates.size === 0 ? [] : [`In-root dylib candidates ${[...input.implicitMacOSPlatformCandidates].sort(compare).join(", ")} have no observed platform load command; macOS compatibility was derived from dyld's implicit-platform rule for an executable root with explicit macOS platform and a supported CPU type. Reported platform facts remain unchanged.`]
				]
			};
		};
		traceDylibLoading = async (view, request) => {
			const images = new Map();
			for (const path of request.unclassified ?? []) images.set(path, await view.image(path));
			const roots = [];
			const rootSlices = [];
			const edges = [];
			const withoutArchitecture = [];
			const environmentRoots = new Set();
			const unknownPlatformCandidates = new Set();
			const implicitMacOSPlatformCandidates = new Set();
			for (const root of request.roots) {
				const facts = await view.image(root);
				images.set(root, facts);
				if (facts.status !== "parsed") continue;
				const slices = facts.slices.filter(({ architecture }) => request.architecture === undefined || architecture === request.architecture);
				if (slices.length === 0) withoutArchitecture.push(root);
				for (const slice of slices) {
					const executable = slice.file_type === "execute" ? root : null;
					const searchOverrides = executable === null ? [] : embeddedDyldOverrides(slice.dyld_environment, slice.platforms);
					if (searchOverrides.some(({ variable, value }) => variable === "DYLD_INSERT_LIBRARIES" && value !== "")) environmentRoots.add(root);
					roots.push({
						image: root,
						architecture: slice.architecture
					});
					rootSlices.push({
						image: root,
						slice
					});
					edges.push(...await traceProcess({
						view,
						root,
						processIdentity: {
							architecture: slice.architecture,
							cpu_type: slice.cpu_type,
							cpu_subtype: slice.cpu_subtype
						},
						searchOverrides,
						environmentRoots,
						unknownPlatformCandidates,
						implicitMacOSPlatformCandidates,
						platforms: slice.platforms,
						executable,
						loaded: new Map(),
						byInstallName: new Map(),
						images
					}, slice, request.signal));
				}
			}
			return projectTraceResult({
				images,
				roots,
				rootSlices,
				edges,
				withoutArchitecture,
				environmentRoots,
				unknownPlatformCandidates,
				implicitMacOSPlatformCandidates
			});
		};
		withoutDependencies = (slice) => ({
			architecture: slice.architecture,
			slice_offset: slice.slice_offset,
			slice_size: slice.slice_size,
			cpu_type: slice.cpu_type,
			cpu_subtype: slice.cpu_subtype,
			fat_cpu_type: slice.fat_cpu_type,
			fat_cpu_subtype: slice.fat_cpu_subtype,
			fat_alignment_exponent: slice.fat_alignment_exponent,
			file_type: slice.file_type,
			file_type_code: slice.file_type_code,
			platform: slice.platform,
			platforms: slice.platforms,
			install_name: slice.install_name,
			rpaths: slice.rpaths,
			dyld_environment: slice.dyld_environment,
			code_signature_present: slice.code_signature_present
		});
		compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
	})))();
}

//#endregion
//#region dist/domain/apple/unknownPlistScalar.js
var UnknownPlistScalar;
function init_unknownPlistScalar() {
	return (init_unknownPlistScalar = __esmMin((() => {
		UnknownPlistScalar = class {
			element;
			rawLiteral;
			reason;
			constructor(element, rawLiteral, reason) {
				this.element = element;
				this.rawLiteral = rawLiteral;
				this.reason = reason;
			}
		};
	})))();
}

//#endregion
//#region dist/domain/apple/plistValue.js
var MAX_PLIST_DEPTH, unknownDateLimitation, binaryDatePrecisionOverlapLimitation, unknownScalarLimitation, nonFiniteRealLimitation, negativeZeroReal, negativeZeroRealLimitation, projectPlistValue;
function init_plistValue() {
	return (init_plistValue = __esmMin((() => {
		init_unknownPlistScalar();
		MAX_PLIST_DEPTH = 128;
		unknownDateLimitation = (count) => `${String(count)} date value(s) are reported as { "$plist_type": "date", "iso8601": null } because the decoder could not represent their timestamps.`;
		binaryDatePrecisionOverlapLimitation = (count) => `${String(count)} date value(s) are reported with unknown timestamps because their sub-millisecond source records overlap another reachable binary object and the public date projection cannot express their exact instants.`;
		unknownScalarLimitation = (count) => `${String(count)} XML scalar value(s) could not be established; their exact literals and reasons are retained in { "$plist_type": "unknown", "element": ..., "literal": ..., "reason": ... } wrappers.`;
		nonFiniteRealLimitation = (count) => `${String(count)} non-finite real value(s) are reported as { "$plist_type": "real", "value": "<spelling>" } using canonical numeric labels nan, +infinity or -infinity because a JSON number cannot carry them.`;
		negativeZeroReal = () => ({
			$plist_type: "real",
			value: "-0"
		});
		negativeZeroRealLimitation = (count) => `${String(count)} negative-zero real value(s) are reported as { "$plist_type": "real", "value": "-0" } because a JSON number cannot carry the sign of zero.`;
		projectPlistValue = (value, onWrappedScalar) => {
			let nonFiniteRealCount = 0;
			let negativeZeroRealCount = 0;
			let unknownDateCount = 0;
			let unknownScalarCount = 0;
			const scalar = (value) => {
				onWrappedScalar?.(value);
				return value;
			};
			const project = (item, depth) => {
				if (depth > 128) throw new RangeError(`Plist exceeds ${String(128)} nesting levels`);
				if (item !== null && typeof item === "object" && types.isProxy(item)) throw new TypeError("Plist values cannot contain proxies");
				if (item instanceof Uint8Array) return scalar({
					$plist_type: "data",
					base64: Buffer.from(item).toString("base64")
				});
				if (item instanceof UnknownPlistScalar) {
					unknownScalarCount += 1;
					return scalar({
						$plist_type: "unknown",
						element: item.element,
						literal: item.rawLiteral,
						reason: item.reason
					});
				}
				if (item instanceof Date) {
					if (!Number.isNaN(Date.prototype.getTime.call(item))) return scalar({
						$plist_type: "date",
						iso8601: Date.prototype.toISOString.call(item)
					});
					unknownDateCount += 1;
					return scalar({
						$plist_type: "date",
						iso8601: null
					});
				}
				if (typeof item === "number" && !Number.isFinite(item)) {
					nonFiniteRealCount += 1;
					const label = Number.isNaN(item) ? "nan" : item > 0 ? "+infinity" : "-infinity";
					return scalar({
						$plist_type: "real",
						value: label
					});
				}
				if (typeof item === "number" && Object.is(item, -0)) {
					negativeZeroRealCount += 1;
					return scalar(negativeZeroReal());
				}
				if (typeof item === "bigint") return scalar({
					$plist_type: "integer",
					decimal: item.toString()
				});
				if (Array.isArray(item)) {
					const result = [];
					for (let index = 0; index < item.length; index++) {
						const descriptor = Object.getOwnPropertyDescriptor(item, index);
						if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) throw new TypeError("Plist arrays require dense data properties without accessors");
						result.push(project(descriptor.value, depth + 1));
					}
					return result;
				}
				if (item !== null && typeof item === "object") {
					const entries = [];
					for (const key of Reflect.ownKeys(item)) {
						const descriptor = Object.getOwnPropertyDescriptor(item, key);
						if (descriptor?.enumerable !== true) continue;
						if (typeof key !== "string" || !Object.hasOwn(descriptor, "value")) throw new TypeError("Plist dictionary entries require string keys and data properties");
						entries.push([key, project(descriptor.value, depth + 1)]);
					}
					return Object.fromEntries(entries);
				}
				return z.union([
					z.string(),
					z.number(),
					z.boolean(),
					z.null()
				]).parse(item);
			};
			const projected = project(value, 0);
			return {
				value: projected,
				nonFiniteRealCount,
				negativeZeroRealCount,
				unknownDateCount,
				unknownScalarCount
			};
		};
	})))();
}

//#endregion
//#region dist/domain/apple/keyedArchive.js
var KeyedArchiveKindError, keyedArchiveInputSchema, linkSchema, keyedArchiveResultSchema, record, uid, archiverMismatch, projectKeyedArchive;
function init_keyedArchive() {
	return (init_keyedArchive = __esmMin((() => {
		init_bundleResourceRoot();
		init_analysisErrorCore();
		init_jsonValue();
		init_localPath();
		init_plistValue();
		KeyedArchiveKindError = class extends TypeError {
			kind;
			name = "KeyedArchiveKindError";
			constructor(message, kind) {
				super(message);
				this.kind = kind;
			}
		};
		keyedArchiveInputSchema = z.strictObject({
			path: localPathStringSchema.default("."),
			root: z.string().optional(),
			offset: z.number().int().min(0).default(0),
			limit: z.number().int().min(1).max(2e4).default(2e4)
		});
		linkSchema = z.strictObject({
			source: z.number().int().nonnegative().nullable(),
			path: z.array(z.union([z.string(), z.number().int().nonnegative()])),
			target: z.number().int().nonnegative().nullable(),
			status: z.enum([
				"resolved",
				"nil",
				"unresolved",
				"malformed"
			]),
			raw: jsonValueSchema
		});
		keyedArchiveResultSchema = bundleResourceBoundResultSchema(z.string(), {
			archive_path: z.string(),
			archive_sha256: z.string(),
			archive_format: z.enum(["binary-plist", "xml-plist"]),
			roots: z.record(z.string(), jsonValueSchema),
			objects: z.array(z.strictObject({
				id: z.number().int().nonnegative(),
				kind: z.enum([
					"nil",
					"scalar",
					"array",
					"dictionary",
					"class-descriptor",
					"archived-object"
				]),
				class_id: z.number().int().nonnegative().nullable(),
				class_name: z.string().nullable(),
				status: z.enum([
					"observed",
					"unknown-class",
					"unresolved-class",
					"nil"
				]),
				value: jsonValueSchema
			})),
			references: z.array(linkSchema),
			total_objects: z.number().int().nonnegative(),
			total_references: z.number().int().nonnegative(),
			offset: z.number().int().nonnegative(),
			next_offset: z.number().int().nonnegative().nullable(),
			truncated: z.boolean(),
			limitations: z.array(z.string())
		});
		record = (value, wrappedScalars) => value !== null && typeof value === "object" && !Array.isArray(value) && !wrappedScalars.has(value) ? value : undefined;
		uid = (value, wrappedScalars) => {
			const object = record(value, wrappedScalars);
			if (object === undefined || Object.keys(object).length !== 1) return undefined;
			const marker = Object.hasOwn(object, "UID") ? object.UID : object["CF$UID"];
			return typeof marker === "number" ? marker : undefined;
		};
		archiverMismatch = (archive) => {
			if (archive === undefined) return "its root is not a dictionary";
			if (!Object.hasOwn(archive, "$archiver")) return "it has no $archiver key";
			return typeof archive.$archiver === "string" ? `its $archiver is ${JSON.stringify(archive.$archiver)}` : "its $archiver is not a string";
		};
		projectKeyedArchive = (value, selection) => {
			const wrappedScalars = new WeakSet();
			const projected = projectPlistValue(value, (scalar) => wrappedScalars.add(scalar));
			const archive = record(projected.value, wrappedScalars);
			if (archive?.$archiver !== "NSKeyedArchiver") throw new KeyedArchiveKindError(`Selected property list is not an NSKeyedArchiver archive: ${archiverMismatch(archive)}`, "property-list");
			if (!Array.isArray(archive.$objects)) throw new TypeError("Expected NSKeyedArchiver with an $objects array");
			const table = archive.$objects;
			if (table.length > 2e5) throw new RangeError("Archive exceeds 200000 object-table entries");
			const top = record(archive.$top, wrappedScalars);
			if (top === undefined || Object.keys(top).length === 0) throw new TypeError("Keyed archive has no $top roots");
			if (selection.root !== undefined && !Object.hasOwn(top, selection.root)) throw new AnalysisInputError("inspect_keyed_archive", undefined, [{
				path: ["root"],
				reason: "invalid_value",
				message: `Archive root does not exist: ${selection.root}. Select one of the archive's $top roots or omit root.`,
				expected: Object.keys(top)
			}]);
			const roots = selection.root === undefined ? top : { [selection.root]: top[selection.root] ?? null };
			const references = [];
			const scan = (source, initial) => {
				const pending = initial;
				let visited = 0;
				while (pending.length > 0) {
					const item = pending.pop();
					if (item === undefined) break;
					if (++visited > 2e5 || item.path.length > 128) throw new RangeError("Archive exceeds 200000 values per object or 128 nesting levels");
					const target = uid(item.value, wrappedScalars);
					if (target !== undefined) {
						const index = Number.isSafeInteger(target) && target >= 0 ? target : null;
						references.push({
							source,
							path: item.path,
							target: index,
							raw: item.value,
							status: index === null ? "malformed" : index >= table.length ? "unresolved" : index === 0 && table[0] === "$null" ? "nil" : "resolved"
						});
					} else if (Array.isArray(item.value)) {
						for (let index = item.value.length - 1; index >= 0; index--) {
							const child = item.value[index];
							if (child !== undefined) pending.push({
								value: child,
								path: [...item.path, index]
							});
						}
					} else {
						const fields = record(item.value, wrappedScalars);
						if (fields !== undefined) for (const key of Object.keys(fields).sort().reverse()) {
							const child = fields[key];
							if (child !== undefined) pending.push({
								value: child,
								path: [...item.path, key]
							});
						}
					}
					if (references.length > 2e5) throw new RangeError("Archive exceeds 200000 reference edges");
				}
			};
			scan(null, Object.keys(roots).sort().reverse().flatMap((key) => {
				const value = roots[key];
				return value === undefined ? [] : [{
					value,
					path: [key]
				}];
			}));
			const objects = table.map((value, id) => {
				scan(id, [{
					value,
					path: []
				}]);
				const fields = record(value, wrappedScalars);
				const classUid = uid(fields?.$class, wrappedScalars);
				const classId = classUid !== undefined && Number.isSafeInteger(classUid) && classUid >= 0 ? classUid : null;
				const descriptor = classId === null ? undefined : record(table[classId], wrappedScalars);
				const className = typeof descriptor?.$classname === "string" ? descriptor.$classname : null;
				const isNil = id === 0 && value === "$null";
				return {
					id,
					kind: isNil ? "nil" : Array.isArray(value) ? "array" : fields === undefined ? "scalar" : typeof fields.$classname === "string" ? "class-descriptor" : Object.hasOwn(fields, "$class") ? "archived-object" : "dictionary",
					class_id: classId,
					class_name: className,
					status: isNil ? "nil" : fields !== undefined && Object.hasOwn(fields, "$class") ? className === null ? "unresolved-class" : "unknown-class" : "observed",
					value
				};
			});
			const end = Math.min(objects.length, selection.offset + selection.limit);
			const page = objects.slice(selection.offset, end);
			const ids = new Set(page.map(({ id }) => id));
			return {
				nonFiniteRealCount: projected.nonFiniteRealCount,
				negativeZeroRealCount: projected.negativeZeroRealCount,
				unknownDateCount: projected.unknownDateCount,
				unknownScalarCount: projected.unknownScalarCount,
				roots,
				objects: page,
				references: references.filter(({ source }) => source === null || ids.has(source)),
				total_objects: objects.length,
				total_references: references.length,
				offset: selection.offset,
				next_offset: end < objects.length ? end : null,
				truncated: page.length !== objects.length,
				limitations: [
					"Archive classes are never instantiated. Class names and serialized fields are observed; class-specific semantics are unknown.",
					"Conditional references serialized as UID 0 cannot be distinguished from ordinary nil references. Missing fields remain absent in the raw serialized value.",
					"Root selection selects the named $top entry; object pagination retains original indices and does not recursively expand references."
				]
			};
		};
	})))();
}

//#endregion
//#region dist/domain/apple/appleAssetCatalog.js
var RESOURCE_KEY_FIELDS, appleResourceKeyFields, appleAssetCatalogInputSchema, catalogSchema, recordSchema, resourceKeyMatchSchema, appleAssetCatalogResultSchema, parseAppleAssetCatalogRecords, projectAppleAssetCatalogPage;
function init_appleAssetCatalog() {
	return (init_appleAssetCatalog = __esmMin((() => {
		init_bundleResourceRoot();
		init_jsonValue();
		init_analysisErrorCore();
		RESOURCE_KEY_FIELDS = new Set([
			"image",
			"imageName",
			"image_name",
			"resourceName",
			"resource_name",
			"assetName",
			"asset_name",
			"UIImageName",
			"NSImageName"
		]);
		appleResourceKeyFields = (attributes) => Object.entries(attributes).filter((entry) => RESOURCE_KEY_FIELDS.has(entry[0]) && typeof entry[1] === "string" && entry[1].length > 0);
		appleAssetCatalogInputSchema = z.strictObject({
			offset: z.number().int().min(0).default(0),
			limit: z.number().int().min(1).max(1e4).default(1e3)
		});
		catalogSchema = z.strictObject({
			path: z.string().min(1),
			sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			record_count: z.number().int().nonnegative()
		});
		recordSchema = z.strictObject({
			catalog_path: z.string().min(1),
			catalog_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			index: z.number().int().nonnegative(),
			kind: z.enum(["catalog", "rendition"]),
			asset_name: z.string().nullable(),
			rendition_name: z.string().nullable(),
			metadata: z.record(z.string(), jsonValueSchema)
		});
		resourceKeyMatchSchema = z.strictObject({
			source_node_id: z.string().min(1),
			source_path: z.string().min(1),
			source_archive_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
			field: z.string().min(1),
			key: z.string().min(1),
			status: z.enum([
				"matched",
				"ambiguous",
				"unmatched"
			]),
			renditions: z.array(z.strictObject({
				catalog_path: z.string().min(1),
				catalog_sha256: z.string().regex(/^[a-f0-9]{64}$/u),
				record_index: z.number().int().nonnegative(),
				rendition_name: z.string().nullable()
			}))
		});
		appleAssetCatalogResultSchema = bundleResourceBoundResultSchema(z.string().regex(/^[a-f0-9]{64}$/u), {
			catalogs: z.array(catalogSchema),
			total_records: z.number().int().nonnegative(),
			offset: z.number().int().nonnegative(),
			limit: z.number().int().positive(),
			records: z.array(recordSchema),
			resource_key_matches: z.array(resourceKeyMatchSchema),
			next_offset: z.number().int().nonnegative().nullable(),
			truncated: z.boolean(),
			limitations: z.array(z.string())
		});
		parseAppleAssetCatalogRecords = (value) => {
			if (!Array.isArray(value)) throw new AnalysisOutputError("inspect_asset_catalog", "assetutil output must be a JSON array");
			return value.map((record, index) => {
				const parsed = z.record(z.string(), jsonValueSchema).safeParse(record);
				if (!parsed.success) throw new AnalysisOutputError("inspect_asset_catalog", `assetutil record ${index} is not a JSON object`, { cause: parsed.error });
				return parsed.data;
			});
		};
		projectAppleAssetCatalogPage = (input) => {
			const all = input.catalogs.flatMap((catalog) => catalog.records.map((metadata, index) => ({
				catalog_path: catalog.path,
				catalog_sha256: catalog.sha256,
				index,
				kind: typeof metadata.RenditionName === "string" || typeof metadata.Name === "string" ? "rendition" : "catalog",
				asset_name: typeof metadata.Name === "string" ? metadata.Name : null,
				rendition_name: typeof metadata.RenditionName === "string" ? metadata.RenditionName : null,
				metadata
			})));
			const records = all.slice(input.offset, input.offset + input.limit);
			const next = input.offset + records.length;
			const recordsByAssetName = new Map();
			for (const record of all) {
				if (record.kind !== "rendition" || record.asset_name === null) continue;
				const matches = recordsByAssetName.get(record.asset_name) ?? [];
				matches.push(record);
				recordsByAssetName.set(record.asset_name, matches);
			}
			const resourceKeyMatches = (input.resourceReferences ?? []).map((source) => {
				const matches = recordsByAssetName.get(source.key) ?? [];
				return {
					source_node_id: source.sourceNodeId,
					source_path: source.sourcePath,
					source_archive_sha256: source.sourceArchiveSha256,
					field: source.field,
					key: source.key,
					status: matches.length === 0 ? "unmatched" : matches.length === 1 ? "matched" : "ambiguous",
					renditions: matches.map((record) => ({
						catalog_path: record.catalog_path,
						catalog_sha256: record.catalog_sha256,
						record_index: record.index,
						rendition_name: record.rendition_name
					}))
				};
			});
			return appleAssetCatalogResultSchema.parse({
				target_sha256: input.targetSha256,
				...input.resourceRoot === undefined ? {} : { resource_root: input.resourceRoot },
				catalogs: input.catalogs.map(({ path, sha256, records: catalogRecords }) => ({
					path,
					sha256,
					record_count: catalogRecords.length
				})),
				total_records: all.length,
				offset: input.offset,
				limit: input.limit,
				records,
				resource_key_matches: resourceKeyMatches,
				next_offset: next < all.length ? next : null,
				truncated: records.length !== all.length,
				limitations: ["Rendition metadata is reported as emitted by the installed assetutil version; private fields and platform-specific interpretations are not normalized.", "Asset catalog inspection does not decode or extract rendition image bytes."]
			});
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedMemberSignatureIdentity.js
var signatureIdentity, hasSignatureResolution, withoutResolution, comparableSides;
function init_managedMemberSignatureIdentity() {
	return (init_managedMemberSignatureIdentity = __esmMin((() => {
		signatureIdentity = ({ raw_sha256, resolved_sha256 }) => resolved_sha256 === null ? `raw:${raw_sha256}` : `resolved:${resolved_sha256}`;
		hasSignatureResolution = (result) => result.signature_resolution !== null || result.methods.length === 0 && result.fields.length === 0;
		withoutResolution = (members) => members.map((member) => ({
			...member,
			signature: {
				...member.signature,
				resolved_sha256: null
			}
		}));
		comparableSides = (left, right) => {
			if (hasSignatureResolution(left.result) && hasSignatureResolution(right.result)) return [left, right];
			const raw = (side) => ({
				...side,
				result: {
					...side.result,
					methods: withoutResolution(side.result.methods),
					fields: withoutResolution(side.result.fields)
				}
			});
			return [raw(left), raw(right)];
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedMemberComparisonCoverage.js
var buildComparisonCoverage, sameSelection, sideCoverageStatus, sideManifest, buildComparisonSummary, buildComparisonMatching, comparisonLimitations;
function init_managedMemberComparisonCoverage() {
	return (init_managedMemberComparisonCoverage = __esmMin((() => {
		init_managedMemberSignatureIdentity();
		buildComparisonCoverage = ({ left, right }) => {
			const leftStatus = sideCoverageStatus(left);
			const rightStatus = sideCoverageStatus(right);
			const unknownInput = left.coverage.state !== "complete" || right.coverage.state !== "complete" || !sameSelection(left, right);
			return {
				status: !unknownInput && leftStatus === "complete" && rightStatus === "complete" ? "complete-within-inputs" : "partial",
				left_status: leftStatus,
				right_status: rightStatus
			};
		};
		sameSelection = (left, right) => {
			if (left.selection === null || right.selection === null) return left.selection === right.selection;
			const rightNames = new Set(right.selection.type_names);
			return rightNames.size === new Set(left.selection.type_names).size && left.selection.type_names.every((name) => rightNames.has(name));
		};
		sideCoverageStatus = (result) => result.coverage.state === "unavailable" ? "unavailable" : result.coverage.state === "complete" ? "complete" : "partial";
		sideManifest = (side) => ({
			evidence_id: side.evidenceId,
			artifact_sha256: side.result.artifact.sha256,
			mvid: side.result.module?.mvid ?? null,
			module_name: side.result.module?.name ?? null,
			metadata_status: side.result.metadata.status,
			methods_total: side.result.methods.length,
			fields_total: side.result.fields.length
		});
		buildComparisonSummary = (items) => ({
			unchanged: items.filter(({ status }) => status === "unchanged").length,
			changed: items.filter(({ status }) => status === "changed").length,
			added: items.filter(({ status }) => status === "added").length,
			removed: items.filter(({ status }) => status === "removed").length,
			unknown: items.filter(({ status }) => status === "unknown").length
		});
		buildComparisonMatching = (methodItems, fieldItems) => ({
			exact_il_signature: methodItems.filter(({ match }) => match.basis === "exact-il-signature").length,
			exact_signature: [...methodItems, ...fieldItems].filter(({ match }) => match.basis === "exact-signature").length,
			structural_method_shape: methodItems.filter(({ match }) => match.basis === "structural-method-shape").length,
			field_signature: fieldItems.filter(({ match }) => match.basis === "field-signature").length,
			ambiguous: methodItems.filter(({ match }) => match.status === "ambiguous").length + fieldItems.filter(({ match }) => match.status === "ambiguous").length,
			unmatched: [...methodItems, ...fieldItems].filter(({ match }) => match.status === "unmatched").length
		});
		comparisonLimitations = (left, right) => {
			const limitations = [
				"Metadata tokens are build-local coordinates; matched pairs are remaps, not persistent identities.",
				"Methods pair within one declared type and name by exact CIL/signature, then signature, then structural shape; only then may exact CIL/signature or structural shape alone remap across declared types or names, never taking a member whose own declared type and name remain unpaired on the other side or whose declaring type is unresolved. Names alone are never a matching basis.",
				"Fields pair by declared type, name, and signature, then remap by exact decoded signature alone under the same rule; an undecoded signature is compared only for an exact signature match, and an unmatched member with one stays unknown."
			];
			const namesTypes = (result) => result.methods.some(({ signature }) => signature.resolved_sha256 !== null && signature.resolved_sha256 !== signature.raw_sha256) || result.fields.some(({ signature }) => signature.resolved_sha256 !== null && signature.resolved_sha256 !== signature.raw_sha256);
			if (hasSignatureResolution(left) && hasSignatureResolution(right) && (namesTypes(left) || namesTypes(right))) limitations.push("Signature type operands compare by namespace, name, and enclosing names only; defining assemblies and CLR type identity are not established by this comparison.");
			if (left.coverage.state !== "complete" || right.coverage.state !== "complete") limitations.push("At least one managed member observation is partial.");
			if (!sameSelection(left, right)) limitations.push("The observations select different declaring types; a member outside the other side's selection is unknown, not added or removed.");
			else if (left.selection !== null) limitations.push(`Both observations cover only the selected declaring types (${left.selection.type_names.join(", ")}); member totals and statuses describe those types, not the whole assembly.`);
			if (!hasSignatureResolution(left) || !hasSignatureResolution(right)) limitations.push("At least one managed member observation does not attest signature type-name resolution, so signatures compare by raw bytes, which name types by build-local metadata row.");
			if (left.nesting_read === null || right.nesting_read === null) limitations.push("At least one managed member observation predates enclosing-name identity. The legacy bare-name comparison does not establish the enclosing owner of a nested type.");
			if (left.exported_types === null || right.exported_types === null) limitations.push("At least one managed member observation predates ExportedType inspection; its exported and forwarded types are unknown.");
			if ((left.exported_types?.length ?? 0) > 0 || (right.exported_types?.length ?? 0) > 0) limitations.push("ExportedType rows, including type forwarders, are observed but not compared; an unchanged comparison does not establish an unchanged exported or forwarded type set.");
			limitations.push("ldstr literals are not compared; normalized CIL keeps #US tokens rather than decoded text, so an unchanged method does not establish unchanged string literals.");
			return limitations;
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedMemberComparisonMatch.js
var sha256$1, keyMethod, keyField, matchMethods, matchFields, identityOf, declaredAs, matchByKeys, unresolvedSignatureAmbiguities, unpairedOf, competitionIdentityKey, ownerlessContested, remappable, declaredCandidates, groupBy, observedBy, matchObserved, keyMembers, parseManagedMemberEvidence;
function init_managedMemberComparisonMatch() {
	return (init_managedMemberComparisonMatch = __esmMin((() => {
		init_managedArtifact();
		init_managedInspectionEvidence();
		init_managedMemberSignatureIdentity();
		sha256$1 = (value) => {
			const serialized = canonicalize(value);
			if (serialized === undefined) throw new TypeError("Managed comparison canonicalization failed");
			return createHash("sha256").update(serialized).digest("hex");
		};
		keyMethod = (item, declared) => ({
			item,
			identity: identityOf({
				declaring_type: declared(item),
				name: item.name
			}),
			identityUnavailable: declared(item) === null,
			signatureId: signatureIdentity(item.signature),
			exactKey: item.body.status === "present" && item.body.il_sha256 !== null && item.body.normalized_il_sha256 !== null ? sha256$1([
				"method-exact",
				signatureIdentity(item.signature),
				item.body.il_sha256,
				item.body.normalized_il_sha256
			]) : null,
			signatureKey: declared(item) === null ? null : sha256$1([
				"method-signature",
				declared(item),
				item.name,
				signatureIdentity(item.signature)
			]),
			structuralKey: item.signature.parse_status === "decoded" && item.body.status === "present" ? sha256$1([
				"method-structural",
				signatureIdentity(item.signature),
				item.body.status,
				item.body.header_format,
				item.body.il_size,
				item.body.max_stack,
				item.body.init_locals,
				item.body.opcode_counts,
				item.body.anchors.map(({ opcode, operand_kind, operand }) => [
					opcode,
					operand_kind,
					operand_kind === "constant" ? operand : null
				]),
				item.body.exception_regions.map((region) => [
					region.flags,
					region.try_length,
					region.handler_length,
					region.class_token === null ? null : "type-token",
					region.filter_offset === null ? null : "filter"
				])
			]) : null
		});
		keyField = (item, declared) => ({
			item,
			identity: identityOf({
				declaring_type: declared(item),
				name: item.name
			}),
			identityUnavailable: declared(item) === null,
			signatureId: signatureIdentity(item.signature),
			exactKey: item.signature.parse_status === "decoded" ? sha256$1(["field-exact", signatureIdentity(item.signature)]) : null,
			signatureKey: declared(item) === null ? null : sha256$1([
				"field-signature",
				declared(item),
				item.name,
				signatureIdentity(item.signature)
			]),
			structuralKey: sha256$1([
				"field-structural",
				item.signature.kind,
				item.signature.field_type,
				item.flags
			])
		});
		matchMethods = (left, right) => matchByKeys({
			left,
			right,
			rounds: [
				{
					basis: "exact-il-signature",
					key: declaredAs(({ exactKey }) => exactKey)
				},
				{
					basis: "exact-signature",
					key: ({ signatureKey }) => signatureKey,
					competitionKey: ({ signatureId }) => signatureId
				},
				{
					basis: "structural-method-shape",
					key: declaredAs((keyed) => keyed.identityUnavailable ? null : keyed.structuralKey),
					competitionKey: ({ structuralKey }) => structuralKey
				},
				{
					basis: "exact-il-signature",
					key: ({ exactKey }) => exactKey,
					remap: true
				},
				{
					basis: "structural-method-shape",
					key: ({ structuralKey }) => structuralKey,
					competitionKey: ({ structuralKey }) => structuralKey,
					remap: true
				}
			]
		});
		matchFields = (left, right) => matchByKeys({
			left,
			right,
			rounds: [
				{
					basis: "field-signature",
					key: declaredAs(({ exactKey }) => exactKey)
				},
				{
					basis: "exact-signature",
					key: ({ signatureKey }) => signatureKey,
					competitionKey: ({ signatureId }) => signatureId
				},
				{
					basis: "field-signature",
					key: ({ exactKey }) => exactKey,
					remap: true
				}
			]
		});
		identityOf = ({ declaring_type, name }) => sha256$1([declaring_type, name]);
		declaredAs = (key) => (item) => {
			const value = key(item);
			return value === null || item.identityUnavailable ? null : sha256$1([item.identity, value]);
		};
		matchByKeys = ({ left, right, rounds }) => {
			const usedLeft = new Set();
			const usedRight = new Set();
			const pairedLeft = new Set();
			const pairedRight = new Set();
			const pairs = [];
			const ambiguous = [];
			for (const round of rounds) {
				const competitionKey = round.competitionKey ?? ((item) => item.exactKey);
				const unpairedLeft = unpairedOf(left, pairedLeft);
				const unpairedRight = unpairedOf(right, pairedRight);
				const declarable = declaredCandidates(unpairedLeft, unpairedRight, competitionKey);
				const openLeft = left.filter((item) => !usedLeft.has(item));
				const openRight = right.filter((item) => !usedRight.has(item));
				const remapContested = round.remap === true ? ownerlessContested([openLeft, openRight], competitionKey) : new Set();
				const leftGroups = groupBy(round.remap === true ? remappable(openLeft, unpairedRight, competitionKey, remapContested) : openLeft.filter(declarable), round.key);
				const rightGroups = groupBy(round.remap === true ? remappable(openRight, unpairedLeft, competitionKey, remapContested) : openRight.filter(declarable), round.key);
				for (const [key, leftItems] of leftGroups) {
					const rightItems = rightGroups.get(key);
					if (rightItems === undefined) continue;
					const refused = round.remap === true && [...leftItems, ...rightItems].some(({ identityUnavailable }) => identityUnavailable);
					if (!refused && leftItems.length === 1 && rightItems.length === 1) {
						const [leftItem] = leftItems;
						const [rightItem] = rightItems;
						if (leftItem === undefined || rightItem === undefined) continue;
						usedLeft.add(leftItem);
						usedRight.add(rightItem);
						pairedLeft.add(leftItem);
						pairedRight.add(rightItem);
						pairs.push({
							left: leftItem,
							right: rightItem,
							basis: round.basis,
							confidence: round.basis === "exact-il-signature" || round.basis === "exact-signature" || round.basis === "field-signature" ? "exact" : "high"
						});
					} else {
						for (const item of leftItems) usedLeft.add(item);
						for (const item of rightItems) usedRight.add(item);
						ambiguous.push({
							left: leftItems,
							right: rightItems,
							basis: round.basis
						});
					}
				}
			}
			for (const group of unresolvedSignatureAmbiguities(left.filter((item) => !usedLeft.has(item)), right.filter((item) => !usedRight.has(item)), ownerlessContested([unpairedOf(left, pairedLeft), unpairedOf(right, pairedRight)], (member) => member.signatureId))) {
				for (const item of group.left) usedLeft.add(item);
				for (const item of group.right) usedRight.add(item);
				ambiguous.push(group);
			}
			return {
				pairs,
				ambiguous,
				leftOnly: left.filter((item) => !usedLeft.has(item)),
				rightOnly: right.filter((item) => !usedRight.has(item))
			};
		};
		unresolvedSignatureAmbiguities = (left, right, contested) => {
			const key = (member) => competitionIdentityKey(member, member.signatureId) ?? "";
			const leftGroups = groupBy(left, key);
			const rightGroups = groupBy(right, key);
			const groups = [];
			for (const [signature, leftItems] of leftGroups) {
				const rightItems = rightGroups.get(signature);
				if (!contested.has(signature) || rightItems === undefined) continue;
				groups.push({
					left: leftItems,
					right: rightItems,
					basis: "exact-signature"
				});
			}
			return groups;
		};
		unpairedOf = (items, paired) => items.filter((item) => !paired.has(item));
		competitionIdentityKey = (member, evidenceKey) => evidenceKey === null ? null : JSON.stringify([member.item.name, evidenceKey]);
		ownerlessContested = (sides, keyOf) => {
			const contested = new Set();
			for (const side of sides) {
				const seen = new Map();
				const ownerless = new Set();
				for (const member of side) {
					const key = competitionIdentityKey(member, keyOf(member));
					if (key === null) continue;
					seen.set(key, (seen.get(key) ?? 0) + 1);
					if (member.identityUnavailable) ownerless.add(key);
				}
				for (const key of ownerless) if ((seen.get(key) ?? 0) > 1) contested.add(key);
			}
			return contested;
		};
		remappable = (items, others, keyOf, contested) => {
			const kept = new Set(others.map(({ identity }) => identity));
			return items.filter((member) => {
				const key = keyOf(member);
				return key !== null && contested.has(competitionIdentityKey(member, key) ?? "") || member.identityUnavailable || !kept.has(member.identity);
			});
		};
		declaredCandidates = (left, right, keyOf) => {
			const contested = ownerlessContested([left, right], keyOf);
			return (member) => {
				if (member.identityUnavailable) return false;
				const key = competitionIdentityKey(member, keyOf(member));
				return key === null || !contested.has(key);
			};
		};
		groupBy = (items, keyOf) => {
			const grouped = new Map();
			for (const item of items) {
				const key = keyOf(item);
				if (key === null) continue;
				const bucket = grouped.get(key) ?? [];
				bucket.push(item);
				grouped.set(key, bucket);
			}
			return grouped;
		};
		observedBy = (side) => ({ declaring_type }) => side.result.selection === null || declaring_type !== null && side.result.selection.type_names.includes(declaring_type);
		matchObserved = (left, right, sides, match, keyLeft, keyRight) => {
			const matched = match(left.filter(sides.inRight).map(keyLeft), right.filter(sides.inLeft).map(keyRight));
			return {
				...matched,
				leftOnly: [...matched.leftOnly, ...left.filter((item) => !sides.inRight(item)).map(keyLeft)],
				rightOnly: [...matched.rightOnly, ...right.filter((item) => !sides.inLeft(item)).map(keyRight)]
			};
		};
		keyMembers = (observedLeft, observedRight) => {
			const [left, right] = comparableSides(observedLeft, observedRight);
			const sides = {
				inLeft: observedBy(left),
				inRight: observedBy(right)
			};
			const modern = left.result.nesting_read !== null && right.result.nesting_read !== null;
			const declared = (inspection) => {
				const names = new Map(inspection.types.map((type) => [type.token, type.name_sha256]));
				return (item) => {
					if (inspection.nesting_read === false) return null;
					const digest = names.get(item.declaring_type_token ?? "");
					if (inspection.nesting_read !== null && digest == null) return null;
					if (!modern) return item.declaring_type;
					return digest == null ? null : ["nominal-name-sha256", digest];
				};
			};
			const declaredLeft = declared(left.result);
			const declaredRight = declared(right.result);
			return {
				methodMatches: matchObserved(left.result.methods, right.result.methods, sides, matchMethods, (item) => keyMethod(item, declaredLeft), (item) => keyMethod(item, declaredRight)),
				fieldMatches: matchObserved(left.result.fields, right.result.fields, sides, matchFields, (item) => keyField(item, declaredLeft), (item) => keyField(item, declaredRight))
			};
		};
		parseManagedMemberEvidence = (evidence) => {
			const parsed = parseManagedInspectionEvidence(evidence, "inspect_managed_members", managedMemberInspectionSchema);
			return {
				evidenceId: parsed.evidence.evidence_id,
				result: parsed.result
			};
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedMemberComparisonItems.js
var inventoryCovers, methodDimensions, callShape, fieldShape, methodIdentity, fieldIdentity, unmatchedComparison, methodOnlyItem, absenceLimitations, unresolved, pairedSignatureLimitations, undecodedOneSidedNames, fieldOnlyItem, ambiguityLimitation, buildMethodItems, buildFieldItems;
function init_managedMemberComparisonItems() {
	return (init_managedMemberComparisonItems = __esmMin((() => {
		init_managedMemberComparisonMatch();
		init_managedMemberSignatureIdentity();
		inventoryCovers = (complete, selection, member) => complete && (selection === null || member.declaring_type !== null && selection.has(member.declaring_type));
		methodDimensions = (left, right) => {
			const dimensions = [];
			if (left.flags !== right.flags || left.impl_flags !== right.impl_flags) dimensions.push("metadata");
			if (signatureIdentity(left.signature) !== signatureIdentity(right.signature)) dimensions.push("signature");
			const leftBodyComplete = left.body.status === "present" && left.body.truncated_instructions === 0;
			const rightBodyComplete = right.body.status === "present" && right.body.truncated_instructions === 0;
			const bothAbsent = left.body.status === "absent" && right.body.status === "absent";
			if (left.body.status === "absent" && rightBodyComplete || right.body.status === "absent" && leftBodyComplete) dimensions.push("availability");
			if (bothAbsent) return {
				dimensions,
				bodyUnknown: false
			};
			if (!leftBodyComplete || !rightBodyComplete) return {
				dimensions,
				bodyUnknown: true
			};
			if (left.body.il_sha256 !== right.body.il_sha256 || left.body.normalized_il_sha256 !== right.body.normalized_il_sha256) dimensions.push("cil");
			if (canonicalize(left.body.opcode_counts) !== canonicalize(right.body.opcode_counts)) dimensions.push("opcode-shape");
			if (callShape(left.body.anchors) !== callShape(right.body.anchors)) dimensions.push("call-shape");
			if (fieldShape(left.body.anchors) !== fieldShape(right.body.anchors)) dimensions.push("field-shape");
			if (canonicalize(left.body.exception_regions) !== canonicalize(right.body.exception_regions)) dimensions.push("exception-shape");
			return {
				dimensions,
				bodyUnknown: false
			};
		};
		callShape = (anchors) => JSON.stringify(anchors.filter(({ operand_kind }) => operand_kind === "method").map(({ opcode, operand_kind }) => [opcode, operand_kind]));
		fieldShape = (anchors) => JSON.stringify(anchors.filter(({ operand_kind }) => operand_kind === "field").map(({ opcode, operand_kind }) => [opcode, operand_kind]));
		methodIdentity = (item) => ({
			token: item.token,
			declaring_type: item.declaring_type,
			name: item.name,
			signature_sha256: item.signature.raw_sha256,
			normalized_il_sha256: item.body.normalized_il_sha256
		});
		fieldIdentity = (item) => ({
			token: item.token,
			declaring_type: item.declaring_type,
			name: item.name,
			signature_sha256: item.signature.raw_sha256
		});
		unmatchedComparison = () => ({
			status: "unmatched",
			basis: "none",
			confidence: "unknown",
			candidate_left_tokens: [],
			candidate_right_tokens: []
		});
		methodOnlyItem = (member, identity, identityUnavailable, context, undecoded) => {
			if (member.left !== undefined) {
				const limitations = absenceLimitations(member.left, identity, {
					oppositeComplete: inventoryCovers(context.rightComplete, context.rightSelection, member.left),
					unpaired: undecoded,
					ownIdentityUnavailable: identityUnavailable,
					opposite: "right",
					inventory: "method"
				});
				return {
					item_id: `mmc_method_${sha256$1({
						token: member.left.token,
						side: "left"
					})}`,
					status: limitations.length === 0 ? "removed" : "unknown",
					left: methodIdentity(member.left),
					right: null,
					match: unmatchedComparison(),
					dimensions: ["availability"],
					evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
					limitations
				};
			}
			const limitations = absenceLimitations(member.right, identity, {
				oppositeComplete: inventoryCovers(context.leftComplete, context.leftSelection, member.right),
				unpaired: undecoded,
				ownIdentityUnavailable: identityUnavailable,
				opposite: "left",
				inventory: "method"
			});
			return {
				item_id: `mmc_method_${sha256$1({
					token: member.right.token,
					side: "right"
				})}`,
				status: limitations.length === 0 ? "added" : "unknown",
				left: null,
				right: methodIdentity(member.right),
				match: unmatchedComparison(),
				dimensions: ["availability"],
				evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
				limitations
			};
		};
		absenceLimitations = (member, identity, opposite) => [
			...opposite.ownIdentityUnavailable ? ["declaring-type-name-not-resolved: Declared type identity could not be resolved; a bare display name cannot establish a counterpart or absence."] : [],
			...opposite.unpaired.unknownOwners[opposite.opposite].has(member.name) ? [`counterpart-declaring-type-name-not-resolved: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired same-named member with unresolved enclosing-name identity, so absence was not established.`] : [],
			...opposite.oppositeComplete ? [] : [`unknown-within-incomplete-metadata: The ${opposite.opposite} ${opposite.inventory} inventory is incomplete, so absence was not observed.`],
			...member.signature.parse_status === "decoded" ? [] : [`signature-not-decoded: The member's ${member.signature.parse_status} signature was compared only by exact declared type, name, and signature bytes, so a changed or renamed counterpart could not be sought.`],
			...member.signature.parse_status === "decoded" && opposite.unpaired.undecoded[opposite.opposite].has(identity) ? [`counterpart-signature-not-decoded: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired member with the same declared type and name whose signature was not decoded, so it may be this member with a changed signature.`] : [],
			...unresolved(member, opposite.unpaired.resolved) ? [`signature-not-resolved: The member's signature names a type REA could not name, so it was compared by raw bytes, which name types by build-local metadata row; a counterpart whose referenced type moved rows could not be found.`] : [],
			...member.signature.parse_status === "decoded" && !unresolved(member, opposite.unpaired.resolved) && opposite.unpaired.unresolved[opposite.opposite].has(identity) ? [`counterpart-signature-not-resolved: The ${opposite.opposite} ${opposite.inventory} inventory has an unpaired member with the same declared type and name whose signature names a type REA could not name, so it may be this member.`] : []
		];
		unresolved = (member, resolved) => resolved && member.signature.kind !== "unknown" && member.signature.resolved_sha256 === null;
		pairedSignatureLimitations = (left, right, examined) => unresolved(left, examined) || unresolved(right, examined) ? ["signature-not-resolved: At least one signature names a type REA could not resolve; equal build-local row bytes do not establish equivalent signature types."] : [];
		undecodedOneSidedNames = (members, resolved) => {
			const sides = {
				left: [...members.leftOnly, ...members.ambiguous.flatMap(({ left }) => left)],
				right: [...members.rightOnly, ...members.ambiguous.flatMap(({ right }) => right)]
			};
			const names = (side, keep) => new Set(side.filter(({ item }) => keep(item)).map(({ identity }) => identity));
			const undecoded = (item) => item.signature.parse_status !== "decoded";
			const notResolved = (item) => unresolved(item, resolved);
			return {
				resolved,
				unknownOwners: {
					left: new Set(sides.left.filter((x) => x.identityUnavailable).map((x) => x.item.name)),
					right: new Set(sides.right.filter((x) => x.identityUnavailable).map((x) => x.item.name))
				},
				undecoded: {
					left: names(sides.left, undecoded),
					right: names(sides.right, undecoded)
				},
				unresolved: {
					left: names(sides.left, notResolved),
					right: names(sides.right, notResolved)
				}
			};
		};
		fieldOnlyItem = (member, identity, identityUnavailable, context, undecoded) => {
			if (member.left !== undefined) {
				const limitations = absenceLimitations(member.left, identity, {
					oppositeComplete: inventoryCovers(context.rightComplete, context.rightSelection, member.left),
					unpaired: undecoded,
					ownIdentityUnavailable: identityUnavailable,
					opposite: "right",
					inventory: "field"
				});
				return {
					item_id: `mmc_field_${sha256$1({
						token: member.left.token,
						side: "left"
					})}`,
					status: limitations.length === 0 ? "removed" : "unknown",
					left: fieldIdentity(member.left),
					right: null,
					match: unmatchedComparison(),
					evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
					limitations
				};
			}
			const limitations = absenceLimitations(member.right, identity, {
				oppositeComplete: inventoryCovers(context.leftComplete, context.leftSelection, member.right),
				unpaired: undecoded,
				ownIdentityUnavailable: identityUnavailable,
				opposite: "left",
				inventory: "field"
			});
			return {
				item_id: `mmc_field_${sha256$1({
					token: member.right.token,
					side: "right"
				})}`,
				status: limitations.length === 0 ? "added" : "unknown",
				left: null,
				right: fieldIdentity(member.right),
				match: unmatchedComparison(),
				evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
				limitations
			};
		};
		ambiguityLimitation = (members, basis, identityUnavailable) => identityUnavailable ? "declaring-type-name-not-resolved: Declared type identity remains unresolved; REA did not guess a counterpart from display names, signatures or CIL." : basis === "exact-signature" ? `Multiple managed ${members} share the same signature; REA did not guess declared ownership or a token remap.` : basis === "exact-il-signature" ? "Multiple managed methods share the same CIL and signature; REA did not guess a token remap." : members === "methods" ? "Multiple managed methods share the same structural shape; REA did not guess a token remap." : "Multiple managed fields share the same signature; REA did not guess a token remap.";
		buildMethodItems = (matches, context) => {
			const items = [];
			for (const pair of matches.pairs) {
				const signatureLimitations = pairedSignatureLimitations(pair.left.item, pair.right.item, context.signatureResolutionExamined);
				const { dimensions: observedDimensions, bodyUnknown } = methodDimensions(pair.left.item, pair.right.item);
				const dimensions = bodyUnknown ? [...observedDimensions, "body-coverage"] : observedDimensions;
				const observedChange = observedDimensions.length > 0;
				items.push({
					item_id: `mmc_method_${sha256$1({
						left: pair.left.item.token,
						right: pair.right.item.token,
						basis: pair.basis
					})}`,
					status: observedChange ? "changed" : bodyUnknown || signatureLimitations.length > 0 ? "unknown" : "unchanged",
					left: methodIdentity(pair.left.item),
					right: methodIdentity(pair.right.item),
					match: {
						status: "matched",
						basis: pair.basis,
						confidence: pair.confidence,
						candidate_left_tokens: [],
						candidate_right_tokens: []
					},
					dimensions,
					evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
					limitations: [...signatureLimitations, ...bodyUnknown ? ["Method body facets are unknown because at least one side has unavailable or partial body data."] : []]
				});
			}
			for (const ambiguous of matches.ambiguous) {
				items.push({
					item_id: `mmc_method_${sha256$1({
						left: ambiguous.left.map(({ item }) => item.token),
						right: ambiguous.right.map(({ item }) => item.token),
						basis: ambiguous.basis
					})}`,
					status: "unknown",
					left: null,
					right: null,
					match: {
						status: "ambiguous",
						basis: ambiguous.basis,
						confidence: "unknown",
						candidate_left_tokens: ambiguous.left.map(({ item }) => item.token),
						candidate_right_tokens: ambiguous.right.map(({ item }) => item.token)
					},
					dimensions: ["availability"],
					evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
					limitations: [ambiguityLimitation("methods", ambiguous.basis, ambiguous.left.some((item) => item.identityUnavailable) || ambiguous.right.some((item) => item.identityUnavailable))]
				});
			}
			const undecoded = undecodedOneSidedNames(matches, context.signatureResolutionExamined);
			for (const item of matches.leftOnly) items.push(methodOnlyItem({ left: item.item }, item.identity, item.identityUnavailable, context, undecoded));
			for (const item of matches.rightOnly) items.push(methodOnlyItem({ right: item.item }, item.identity, item.identityUnavailable, context, undecoded));
			return items;
		};
		buildFieldItems = (matches, context) => {
			const items = [];
			for (const pair of matches.pairs) {
				const signatureLimitations = pairedSignatureLimitations(pair.left.item, pair.right.item, context.signatureResolutionExamined);
				const changed = signatureIdentity(pair.left.item.signature) !== signatureIdentity(pair.right.item.signature) || pair.left.item.flags !== pair.right.item.flags;
				items.push({
					item_id: `mmc_field_${sha256$1({
						left: pair.left.item.token,
						right: pair.right.item.token
					})}`,
					status: changed ? "changed" : signatureLimitations.length > 0 ? "unknown" : "unchanged",
					left: fieldIdentity(pair.left.item),
					right: fieldIdentity(pair.right.item),
					match: {
						status: "matched",
						basis: pair.basis,
						confidence: pair.confidence,
						candidate_left_tokens: [],
						candidate_right_tokens: []
					},
					evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
					limitations: signatureLimitations
				});
			}
			for (const ambiguous of matches.ambiguous) items.push({
				item_id: `mmc_field_${sha256$1({
					left: ambiguous.left.map(({ item }) => item.token),
					right: ambiguous.right.map(({ item }) => item.token)
				})}`,
				status: "unknown",
				left: null,
				right: null,
				match: {
					status: "ambiguous",
					basis: ambiguous.basis,
					confidence: "unknown",
					candidate_left_tokens: ambiguous.left.map(({ item }) => item.token),
					candidate_right_tokens: ambiguous.right.map(({ item }) => item.token)
				},
				evidence_links: [context.leftEvidenceId, context.rightEvidenceId],
				limitations: [ambiguityLimitation("fields", ambiguous.basis, ambiguous.left.some((item) => item.identityUnavailable) || ambiguous.right.some((item) => item.identityUnavailable))]
			});
			const undecoded = undecodedOneSidedNames(matches, context.signatureResolutionExamined);
			for (const item of matches.leftOnly) items.push(fieldOnlyItem({ left: item.item }, item.identity, item.identityUnavailable, context, undecoded));
			for (const item of matches.rightOnly) items.push(fieldOnlyItem({ right: item.item }, item.identity, item.identityUnavailable, context, undecoded));
			return items;
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedMemberComparison.js
var evidenceIdSchema$8, tokenSchema$2, boundedTextSchema, compareManagedMembersInputSchema, concreteMatchBasisSchema, candidateTokensSchema, matchedComparisonSchema, unmatchedComparisonSchema, ambiguousComparisonSchema, memberIdentitySchema, comparisonItemSchema, comparisonItemContextShape, methodComparisonItemSchema, fieldComparisonItemSchema, managedMemberComparisonResultSchema, selectedTypes, compareManagedMembers;
function init_managedMemberComparison() {
	return (init_managedMemberComparison = __esmMin((() => {
		init_emptyArraySchema();
		init_evidence();
		init_managedArtifact();
		init_managedMemberComparisonCoverage();
		init_managedMemberComparisonItems();
		init_managedMemberComparisonMatch();
		init_managedMemberSignatureIdentity();
		init_digests();
		evidenceIdSchema$8 = prefixedDigestSchema("ev");
		tokenSchema$2 = z.string().regex(/^0x[0-9a-f]{8}$/u);
		boundedTextSchema = z.string().min(1);
		compareManagedMembersInputSchema = z.strictObject({
			left: evidenceSchema,
			right: evidenceSchema
		}).superRefine((input, context) => {
			if (input.left.evidence_id === input.right.evidence_id) context.addIssue({
				code: "custom",
				path: ["right"],
				message: "Managed member Evidence must be distinct"
			});
		});
		concreteMatchBasisSchema = z.enum([
			"exact-il-signature",
			"exact-signature",
			"structural-method-shape",
			"field-signature"
		]);
		candidateTokensSchema = z.array(tokenSchema$2).min(1);
		matchedComparisonSchema = z.strictObject({
			status: z.literal("matched"),
			basis: concreteMatchBasisSchema,
			confidence: z.enum(["exact", "high"]),
			candidate_left_tokens: emptyArraySchema,
			candidate_right_tokens: emptyArraySchema
		});
		unmatchedComparisonSchema = z.strictObject({
			status: z.literal("unmatched"),
			basis: z.literal("none"),
			confidence: z.literal("unknown"),
			candidate_left_tokens: emptyArraySchema,
			candidate_right_tokens: emptyArraySchema
		});
		ambiguousComparisonSchema = z.strictObject({
			status: z.literal("ambiguous"),
			basis: concreteMatchBasisSchema,
			confidence: z.literal("unknown"),
			candidate_left_tokens: candidateTokensSchema,
			candidate_right_tokens: candidateTokensSchema
		});
		memberIdentitySchema = z.strictObject({
			token: tokenSchema$2,
			declaring_type: z.string().nullable(),
			name: z.string(),
			signature_sha256: digestSchema,
			normalized_il_sha256: digestSchema.nullable()
		});
		comparisonItemSchema = (base, identity) => z.union([
			z.strictObject({
				...base,
				status: z.enum([
					"unchanged",
					"changed",
					"unknown"
				]),
				left: identity,
				right: identity,
				match: matchedComparisonSchema
			}),
			z.strictObject({
				...base,
				status: z.enum(["removed", "unknown"]),
				left: identity,
				right: z.null(),
				match: unmatchedComparisonSchema
			}),
			z.strictObject({
				...base,
				status: z.enum(["added", "unknown"]),
				left: z.null(),
				right: identity,
				match: unmatchedComparisonSchema
			}),
			z.strictObject({
				...base,
				status: z.literal("unknown"),
				left: z.null(),
				right: z.null(),
				match: ambiguousComparisonSchema
			})
		]);
		comparisonItemContextShape = {
			evidence_links: z.array(evidenceIdSchema$8).length(2),
			limitations: z.array(boundedTextSchema)
		};
		methodComparisonItemSchema = comparisonItemSchema({
			...comparisonItemContextShape,
			item_id: prefixedDigestSchema("mmc_method"),
			dimensions: z.array(z.enum([
				"metadata",
				"signature",
				"cil",
				"opcode-shape",
				"call-shape",
				"field-shape",
				"exception-shape",
				"availability",
				"body-coverage"
			]))
		}, memberIdentitySchema);
		fieldComparisonItemSchema = comparisonItemSchema({
			...comparisonItemContextShape,
			item_id: prefixedDigestSchema("mmc_field")
		}, memberIdentitySchema.omit({ normalized_il_sha256: true }));
		managedMemberComparisonResultSchema = z.strictObject({
			comparison_id: prefixedDigestSchema("mmc"),
			algorithm: z.strictObject({
				name: z.literal("rea-managed-member-comparison"),
				token_identity: z.literal("build-local"),
				name_matching: z.literal("exact-signature-fallback")
			}),
			left: z.strictObject({
				evidence_id: evidenceIdSchema$8,
				artifact_sha256: digestSchema,
				mvid: cliMetadataGuidSchema.nullable(),
				module_name: z.string().nullable(),
				metadata_status: z.enum([
					"absent",
					"complete",
					"partial",
					"malformed"
				]),
				methods_total: z.number().int().min(0),
				fields_total: z.number().int().min(0)
			}),
			right: z.strictObject({
				evidence_id: evidenceIdSchema$8,
				artifact_sha256: digestSchema,
				mvid: cliMetadataGuidSchema.nullable(),
				module_name: z.string().nullable(),
				metadata_status: z.enum([
					"absent",
					"complete",
					"partial",
					"malformed"
				]),
				methods_total: z.number().int().min(0),
				fields_total: z.number().int().min(0)
			}),
			summary: z.strictObject({
				unchanged: z.number().int().min(0),
				changed: z.number().int().min(0),
				added: z.number().int().min(0),
				removed: z.number().int().min(0),
				unknown: z.number().int().min(0)
			}),
			matching: z.strictObject({
				exact_il_signature: z.number().int().min(0),
				exact_signature: z.number().int().min(0),
				structural_method_shape: z.number().int().min(0),
				field_signature: z.number().int().min(0),
				ambiguous: z.number().int().min(0),
				unmatched: z.number().int().min(0)
			}),
			methods: z.array(methodComparisonItemSchema),
			fields: z.array(fieldComparisonItemSchema),
			coverage: z.strictObject({
				status: z.enum(["complete-within-inputs", "partial"]),
				left_status: z.enum([
					"complete",
					"partial",
					"unavailable"
				]),
				right_status: z.enum([
					"complete",
					"partial",
					"unavailable"
				])
			}),
			evidence_links: z.array(evidenceIdSchema$8).length(2),
			limitations: z.array(boundedTextSchema)
		});
		selectedTypes = (result) => result.selection === null ? null : new Set(result.selection.type_names);
		compareManagedMembers = (left, right) => {
			const { methodMatches, fieldMatches } = keyMembers(left, right);
			const itemContext = {
				leftEvidenceId: left.evidenceId,
				rightEvidenceId: right.evidenceId,
				leftComplete: left.result.metadata.status === "complete",
				rightComplete: right.result.metadata.status === "complete",
				leftSelection: selectedTypes(left.result),
				rightSelection: selectedTypes(right.result),
				signatureResolutionExamined: hasSignatureResolution(left.result) && hasSignatureResolution(right.result)
			};
			const methodItems = buildMethodItems(methodMatches, itemContext);
			const fieldItems = buildFieldItems(fieldMatches, itemContext);
			const allItems = [...methodItems, ...fieldItems];
			const summary = buildComparisonSummary(allItems);
			const matching = buildComparisonMatching(methodItems, fieldItems);
			const coverage = buildComparisonCoverage({
				left: left.result,
				right: right.result
			});
			const limitations = comparisonLimitations(left.result, right.result);
			const result = {
				comparison_id: `mmc_${sha256$1({
					left: left.evidenceId,
					right: right.evidenceId,
					methods: [...methodItems],
					fields: [...fieldItems]
				})}`,
				algorithm: {
					name: "rea-managed-member-comparison",
					token_identity: "build-local",
					name_matching: "exact-signature-fallback"
				},
				left: sideManifest(left),
				right: sideManifest(right),
				summary,
				matching,
				methods: methodItems,
				fields: fieldItems,
				coverage,
				evidence_links: [left.evidenceId, right.evidenceId],
				limitations
			};
			return managedMemberComparisonResultSchema.parse(result);
		};
	})))();
}

//#endregion
//#region dist/domain/managed/managedNativeVerificationSchemas.js
var evidenceIdSchema$7, tokenSchema$1, textSchema$1, nativeSymbolSchema, pinvokeVerificationContextShape, observedCandidatesSchema, pinvokeVerificationSchema, managedNativeVerificationInputSchema, verificationCoverageSchema, managedNativeVerificationResultSchema;
function init_managedNativeVerificationSchemas() {
	return (init_managedNativeVerificationSchemas = __esmMin((() => {
		init_emptyArraySchema();
		init_evidence();
		init_managedArtifact();
		init_digests();
		evidenceIdSchema$7 = prefixedDigestSchema("ev");
		tokenSchema$1 = z.string().regex(/^0x[0-9a-f]{8}$/u);
		textSchema$1 = z.string().min(1);
		nativeSymbolSchema = z.strictObject({
			evidence_id: evidenceIdSchema$7,
			operation: z.string().min(1),
			name: z.string().min(1),
			address: z.string().nullable(),
			module_name: z.string().nullable(),
			module_path: z.string().nullable(),
			source: z.enum(["macho-export", "function-dossier"])
		});
		pinvokeVerificationContextShape = {
			item_id: prefixedDigestSchema("mnv_pinvoke"),
			managed: z.strictObject({
				token: tokenSchema$1,
				member_token: tokenSchema$1.nullable(),
				member_name: z.string().nullable(),
				import_name: z.string().min(1),
				import_scope_name: z.string().nullable(),
				no_mangle: z.boolean(),
				char_set: z.enum([
					"not-specified",
					"ansi",
					"unicode",
					"auto",
					"unknown"
				]),
				call_convention: z.enum([
					"not-specified",
					"winapi",
					"cdecl",
					"stdcall",
					"thiscall",
					"fastcall",
					"unknown"
				]),
				declaration_verification: z.literal("managed-declaration-only")
			}),
			evidence_links: z.array(evidenceIdSchema$7).min(1),
			limitations: z.array(textSchema$1)
		};
		observedCandidatesSchema = z.tuple([nativeSymbolSchema], nativeSymbolSchema).check(z.minLength(1));
		pinvokeVerificationSchema = z.union([
			z.strictObject({
				...pinvokeVerificationContextShape,
				status: z.literal("verified"),
				basis: z.enum(["exact-export-name", "exact-function-name"]),
				confidence: z.literal("observed"),
				matched_native: nativeSymbolSchema,
				candidates: observedCandidatesSchema
			}),
			z.strictObject({
				...pinvokeVerificationContextShape,
				status: z.literal("inferred"),
				basis: z.literal("decorated-name-candidate"),
				confidence: z.literal("inferred"),
				matched_native: nativeSymbolSchema,
				candidates: observedCandidatesSchema
			}),
			z.strictObject({
				...pinvokeVerificationContextShape,
				status: z.literal("unresolved"),
				basis: z.enum(["no-native-candidate", "unsupported-native-evidence"]),
				confidence: z.literal("unknown"),
				matched_native: z.null(),
				candidates: emptyArraySchema
			}),
			z.strictObject({
				...pinvokeVerificationContextShape,
				status: z.literal("unresolved"),
				basis: z.literal("module-identity-unknown"),
				confidence: z.literal("unknown"),
				matched_native: nativeSymbolSchema,
				candidates: observedCandidatesSchema
			}),
			z.strictObject({
				...pinvokeVerificationContextShape,
				status: z.literal("contradicted"),
				basis: z.literal("module-mismatch"),
				confidence: z.literal("unknown"),
				matched_native: nativeSymbolSchema,
				candidates: observedCandidatesSchema
			})
		]);
		managedNativeVerificationInputSchema = z.strictObject({
			managed_boundaries: evidenceSchema,
			native_observations: z.array(evidenceSchema).min(1).describe("Native function or export Evidence records")
		}).superRefine((input, context) => {
			const ids = new Set();
			for (const [index, evidence] of input.native_observations.entries()) {
				if (evidence.evidence_id === input.managed_boundaries.evidence_id) {
					context.addIssue({
						code: "custom",
						path: ["native_observations", index],
						message: "Native observation Evidence must be distinct from managed boundary Evidence"
					});
				}
				if (ids.has(evidence.evidence_id)) {
					context.addIssue({
						code: "custom",
						path: ["native_observations", index],
						message: "Native observation Evidence IDs must be unique"
					});
				}
				ids.add(evidence.evidence_id);
			}
		});
		verificationCoverageSchema = z.strictObject({ status: z.enum(["complete-within-inputs", "partial"]) });
		managedNativeVerificationResultSchema = z.strictObject({
			verification_id: prefixedDigestSchema("mnv"),
			algorithm: z.strictObject({
				name: z.literal("rea-managed-native-verification"),
				token_identity: z.literal("build-local"),
				token_to_address_mapping: z.literal("not-inferred")
			}),
			managed_boundary: z.strictObject({
				evidence_id: evidenceIdSchema$7,
				artifact_sha256: digestSchema,
				artifact_path: z.string().min(1),
				mvid: cliMetadataGuidSchema.nullable(),
				metadata_status: z.enum([
					"absent",
					"complete",
					"partial",
					"malformed"
				]),
				pinvoke_imports_total: z.number().int().min(0),
				native_implementations_total: z.number().int().min(0),
				coverage_state: z.enum([
					"complete",
					"partial",
					"unavailable"
				])
			}),
			native_observations: z.strictObject({
				total: z.number().int().min(1),
				accepted: z.number().int().min(0),
				unsupported: z.number().int().min(0),
				symbols: z.number().int().min(0)
			}),
			summary: z.strictObject({
				verified: z.number().int().min(0),
				inferred: z.number().int().min(0),
				unresolved: z.number().int().min(0),
				contradicted: z.number().int().min(0),
				native_body_unresolved: z.number().int().min(0)
			}),
			pinvoke_imports: z.array(pinvokeVerificationSchema),
			native_implementations: z.strictObject({
				unresolved: z.number().int().min(0),
				reason: textSchema$1
			}),
			coverage: verificationCoverageSchema,
			evidence_links: z.array(evidenceIdSchema$7).min(2),
			limitations: z.array(textSchema$1)
		}).superRefine((result, context) => {
			const observedNativeCount = result.native_observations.accepted + result.native_observations.unsupported;
			if (observedNativeCount !== result.native_observations.total) context.addIssue({
				code: "custom",
				path: ["native_observations"],
				message: "Native observation counts must account for the total input"
			});
			for (const status of [
				"verified",
				"inferred",
				"unresolved",
				"contradicted"
			]) if (result.summary[status] !== result.pinvoke_imports.filter((item) => item.status === status).length) context.addIssue({
				code: "custom",
				path: ["summary", status],
				message: `P/Invoke ${status} count must match the item results`
			});
			if (result.summary.native_body_unresolved !== result.native_implementations.unresolved) context.addIssue({
				code: "custom",
				path: ["summary", "native_body_unresolved"],
				message: "Native body summary must match unresolved implementations"
			});
		}).describe("Counts must agree across the result: native accepted plus unsupported equals total; each P/Invoke summary count equals the number of items with that status; and native_body_unresolved equals native_implementations.unresolved. REA checks these cross-field invariants after constructing the result.");
	})))();
}

//#endregion
//#region dist/domain/managed/managedReconstruction.js
var evidenceIdSchema$6, tokenSchema, textSchema, decompilerSchema, managedReconstructionMethodInputSchema, managedReconstructionImportInputSchema, importedMethodSchema, managedReconstructionImportResultSchema, sha256Text, sha256Json, countLines, findObservedMethod, verifyTextSha256, buildImportedMethod, buildReconstructionSummary, buildStaticObservation, buildDecompilerRecord, RECONSTRUCTION_LIMITATIONS, buildReconstructionWithoutId, importManagedReconstruction;
function init_managedReconstruction() {
	return (init_managedReconstruction = __esmMin((() => {
		init_evidence();
		init_managedArtifact();
		init_digests();
		init_managedInspectionEvidence();
		evidenceIdSchema$6 = prefixedDigestSchema("ev");
		tokenSchema = z.string().regex(/^0x[0-9a-f]{8}$/u);
		textSchema = z.string().min(1);
		decompilerSchema = z.strictObject({
			name: textSchema,
			version: textSchema.nullable().default(null),
			family: z.enum([
				"ilspy",
				"dnspy",
				"dnlib",
				"mono-cecil",
				"other"
			]),
			executable_sha256: digestSchema.nullable().default(null),
			options: z.array(z.string()).default([])
		});
		managedReconstructionMethodInputSchema = z.strictObject({
			token: tokenSchema,
			signature_sha256: digestSchema,
			normalized_il_sha256: digestSchema.nullable(),
			reconstruction: z.strictObject({
				kind: z.enum([
					"decompiled-csharp",
					"decompiled-il",
					"semantic-pseudocode"
				]),
				language: z.enum([
					"csharp",
					"il",
					"pseudocode"
				]),
				text: textSchema,
				text_sha256: digestSchema.optional(),
				source_path: textSchema.nullable().optional(),
				start_line: z.number().int().min(1).nullable().optional(),
				end_line: z.number().int().min(1).nullable().optional()
			})
		});
		managedReconstructionImportInputSchema = z.strictObject({
			static_members: evidenceSchema,
			decompiler: decompilerSchema,
			methods: z.array(managedReconstructionMethodInputSchema).min(1),
			notes: z.array(textSchema).default([])
		});
		importedMethodSchema = z.strictObject({
			token: tokenSchema,
			declaring_type: z.string().nullable(),
			name: z.string(),
			signature_sha256: digestSchema,
			normalized_il_sha256: digestSchema.nullable(),
			body_sha256: digestSchema.nullable(),
			il_size: z.number().int().min(0),
			reconstruction: z.strictObject({
				kind: z.enum([
					"decompiled-csharp",
					"decompiled-il",
					"semantic-pseudocode"
				]),
				language: z.enum([
					"csharp",
					"il",
					"pseudocode"
				]),
				text: textSchema,
				text_sha256: digestSchema,
				text_length: z.number().int().min(1),
				line_count: z.number().int().min(1),
				source_path: textSchema.nullable(),
				start_line: z.number().int().min(1).nullable(),
				end_line: z.number().int().min(1).nullable()
			}),
			validation: z.strictObject({
				matched_static_member: z.literal(true),
				exact_build_required: z.literal(true),
				canonical_observation: z.literal(false),
				confidence_floor: z.literal("inference")
			})
		});
		managedReconstructionImportResultSchema = z.strictObject({
			reconstruction_id: prefixedDigestSchema("mre"),
			phase: z.literal("reconstruction-import"),
			executed: z.literal(false),
			static_observation: z.strictObject({
				evidence_id: evidenceIdSchema$6,
				artifact_sha256: digestSchema,
				artifact_path: z.string().min(1),
				byte_length: z.number().int().min(0),
				module_name: z.string().nullable(),
				mvid: cliMetadataGuidSchema.nullable(),
				metadata_status: z.enum([
					"absent",
					"complete",
					"partial",
					"malformed"
				])
			}),
			decompiler: decompilerSchema.extend({ options_sha256: digestSchema }),
			summary: z.strictObject({
				imported_methods: z.number().int().min(1),
				decompiled_csharp_methods: z.number().int().min(0),
				decompiled_il_methods: z.number().int().min(0),
				pseudocode_methods: z.number().int().min(0),
				total_text_bytes: z.number().int().min(1)
			}),
			methods: z.array(importedMethodSchema).min(1),
			notes: z.array(textSchema),
			evidence_links: z.array(evidenceIdSchema$6).length(1),
			limitations: z.array(textSchema)
		});
		sha256Text = (value) => createHash("sha256").update(value).digest("hex");
		sha256Json = (value) => {
			const serialized = canonicalize(value);
			if (serialized === undefined) throw new TypeError("Managed reconstruction canonicalization failed");
			return createHash("sha256").update(serialized).digest("hex");
		};
		countLines = (text) => text.length === 0 ? 0 : text.split(/\r\n|\r|\n/u).length;
		findObservedMethod = (members, candidate) => members.methods.find((item) => item.token === candidate.token && item.signature.raw_sha256 === candidate.signature_sha256 && item.body.status === "present" && item.body.normalized_il_sha256 !== null && candidate.normalized_il_sha256 !== null && item.body.normalized_il_sha256 === candidate.normalized_il_sha256);
		verifyTextSha256 = (candidate, textSha256) => {
			if (candidate.reconstruction.text_sha256 !== undefined && candidate.reconstruction.text_sha256 !== textSha256) throw new TypeError(`Reconstruction text hash mismatch for ${candidate.token}`);
		};
		buildImportedMethod = (observed, candidate, textSha256) => ({
			token: observed.token,
			declaring_type: observed.declaring_type,
			name: observed.name,
			signature_sha256: observed.signature.raw_sha256,
			normalized_il_sha256: observed.body.normalized_il_sha256,
			body_sha256: observed.body.il_sha256,
			il_size: observed.body.il_size,
			reconstruction: {
				kind: candidate.reconstruction.kind,
				language: candidate.reconstruction.language,
				text: candidate.reconstruction.text,
				text_sha256: textSha256,
				text_length: candidate.reconstruction.text.length,
				line_count: countLines(candidate.reconstruction.text),
				source_path: candidate.reconstruction.source_path ?? null,
				start_line: candidate.reconstruction.start_line ?? null,
				end_line: candidate.reconstruction.end_line ?? null
			},
			validation: {
				matched_static_member: true,
				exact_build_required: true,
				canonical_observation: false,
				confidence_floor: "inference"
			}
		});
		buildReconstructionSummary = (methods) => ({
			imported_methods: methods.length,
			decompiled_csharp_methods: methods.filter(({ reconstruction }) => reconstruction.kind === "decompiled-csharp").length,
			decompiled_il_methods: methods.filter(({ reconstruction }) => reconstruction.kind === "decompiled-il").length,
			pseudocode_methods: methods.filter(({ reconstruction }) => reconstruction.kind === "semantic-pseudocode").length,
			total_text_bytes: methods.reduce((total, { reconstruction }) => total + Buffer.byteLength(reconstruction.text, "utf8"), 0)
		});
		buildStaticObservation = (staticEvidence, members) => ({
			evidence_id: staticEvidence.evidence_id,
			artifact_sha256: members.artifact.sha256,
			artifact_path: members.artifact.path,
			byte_length: members.artifact.byte_length,
			module_name: members.module?.name ?? null,
			mvid: members.module?.mvid ?? null,
			metadata_status: members.metadata.status
		});
		buildDecompilerRecord = (decompiler) => ({
			...decompiler,
			options_sha256: sha256Json(decompiler.options)
		});
		RECONSTRUCTION_LIMITATIONS = [
			"Decompiler output is imported as reconstruction evidence and analyst inference; metadata and IL observations remain canonical.",
			"This operation did not execute, load, reflect over, debug, instrument, patch, or decompile the target artifact.",
			"The imported reconstruction is valid only for the exact artifact SHA-256, MVID, method signature, and normalized IL shape recorded here.",
			"Obfuscated names, decompiler variables, and control-flow restructuring are not treated as proof without separate validation."
		];
		buildReconstructionWithoutId = (input, staticEvidence, members, methods) => ({
			phase: "reconstruction-import",
			executed: false,
			static_observation: buildStaticObservation(staticEvidence, members),
			decompiler: buildDecompilerRecord(input.decompiler),
			summary: buildReconstructionSummary(methods),
			methods: [...methods],
			notes: input.notes,
			evidence_links: [staticEvidence.evidence_id],
			limitations: RECONSTRUCTION_LIMITATIONS
		});
		importManagedReconstruction = (input) => {
			const { evidence: staticEvidence, result: members } = parseManagedInspectionEvidence(input.static_members, "inspect_managed_members", managedMemberInspectionSchema);
			const methods = input.methods.map((candidate) => {
				const observed = findObservedMethod(members, candidate);
				if (observed === undefined) throw new TypeError(`Reconstruction method lock ${candidate.token} does not match a static managed member observation`);
				const textSha256 = sha256Text(candidate.reconstruction.text);
				verifyTextSha256(candidate, textSha256);
				return buildImportedMethod(observed, candidate, textSha256);
			});
			const withoutId = buildReconstructionWithoutId(input, staticEvidence, members, methods);
			return managedReconstructionImportResultSchema.parse({
				...withoutId,
				reconstruction_id: `mre_${sha256Json(withoutId)}`
			});
		};
	})))();
}

//#endregion
//#region dist/domain/artifactComparison.js
var evidenceIdSchema$5, comparisonStatusSchema, changeKindSchema, comparisonDimensionSchema, artifactComparisonInputSchema, artifactChangeSchema, artifactComparisonResultSchema, compareArtifacts, compareOccurrences, occurrencesByPath, buildArtifactChangeBase, classifyPresence, classifyIntegrity, classifyAvailability, classifyPath, changedDimensions, metadataChanged, nodeFor, relationsByPath, summarize, applyRootHashChange;
function init_artifactComparison() {
	return (init_artifactComparison = __esmMin((() => {
		init_unicodeCodePointOrder();
		init_evidence();
		init_artifactInventoryEvidence();
		init_digests();
		init_comparisonSemantics();
		evidenceIdSchema$5 = prefixedDigestSchema("ev");
		comparisonStatusSchema = z.enum([
			"unchanged",
			"added",
			"removed",
			"changed",
			"truncated",
			"unknown",
			"contradiction"
		]);
		changeKindSchema = z.enum([
			"added",
			"removed",
			"changed",
			"unknown",
			"contradiction"
		]);
		comparisonDimensionSchema = z.enum([
			"content",
			"kind",
			"format",
			"size",
			"executable",
			"relations",
			"metadata",
			"availability",
			"integrity"
		]);
		artifactComparisonInputSchema = z.strictObject({
			left: evidenceSchema,
			right: evidenceSchema
		});
		artifactChangeSchema = z.object({
			classification: changeKindSchema,
			logical_path: z.string().min(1),
			dimensions: z.array(comparisonDimensionSchema).min(1),
			left_occurrence_id: z.string().regex(/^occ_[a-f0-9]{64}$/u).nullable(),
			right_occurrence_id: z.string().regex(/^occ_[a-f0-9]{64}$/u).nullable(),
			left_artifact_id: z.string().regex(/^art_[a-f0-9]{64}$/u).nullable(),
			right_artifact_id: z.string().regex(/^art_[a-f0-9]{64}$/u).nullable(),
			evidence_links: z.array(evidenceIdSchema$5).min(2)
		});
		artifactComparisonResultSchema = z.object({
			status: comparisonStatusSchema,
			left_manifest_id: prefixedDigestSchema("agm"),
			right_manifest_id: prefixedDigestSchema("agm"),
			summary: z.object({
				unchanged: z.number().int().min(0),
				added: z.number().int().min(0),
				removed: z.number().int().min(0),
				changed: z.number().int().min(0),
				unknown: z.number().int().min(0),
				contradiction: z.number().int().min(0).default(0)
			}),
			changes: z.array(artifactChangeSchema),
			limitations: z.array(z.string())
		});
		compareArtifacts = (leftEvidence, rightEvidence) => {
			const left = parseArtifactInventoryEvidence(leftEvidence);
			const right = parseArtifactInventoryEvidence(rightEvidence);
			const leftComplete = left.inventory.complete;
			const rightComplete = right.inventory.complete;
			const sameScope = left.inventory.coverage.scope === right.inventory.coverage.scope;
			const rootCoverageComplete = sameScope && left.inventory.complete && right.inventory.complete && left.inventory.coverage.status === "complete" && right.inventory.coverage.status === "complete";
			const entryCoverageComplete = rootCoverageComplete && left.inventory.coverage.scope === "container-entries";
			const leftCovered = sameScope && hasCompleteInventoryCoverage(left.inventory, left.inventory.coverage.scope);
			const rightCovered = sameScope && hasCompleteInventoryCoverage(right.inventory, right.inventory.coverage.scope);
			const fullyCovered = leftCovered && rightCovered && (entryCoverageComplete || rootCoverageComplete && left.inventory.manifest.occurrence_count === 1 && right.inventory.manifest.occurrence_count === 1);
			const leftOccurrencesByPath = occurrencesByPath(left.inventory.occurrences);
			const rightOccurrencesByPath = occurrencesByPath(right.inventory.occurrences);
			const comparison = compareOccurrences(left.inventory, right.inventory, leftOccurrencesByPath, rightOccurrencesByPath, [...left.evidence.map(({ evidence_id: id }) => id), ...right.evidence.map(({ evidence_id: id }) => id)], {
				root: rootCoverageComplete,
				entries: entryCoverageComplete
			});
			const changes = comparison.changes;
			const limitations = [
				...left.inventory.limitations.map((item) => `Left: ${item}`),
				...right.inventory.limitations.map((item) => `Right: ${item}`),
				...leftComplete ? [] : ["Left artifact inventory is incomplete."],
				...rightComplete ? [] : ["Right artifact inventory is incomplete."],
				...sameScope ? [] : ["Artifact inventory scopes differ."],
				...sameScope && left.inventory.coverage.scope === "root" && (left.inventory.manifest.occurrence_count > 1 || right.inventory.manifest.occurrence_count > 1) ? ["Container entry coverage is unavailable for child paths."] : [],
				...left.inventory.coverage.status === "complete" ? [] : ["Left artifact inventory traversal coverage is unknown."],
				...right.inventory.coverage.status === "complete" ? [] : ["Right artifact inventory traversal coverage is unknown."],
				...comparison.hasAmbiguousDuplicatePaths ? ["Duplicate logical paths cannot be paired across inventories; comparisons for those paths are unknown."] : []
			];
			applyRootHashChange(left.inventory, right.inventory, changes, [...left.evidence.map(({ evidence_id: id }) => id), ...right.evidence.map(({ evidence_id: id }) => id)]);
			const summary = summarize(left.inventory, right.inventory, changes, fullyCovered);
			return artifactComparisonResultSchema.parse({
				status: !leftComplete || !rightComplete ? "truncated" : changes.some(({ classification }) => classification === "contradiction") ? "contradiction" : !fullyCovered ? "unknown" : changes.some(({ classification }) => classification === "unknown") ? "unknown" : changes.length === 0 ? "unchanged" : "changed",
				left_manifest_id: left.inventory.manifest.manifest_id,
				right_manifest_id: right.inventory.manifest.manifest_id,
				summary,
				changes,
				limitations: [...new Set(limitations)].sort(compareUnicodeCodePoints)
			});
		};
		compareOccurrences = (left, right, leftByPath, rightByPath, evidenceLinks, coverage) => {
			const leftNodes = new Map(left.nodes.map((item) => [item.artifact_id, item]));
			const rightNodes = new Map(right.nodes.map((item) => [item.artifact_id, item]));
			const leftRelations = relationsByPath(left);
			const rightRelations = relationsByPath(right);
			const paths = [...new Set([...leftByPath.keys(), ...rightByPath.keys()])].sort(compareUnicodeCodePoints);
			const output = [];
			let hasAmbiguousDuplicatePaths = false;
			for (const path of paths) {
				const leftMatches = leftByPath.get(path) ?? [];
				const rightMatches = rightByPath.get(path) ?? [];
				if (leftMatches.length > 1 || rightMatches.length > 1) {
					hasAmbiguousDuplicatePaths = true;
					output.push({
						logical_path: path,
						classification: "unknown",
						dimensions: ["availability"],
						left_occurrence_id: null,
						right_occurrence_id: null,
						left_artifact_id: null,
						right_artifact_id: null,
						evidence_links: [...evidenceLinks]
					});
					continue;
				}
				const leftOccurrence = leftMatches[0];
				const rightOccurrence = rightMatches[0];
				const change = classifyPath({
					path,
					leftOccurrence,
					rightOccurrence,
					leftNode: nodeFor(leftOccurrence, leftNodes),
					rightNode: nodeFor(rightOccurrence, rightNodes),
					leftRelations: leftRelations.get(path) ?? [],
					rightRelations: rightRelations.get(path) ?? [],
					rootCovered: coverage.root,
					entriesCovered: coverage.entries,
					evidenceLinks
				});
				if (change !== null) output.push(change);
			}
			return {
				changes: output,
				hasAmbiguousDuplicatePaths
			};
		};
		occurrencesByPath = (occurrences) => {
			const output = new Map();
			for (const occurrence of occurrences) {
				const matches = output.get(occurrence.logical_path);
				if (matches === undefined) output.set(occurrence.logical_path, [occurrence]);
				else matches.push(occurrence);
			}
			return output;
		};
		buildArtifactChangeBase = (input) => ({
			logical_path: input.path,
			left_occurrence_id: input.leftOccurrence?.occurrence_id ?? null,
			right_occurrence_id: input.rightOccurrence?.occurrence_id ?? null,
			left_artifact_id: input.leftOccurrence?.artifact_id ?? null,
			right_artifact_id: input.rightOccurrence?.artifact_id ?? null,
			evidence_links: [...input.evidenceLinks]
		});
		classifyPresence = (input) => {
			const covered = input.path === "." ? input.rootCovered : input.entriesCovered;
			if (input.leftOccurrence === undefined) return {
				...buildArtifactChangeBase(input),
				classification: covered ? "added" : "unknown",
				dimensions: [covered ? "content" : "availability"]
			};
			if (input.rightOccurrence === undefined) return {
				...buildArtifactChangeBase(input),
				classification: covered ? "removed" : "unknown",
				dimensions: [covered ? "content" : "availability"]
			};
			return null;
		};
		classifyIntegrity = (input, base) => {
			if (input.leftOccurrence?.hash_status === "mismatched" || input.rightOccurrence?.hash_status === "mismatched") return {
				...base,
				classification: "contradiction",
				dimensions: ["integrity"]
			};
			return null;
		};
		classifyAvailability = (input, base) => {
			if (input.leftOccurrence?.hash_status !== "verified" || input.rightOccurrence?.hash_status !== "verified" || input.leftNode === undefined || input.rightNode === undefined) return {
				...base,
				classification: "unknown",
				dimensions: ["availability"]
			};
			return null;
		};
		classifyPath = (input) => {
			const presence = classifyPresence(input);
			if (presence !== null) return presence;
			const base = buildArtifactChangeBase(input);
			const integrity = classifyIntegrity(input, base);
			if (integrity !== null) return integrity;
			const availability = classifyAvailability(input, base);
			if (availability !== null) return availability;
			const dimensions = changedDimensions(input);
			return dimensions.length === 0 ? null : {
				...base,
				classification: "changed",
				dimensions
			};
		};
		changedDimensions = (input) => {
			const left = input.leftNode;
			const right = input.rightNode;
			if (left === undefined || right === undefined) return ["availability"];
			const checks = [
				["content", left.sha256 !== right.sha256],
				["kind", input.leftOccurrence?.artifact_kind !== input.rightOccurrence?.artifact_kind],
				["format", left.format !== right.format || input.leftOccurrence?.artifact_format !== input.rightOccurrence?.artifact_format],
				["size", left.size !== right.size],
				["executable", input.leftOccurrence?.executable !== input.rightOccurrence?.executable],
				["relations", JSON.stringify(input.leftRelations) !== JSON.stringify(input.rightRelations)],
				["metadata", metadataChanged(input, left, right)]
			];
			return checks.filter(([, changed]) => changed).map(([dimension]) => dimension);
		};
		metadataChanged = (input, left, right) => left.media_type !== right.media_type || left.architecture !== right.architecture || left.content_state !== right.content_state || input.leftOccurrence?.entry_kind !== input.rightOccurrence?.entry_kind || input.leftOccurrence?.encrypted !== input.rightOccurrence?.encrypted || JSON.stringify(left.limitations) !== JSON.stringify(right.limitations) || JSON.stringify(input.leftOccurrence?.limitations) !== JSON.stringify(input.rightOccurrence?.limitations);
		nodeFor = (occurrence, nodes) => occurrence?.artifact_id === null || occurrence?.artifact_id === undefined ? undefined : nodes.get(occurrence.artifact_id);
		relationsByPath = (inventory) => {
			const output = new Map();
			const occurrences = new Map(inventory.occurrences.map((item) => [item.occurrence_id, item]));
			for (const edge of inventory.edges) {
				const occurrence = occurrences.get(edge.occurrence_id);
				if (occurrence?.artifact_id === null || occurrence === undefined) continue;
				const path = occurrence.logical_path;
				const values = output.get(path);
				const projection = {
					parent_logical_path: occurrence.parent_occurrence_id === null ? null : occurrences.get(occurrence.parent_occurrence_id)?.logical_path ?? null,
					child_artifact_id: occurrence.artifact_id,
					relation: edge.relation,
					logical_path: occurrence.logical_path,
					producer: edge.producer
				};
				if (values === undefined) output.set(path, [projection]);
				else values.push(projection);
			}
			for (const values of output.values()) values.sort((left, right) => compareUnicodeCodePoints(canonicalJson$1(left), canonicalJson$1(right)));
			return output;
		};
		summarize = (left, right, changes, covered) => {
			const counts = {
				added: 0,
				removed: 0,
				changed: 0,
				unknown: 0,
				contradiction: 0
			};
			for (const change of changes) counts[change.classification] += 1;
			const changedPaths = new Set(changes.filter(({ classification }) => classification !== "added").map(({ logical_path: path }) => path));
			return {
				unchanged: covered ? left.occurrences.filter(({ logical_path: path }) => !changedPaths.has(path)).length : 0,
				...counts,
				unknown: covered ? counts.unknown : Math.max(counts.unknown, Math.max(left.manifest.occurrence_count, right.manifest.occurrence_count) - counts.added - counts.removed - counts.changed - counts.contradiction)
			};
		};
		applyRootHashChange = (left, right, changes, evidenceLinks) => {
			if (left.manifest.root_sha256 === right.manifest.root_sha256) return;
			const index = changes.findIndex((change) => change.logical_path === ".");
			const existing = changes[index];
			if (existing !== undefined) {
				if (existing.dimensions.includes("content") || existing.classification !== "unknown" && existing.classification !== "changed") return;
				changes[index] = {
					...existing,
					classification: "changed",
					dimensions: comparisonDimensionSchema.options.filter((dimension) => dimension === "content" || existing.dimensions.includes(dimension)),
					evidence_links: [...new Set([...existing.evidence_links, ...evidenceLinks])]
				};
				return;
			}
			const leftRoot = left.occurrences.find((occurrence) => occurrence.logical_path === ".");
			const rightRoot = right.occurrences.find((occurrence) => occurrence.logical_path === ".");
			changes.push({
				classification: "changed",
				logical_path: ".",
				dimensions: ["content"],
				left_occurrence_id: leftRoot?.occurrence_id ?? null,
				right_occurrence_id: rightRoot?.occurrence_id ?? null,
				left_artifact_id: leftRoot?.artifact_id ?? null,
				right_artifact_id: rightRoot?.artifact_id ?? null,
				evidence_links: [...evidenceLinks]
			});
		};
	})))();
}

//#endregion
//#region dist/domain/comparisonSourceEvidence.js
var evidenceIdSchema$4, sideParametersSchema, comparisonSourceEvidenceSides, comparisonSourceEvidenceIds, assertComparisonFindingLinks;
function init_comparisonSourceEvidence() {
	return (init_comparisonSourceEvidence = __esmMin((() => {
		init_canonicalOrdering();
		init_digests();
		evidenceIdSchema$4 = prefixedDigestSchema("ev");
		sideParametersSchema = z.object({
			left_evidence_id: evidenceIdSchema$4.optional(),
			right_evidence_id: evidenceIdSchema$4.optional(),
			left_evidence_ids: z.array(evidenceIdSchema$4).min(1).optional(),
			right_evidence_ids: z.array(evidenceIdSchema$4).min(1).optional()
		});
		comparisonSourceEvidenceSides = (evidence) => {
			const parameters = sideParametersSchema.parse(evidence.parameters);
			if (parameters.left_evidence_id === undefined !== (parameters.right_evidence_id === undefined) || parameters.left_evidence_ids === undefined !== (parameters.right_evidence_ids === undefined)) throw new TypeError("Comparison Evidence source representation omitted one side");
			const side = (single, multiple) => {
				if (single !== undefined && multiple !== undefined && (multiple.length !== 1 || multiple[0] !== single)) throw new TypeError("Comparison Evidence source representations disagree");
				const selected = single === undefined ? multiple ?? [] : [single];
				if (selected.length === 0) throw new TypeError("Comparison Evidence omitted its source parameters");
				if (new Set(selected).size !== selected.length) throw new TypeError("Comparison Evidence repeats a source within one side");
				return selected;
			};
			return {
				left: side(parameters.left_evidence_id, parameters.left_evidence_ids),
				right: side(parameters.right_evidence_id, parameters.right_evidence_ids)
			};
		};
		comparisonSourceEvidenceIds = (evidence) => {
			const sides = comparisonSourceEvidenceSides(evidence);
			return uniqueSorted([...sides.left, ...sides.right]);
		};
		assertComparisonFindingLinks = (evidence, nestedLinks) => {
			const closure = new Set(evidence.evidence_links);
			if (nestedLinks.some((id) => !closure.has(id))) throw new TypeError("Comparison finding cites Evidence outside its top-level closure");
		};
	})))();
}

//#endregion
//#region dist/domain/process/processEvidenceProvider.js
var PROCESS_PROVIDER, isProcessEvidenceProvider;
function init_processEvidenceProvider() {
	return (init_processEvidenceProvider = __esmMin((() => {
		PROCESS_PROVIDER = {
			id: "rea-process",
			name: "REA process capture",
			version: "3"
		};
		isProcessEvidenceProvider = (provider) => provider.id === PROCESS_PROVIDER.id && provider.version === PROCESS_PROVIDER.version && (provider.name === PROCESS_PROVIDER.name || provider.name === "REA deterministic process harness");
	})))();
}

//#endregion
//#region dist/domain/changedBehavior.js
var evidenceIdSchema$3, changedBehaviorInputSchema, findingSchema, changedBehaviorResultSchema, EXPECTED_PROVIDERS, acceptsPredicate, findChangedBehavior, parseComparisonEvidence, parseResult, findingsFor, processFindings, functionFindings, artifactFindings, makeFinding, behaviorStatus, isChange, count, compareFindings, assertUnique$1;
function init_changedBehavior() {
	return (init_changedBehavior = __esmMin((() => {
		init_artifactComparison();
		init_canonicalOrdering();
		init_unicodeCodePointOrder();
		init_comparisonSourceEvidence();
		init_evidence();
		init_functionComparisonSchemas();
		init_processEvidenceProvider();
		init_processComparison();
		init_digests();
		evidenceIdSchema$3 = prefixedDigestSchema("ev");
		changedBehaviorInputSchema = z.strictObject({ comparisons: z.array(evidenceSchema).min(1) });
		findingSchema = z.object({
			scope: z.enum([
				"runtime",
				"protocol",
				"resource",
				"static_candidate"
			]),
			dimension: z.string().min(1),
			classification: z.enum([
				"observed_change",
				"derived_relationship",
				"contradiction",
				"unresolved_branch"
			]),
			status: comparisonStatusSchema$1,
			source_comparison_id: evidenceIdSchema$3,
			evidence_links: z.array(evidenceIdSchema$3).min(2),
			limitations: z.array(z.string())
		});
		changedBehaviorResultSchema = z.object({
			behavior_status: z.enum([
				"observed_changed",
				"observed_unchanged",
				"unknown",
				"truncated"
			]),
			summary: z.object({
				observed_changes: z.number().int().min(0),
				static_candidates: z.number().int().min(0),
				contradictions: z.number().int().min(0),
				unresolved: z.number().int().min(0)
			}),
			findings: z.object({ items: z.array(findingSchema) }),
			evidence_links: z.array(evidenceIdSchema$3).min(2),
			limitations: z.array(z.string())
		}).superRefine((result, context) => {
			const summaryTotal = Object.values(result.summary).reduce((total, count) => total + count, 0);
			if (summaryTotal !== result.findings.items.length) context.addIssue({
				code: "custom",
				message: "Finding classification counts must equal the finding total",
				path: ["summary"]
			});
			if (result.behavior_status === "observed_changed" && result.summary.observed_changes === 0 || result.behavior_status === "observed_unchanged" && result.summary.observed_changes > 0) context.addIssue({
				code: "custom",
				message: "Observed-change status must agree with runtime findings",
				path: ["behavior_status"]
			});
		});
		EXPECTED_PROVIDERS = {
			compare_process_captures: {
				predicates: ["rea.process-comparison"],
				...PROCESS_PROVIDER
			},
			compare_artifacts: {
				predicates: ["rea.artifact-comparison"],
				id: "rea-artifact-comparison",
				name: "REA artifact comparison",
				version: "1"
			},
			compare_functions: {
				predicates: ["rea.function-comparison"],
				id: "rea-function-comparison",
				name: "REA function comparison",
				version: "1"
			}
		};
		acceptsPredicate = (expected, actual) => expected.some((predicate) => predicate === actual);
		findChangedBehavior = (input) => {
			const { comparisons } = z.strictObject({ comparisons: z.array(z.unknown()).min(1) }).parse(input);
			const evidence = comparisons.map(parseComparisonEvidence);
			assertUnique$1(evidence.map(({ evidence: { evidence_id: id } }) => id), "comparison Evidence");
			const findings = evidence.flatMap(findingsFor).sort(compareFindings);
			const runtimeStatuses = evidence.flatMap((comparison) => comparison.operation === "compare_process_captures" ? [comparison.result.status] : []);
			const links = uniqueSorted(evidence.flatMap(({ evidence: item }) => [item.evidence_id, ...item.evidence_links]));
			const result = changedBehaviorResultSchema.parse({
				behavior_status: behaviorStatus(runtimeStatuses),
				summary: {
					observed_changes: count(findings, "observed_change"),
					static_candidates: count(findings, "derived_relationship"),
					contradictions: count(findings, "contradiction"),
					unresolved: count(findings, "unresolved_branch")
				},
				findings: { items: findings },
				evidence_links: links,
				limitations: uniqueSorted([
					...evidence.flatMap(({ evidence: item }) => item.limitations),
					...evidence.some(({ operation }) => operation !== "compare_process_captures") ? ["Static differences are behavior candidates, not runtime observations."] : [],
					...runtimeStatuses.length === 0 ? ["No process comparison Evidence was supplied."] : []
				])
			});
			return {
				result,
				comparisonEvidenceIds: evidence.map(({ evidence: { evidence_id } }) => evidence_id)
			};
		};
		parseComparisonEvidence = (input) => {
			const evidence = parseEvidence(input);
			if (!(evidence.operation in EXPECTED_PROVIDERS)) throw new TypeError("Changed-behavior analysis requires process, artifact, or function comparison Evidence");
			const operation = z.enum([
				"compare_process_captures",
				"compare_artifacts",
				"compare_functions"
			]).parse(evidence.operation);
			const expected = EXPECTED_PROVIDERS[operation];
			if (!acceptsPredicate(expected.predicates, evidence.predicate_type) || (operation === "compare_process_captures" ? !isProcessEvidenceProvider(evidence.provider) : evidence.provider.id !== expected.id || evidence.provider.name !== expected.name || evidence.provider.version !== expected.version) || evidence.confidence !== "derived" || evidence.authority !== "analyst-inference" || evidence.subject !== null) throw new TypeError("Comparison Evidence operation, predicate, and provider disagree");
			if (!comparisonSourceEvidenceIds(evidence).every((id) => evidence.evidence_links.includes(id))) throw new TypeError("Comparison Evidence must cite both selected source observations");
			return parseResult(evidence, operation);
		};
		parseResult = (evidence, operation) => {
			if (operation === "compare_process_captures") {
				const result = processCaptureComparisonSchema.parse(evidence.normalized_result);
				const expected = deriveProcessComparisonStatus(PROCESS_COMPARISON_DIMENSIONS.map((dimension) => result[dimension]));
				if (result.status !== expected) throw new TypeError("Process comparison status contradicts its dimensions");
				return {
					operation,
					evidence,
					result
				};
			}
			if (operation === "compare_functions") {
				const result = functionComparisonResultSchema.parse(evidence.normalized_result);
				assertComparisonFindingLinks(evidence, result.dimensions.flatMap(({ evidence_links: links }) => links));
				return {
					operation,
					evidence,
					result
				};
			}
			const result = artifactComparisonResultSchema.parse(evidence.normalized_result);
			assertComparisonFindingLinks(evidence, result.changes.flatMap(({ evidence_links: links }) => links));
			return {
				operation,
				evidence,
				result
			};
		};
		findingsFor = (comparison) => {
			if (comparison.operation === "compare_process_captures") return processFindings(comparison);
			if (comparison.operation === "compare_functions") return functionFindings(comparison);
			return artifactFindings(comparison);
		};
		processFindings = (comparison) => {
			const { evidence, result } = comparison;
			const dimensions = [
				[
					"terminal",
					result.terminal,
					"runtime"
				],
				[
					"interaction",
					result.interaction,
					"runtime"
				],
				[
					"exit",
					result.exit,
					"runtime"
				],
				[
					"filesystem",
					result.filesystem,
					"resource"
				],
				[
					"process",
					result.process,
					"runtime"
				]
			];
			return dimensions.flatMap(([dimension, status, scope]) => status === "unchanged" ? [] : [makeFinding({
				evidence,
				dimension,
				scope,
				status,
				classification: isChange(status) ? "observed_change" : "unresolved_branch",
				limitations: result.limitations
			})]);
		};
		functionFindings = (comparison) => {
			const { evidence, result } = comparison;
			return result.dimensions.flatMap((dimension) => dimension.status === "unchanged" ? [] : [makeFinding({
				evidence,
				dimension: dimension.dimension,
				scope: "static_candidate",
				status: dimension.status,
				classification: dimension.status === "unknown" ? "unresolved_branch" : dimension.conclusion_kind,
				limitations: dimension.limitations,
				links: dimension.evidence_links
			})]);
		};
		artifactFindings = (comparison) => {
			const { evidence, result } = comparison;
			const changes = result.changes.map((change) => makeFinding({
				evidence,
				dimension: `artifact:${change.logical_path}`,
				scope: "static_candidate",
				status: change.classification,
				classification: change.classification === "contradiction" ? "contradiction" : change.classification === "unknown" ? "unresolved_branch" : "derived_relationship",
				limitations: result.limitations,
				links: change.evidence_links
			}));
			return (result.status === "unknown" || result.status === "truncated") && !changes.some(({ classification }) => classification === "unresolved_branch") ? [...changes, makeFinding({
				evidence,
				dimension: "artifact:coverage",
				scope: "static_candidate",
				status: result.status,
				classification: "unresolved_branch",
				limitations: result.limitations
			})] : changes;
		};
		makeFinding = (input) => findingSchema.parse({
			scope: input.scope,
			dimension: input.dimension,
			classification: input.classification,
			status: input.status,
			source_comparison_id: input.evidence.evidence_id,
			evidence_links: uniqueSorted([input.evidence.evidence_id, ...input.links ?? input.evidence.evidence_links]),
			limitations: uniqueSorted(input.limitations)
		});
		behaviorStatus = (statuses) => {
			if (statuses.length === 0) return "unknown";
			if (statuses.includes("truncated")) return "truncated";
			if (statuses.includes("unknown")) return "unknown";
			return statuses.some(isChange) ? "observed_changed" : "observed_unchanged";
		};
		isChange = (status) => status === "added" || status === "removed" || status === "changed";
		count = (findings, classification) => findings.filter((finding) => finding.classification === classification).length;
		compareFindings = (left, right) => compareUnicodeCodePoints(compositeKey([
			left.scope,
			left.dimension,
			left.source_comparison_id
		]), compositeKey([
			right.scope,
			right.dimension,
			right.source_comparison_id
		]));
		assertUnique$1 = (values, label) => {
			if (new Set(values).size !== values.length) throw new TypeError(`Changed-behavior analysis rejects duplicate ${label}`);
		};
	})))();
}

//#endregion
//#region dist/domain/callPathSchemas.js
var evidenceIdSchema$2, callPathInputSchema, citedNodeSchema, citedEdgeSchema, pathSchema, resultContextShape, callPathResultSchema;
function init_callPathSchemas() {
	return (init_callPathSchemas = __esmMin((() => {
		init_emptyArraySchema();
		init_evidence();
		init_digests();
		init_nativeAddress();
		evidenceIdSchema$2 = prefixedDigestSchema("ev");
		callPathInputSchema = z.strictObject({
			functions: z.array(evidenceSchema).min(1),
			start: z.object({ address: nativeAddressInputSchema }).strict(),
			goal: z.object({ address: nativeAddressInputSchema }).strict()
		});
		citedNodeSchema = z.object({
			address: nativeAddressSchema,
			name: z.string().nullable(),
			evidence_links: z.array(evidenceIdSchema$2).min(1)
		});
		citedEdgeSchema = z.object({
			source: nativeAddressSchema,
			target: nativeAddressSchema,
			evidence_links: z.array(evidenceIdSchema$2).min(1)
		});
		pathSchema = z.object({
			hops: z.number().int().min(0),
			nodes: z.array(citedNodeSchema).min(1),
			edges: z.array(citedEdgeSchema),
			evidence_links: z.array(evidenceIdSchema$2).min(1)
		}).superRefine((path, context) => {
			const edgesConnectNodes = path.edges.every((edge, index) => edge.source === path.nodes[index]?.address && edge.target === path.nodes[index + 1]?.address);
			if (path.hops !== path.edges.length || path.nodes.length !== path.edges.length + 1 || !edgesConnectNodes) context.addIssue({
				code: "custom",
				message: "Path hops and edges must connect the ordered nodes"
			});
		});
		resultContextShape = {
			start: nativeAddressSchema,
			goal: nativeAddressSchema,
			explored: z.object({
				nodes: z.number().int().min(0),
				edges: z.number().int().min(0),
				depth_reached: z.number().int().min(0)
			}),
			evidence_links: z.array(evidenceIdSchema$2).min(1),
			limitations: z.array(z.string())
		};
		callPathResultSchema = z.union([
			z.object({
				...resultContextShape,
				status: z.literal("found"),
				shortest_hops: z.number().int().min(0),
				search_scope: z.object({ exhaustive: z.boolean() }),
				paths: z.array(pathSchema).min(1)
			}),
			z.object({
				...resultContextShape,
				status: z.literal("not_found"),
				shortest_hops: z.null(),
				search_scope: z.object({ exhaustive: z.literal(true) }),
				paths: emptyArraySchema
			}),
			z.object({
				...resultContextShape,
				status: z.literal("unknown"),
				shortest_hops: z.null(),
				search_scope: z.object({ exhaustive: z.literal(false) }),
				paths: emptyArraySchema
			})
		]);
	})))();
}

//#endregion
//#region dist/domain/staticRuntimeCorrelation.js
var evidenceIdSchema$1, functionDimensionSchema, runtimeDimensionSchema, expectedPatternSchema, observedPatternSchema, artifactSelectorSchema, functionSelectorSchema, staticSelectorSchema, mappingSchema, staticRuntimeCorrelationInputSchema, correlationItemSchema, staticRuntimeCorrelationResultSchema, EXPECTED, correlateStaticAndRuntime, correlate, selectStatic, parseStatic, parseRuntime, assertComparisonIdentity, observedPattern, required, byId, assertUnique, sha256, canonicalJson;
function init_staticRuntimeCorrelation() {
	return (init_staticRuntimeCorrelation = __esmMin((() => {
		init_artifactComparison();
		init_canonicalOrdering();
		init_unicodeCodePointOrder();
		init_comparisonSourceEvidence();
		init_evidence();
		init_functionComparisonSchemas();
		init_processEvidenceProvider();
		init_processComparison();
		init_digests();
		evidenceIdSchema$1 = prefixedDigestSchema("ev");
		functionDimensionSchema = z.enum([
			"identity",
			"pseudocode",
			"assembly",
			"comments",
			"calls",
			"references",
			"strings_names",
			"cfg"
		]);
		runtimeDimensionSchema = z.enum(PROCESS_COMPARISON_DIMENSIONS);
		expectedPatternSchema = z.enum([
			"cochanged",
			"static_only",
			"runtime_only",
			"both_unchanged"
		]);
		observedPatternSchema = z.enum([
			...expectedPatternSchema.options,
			"unknown",
			"truncated"
		]);
		artifactSelectorSchema = z.object({
			kind: z.literal("artifact"),
			logical_path: z.string().min(1)
		}).strict();
		functionSelectorSchema = z.object({
			kind: z.literal("function"),
			dimension: functionDimensionSchema
		}).strict();
		staticSelectorSchema = z.discriminatedUnion("kind", [artifactSelectorSchema, functionSelectorSchema]);
		mappingSchema = z.object({
			static: z.object({
				comparison_evidence_id: evidenceIdSchema$1,
				selector: staticSelectorSchema
			}).strict(),
			runtime: z.object({
				comparison_evidence_id: evidenceIdSchema$1,
				dimension: runtimeDimensionSchema
			}).strict(),
			side_alignment: z.enum(["left_to_left", "left_to_right"]),
			hypothesis: z.object({
				statement: z.string().trim().min(1),
				expected_pattern: expectedPatternSchema
			}).strict()
		}).strict();
		staticRuntimeCorrelationInputSchema = z.object({
			static_comparisons: z.array(evidenceSchema).min(1),
			runtime_comparisons: z.array(evidenceSchema).min(1),
			mappings: z.array(mappingSchema).min(1)
		}).strict();
		correlationItemSchema = z.object({
			correlation_id: prefixedDigestSchema("cor"),
			static: z.object({
				comparison_evidence_id: evidenceIdSchema$1,
				selector: staticSelectorSchema,
				status: comparisonStatusSchema$1,
				conclusion_kind: z.enum([
					"derived_relationship",
					"contradiction",
					"unresolved_branch"
				])
			}),
			runtime: z.object({
				comparison_evidence_id: evidenceIdSchema$1,
				dimension: runtimeDimensionSchema,
				status: comparisonStatusSchema$1
			}),
			side_alignment: z.enum(["left_to_left", "left_to_right"]),
			hypothesis: z.object({
				statement: z.string().min(1),
				expected_pattern: expectedPatternSchema
			}),
			observed_pattern: observedPatternSchema,
			classification: z.enum([
				"hypothesis",
				"contradiction",
				"unresolved_branch"
			]),
			evidence_links: z.array(evidenceIdSchema$1).min(2),
			limitations: z.array(z.string())
		});
		staticRuntimeCorrelationResultSchema = z.object({
			status: z.enum([
				"correlated",
				"contradicted",
				"unknown",
				"truncated"
			]),
			summary: z.object({
				hypotheses: z.number().int().min(0),
				contradictions: z.number().int().min(0),
				unresolved: z.number().int().min(0)
			}),
			correlations: z.object({ items: z.array(correlationItemSchema) }),
			evidence_links: z.array(evidenceIdSchema$1).min(2),
			limitations: z.array(z.string())
		});
		EXPECTED = {
			compare_artifacts: [
				"rea.artifact-comparison",
				"rea-artifact-comparison",
				"REA artifact comparison"
			],
			compare_functions: [
				"rea.function-comparison",
				"rea-function-comparison",
				"REA function comparison"
			],
			compare_process_captures: [
				"rea.process-comparison",
				PROCESS_PROVIDER.id,
				PROCESS_PROVIDER.name
			]
		};
		correlateStaticAndRuntime = (input) => {
			const parsed = staticRuntimeCorrelationInputSchema.parse(input);
			const staticEvidence = parsed.static_comparisons.map(parseStatic);
			const runtimeEvidence = parsed.runtime_comparisons.map(parseRuntime);
			assertUnique(staticEvidence, "static comparison Evidence");
			assertUnique(runtimeEvidence, "runtime comparison Evidence");
			const staticById = byId(staticEvidence);
			const runtimeById = byId(runtimeEvidence);
			const correlations = parsed.mappings.map((mapping) => correlate(mapping, staticById, runtimeById)).sort((left, right) => compareUnicodeCodePoints(left.correlation_id, right.correlation_id));
			if (new Set(correlations.map(({ correlation_id: id }) => id)).size !== correlations.length) throw new TypeError("Static/runtime correlation rejects duplicate mappings");
			const links = uniqueSorted(correlations.flatMap(({ evidence_links: evidenceLinks }) => evidenceLinks));
			const unresolved = correlations.filter(({ classification }) => classification === "unresolved_branch");
			const contradictions = correlations.filter(({ classification }) => classification === "contradiction");
			return staticRuntimeCorrelationResultSchema.parse({
				status: correlations.some(({ observed_pattern: pattern }) => pattern === "truncated") ? "truncated" : unresolved.length > 0 ? "unknown" : contradictions.length > 0 ? "contradicted" : "correlated",
				summary: {
					hypotheses: correlations.length - contradictions.length - unresolved.length,
					contradictions: contradictions.length,
					unresolved: unresolved.length
				},
				correlations: { items: correlations },
				evidence_links: links,
				limitations: ["Mappings are caller-declared hypotheses; consistency does not establish causality.", "Only explicit mappings were evaluated; similar unmapped observations were not correlated."]
			});
		};
		correlate = (mapping, staticById, runtimeById) => {
			const staticEvidence = required(staticById, mapping.static.comparison_evidence_id, "static comparison");
			const runtimeEvidence = required(runtimeById, mapping.runtime.comparison_evidence_id, "runtime comparison");
			const { limitations: selectedLimitations, ...selectedStatic } = selectStatic(staticEvidence, mapping.static.selector);
			const process = processCaptureComparisonSchema.parse(runtimeEvidence.normalized_result);
			const runtimeStatus = process[mapping.runtime.dimension];
			const pattern = observedPattern(selectedStatic.status, runtimeStatus);
			const classification = pattern === "unknown" || pattern === "truncated" ? "unresolved_branch" : pattern === mapping.hypothesis.expected_pattern ? "hypothesis" : "contradiction";
			const projection = {
				static: mapping.static,
				runtime: mapping.runtime,
				side_alignment: mapping.side_alignment,
				hypothesis: mapping.hypothesis
			};
			return correlationItemSchema.parse({
				correlation_id: `cor_${sha256(canonicalJson(projection))}`,
				static: {
					...mapping.static,
					...selectedStatic
				},
				runtime: {
					...mapping.runtime,
					status: runtimeStatus
				},
				side_alignment: mapping.side_alignment,
				hypothesis: mapping.hypothesis,
				observed_pattern: pattern,
				classification,
				evidence_links: uniqueSorted([
					staticEvidence.evidence_id,
					...staticEvidence.evidence_links,
					runtimeEvidence.evidence_id,
					...runtimeEvidence.evidence_links
				]),
				limitations: uniqueSorted([
					...staticEvidence.limitations,
					...selectedLimitations,
					...runtimeEvidence.limitations,
					...process.limitations,
					"This correlation tests an explicit hypothesis and does not establish causality.",
					"Side alignment is caller-declared and was not independently validated against source subjects or environments."
				])
			});
		};
		selectStatic = (evidence, selector) => {
			if (selector.kind === "function") {
				if (evidence.operation !== "compare_functions") throw new TypeError("Function selector requires function comparison Evidence");
				const result = functionComparisonResultSchema.parse(evidence.normalized_result);
				const matches = result.dimensions.filter(({ dimension }) => dimension === selector.dimension);
				const match = matches.at(0);
				if (matches.length !== 1 || match === undefined) throw new TypeError("Function selector must resolve exactly once");
				return {
					status: match.status,
					conclusion_kind: match.conclusion_kind,
					limitations: match.limitations
				};
			}
			if (evidence.operation !== "compare_artifacts") throw new TypeError("Artifact selector requires artifact comparison Evidence");
			const result = artifactComparisonResultSchema.parse(evidence.normalized_result);
			const matches = result.changes.filter(({ logical_path: path }) => path === selector.logical_path);
			const match = matches.at(0);
			if (matches.length !== 1 || match === undefined) throw new TypeError("Artifact selector must resolve exactly one reported delta");
			const status = match.classification;
			return {
				status,
				limitations: [],
				conclusion_kind: status === "contradiction" ? "contradiction" : status === "unknown" ? "unresolved_branch" : "derived_relationship"
			};
		};
		parseStatic = (input) => {
			const evidence = parseEvidence(input);
			if (evidence.operation !== "compare_artifacts" && evidence.operation !== "compare_functions") throw new TypeError("Static/runtime correlation requires artifact or function comparison Evidence");
			assertComparisonIdentity(evidence);
			if (evidence.operation === "compare_artifacts") {
				const result = artifactComparisonResultSchema.parse(evidence.normalized_result);
				assertComparisonFindingLinks(evidence, result.changes.flatMap(({ evidence_links: links }) => links));
			} else {
				const result = functionComparisonResultSchema.parse(evidence.normalized_result);
				assertComparisonFindingLinks(evidence, result.dimensions.flatMap(({ evidence_links: links }) => links));
			}
			return evidence;
		};
		parseRuntime = (input) => {
			const evidence = parseEvidence(input);
			if (evidence.operation !== "compare_process_captures") throw new TypeError("Static/runtime correlation requires process comparison Evidence");
			assertComparisonIdentity(evidence);
			processCaptureComparisonSchema.parse(evidence.normalized_result);
			return evidence;
		};
		assertComparisonIdentity = (evidence) => {
			const expected = EXPECTED[evidence.operation];
			if (expected === undefined || !(Array.isArray(expected[0]) ? expected[0].includes(evidence.predicate_type) : evidence.predicate_type === expected[0]) || (evidence.operation === "compare_process_captures" ? !isProcessEvidenceProvider(evidence.provider) : evidence.provider.id !== expected[1] || evidence.provider.name !== expected[2] || evidence.provider.version !== "1") || evidence.confidence !== "derived" || evidence.authority !== "analyst-inference" || evidence.subject !== null) throw new TypeError("Comparison Evidence operation, predicate, provider, or citations disagree");
			const expectedLinks = comparisonSourceEvidenceIds(evidence);
			const actualLinks = uniqueSorted(evidence.evidence_links);
			if (expectedLinks.length !== actualLinks.length || expectedLinks.some((id, index) => id !== actualLinks[index])) throw new TypeError("Comparison Evidence closure disagrees with its source parameters");
		};
		observedPattern = (staticStatus, runtimeStatus) => {
			if (staticStatus === "truncated" || runtimeStatus === "truncated") return "truncated";
			if (staticStatus === "unknown" || runtimeStatus === "unknown") return "unknown";
			const staticChanged = staticStatus !== "unchanged";
			const runtimeChanged = runtimeStatus !== "unchanged";
			if (staticChanged && runtimeChanged) return "cochanged";
			if (staticChanged) return "static_only";
			if (runtimeChanged) return "runtime_only";
			return "both_unchanged";
		};
		required = (values, id, label) => {
			const value = values.get(id);
			if (value === undefined) throw new TypeError(`Mapping references absent ${label} Evidence`);
			return value;
		};
		byId = (evidence) => new Map(evidence.map((item) => [item.evidence_id, item]));
		assertUnique = (evidence, label) => {
			if (new Set(evidence.map(({ evidence_id: id }) => id)).size !== evidence.length) throw new TypeError(`Static/runtime correlation rejects duplicate ${label}`);
		};
		sha256 = (value) => createHash("sha256").update(value).digest("hex");
		canonicalJson = (value) => {
			const serialized = canonicalize(value);
			if (serialized === undefined) throw new TypeError("RFC 8785 canonicalization rejected correlation mapping");
			return serialized;
		};
	})))();
}

//#endregion
//#region dist/domain/reconstructionVerificationSchemas.js
var evidenceIdSchema, unknownIdSchema, claimIdSchema, titleSchema, verificationStatusSchema, commonClaim, behavioralClaimSchema, functionClaimSchema, artifactClaimSchema, reconstructionClaimSchema, reconstructionSpecificationSchema, reconstructionVerificationInputSchema, reconstructionClaimResultSchema, reconstructionVerificationResultSchema;
function init_reconstructionVerificationSchemas() {
	return (init_reconstructionVerificationSchemas = __esmMin((() => {
		init_stringPatterns();
		init_digests();
		init_processComparison();
		evidenceIdSchema = prefixedDigestSchema("ev");
		unknownIdSchema = prefixedDigestSchema("unk");
		claimIdSchema = z.string().regex(IDENTIFIER_PATTERN);
		titleSchema = z.string().trim().min(1);
		verificationStatusSchema = z.enum([
			"pass",
			"fail",
			"unknown"
		]);
		commonClaim = {
			claim_id: claimIdSchema,
			title: titleSchema,
			comparison_evidence_id: evidenceIdSchema
		};
		behavioralClaimSchema = z.object({
			...commonClaim,
			kind: z.literal("behavioral"),
			dimension: z.enum(["overall", ...PROCESS_COMPARISON_DIMENSIONS])
		});
		functionClaimSchema = z.object({
			...commonClaim,
			kind: z.literal("structural-function"),
			dimension: z.enum([
				"overall",
				"identity",
				"pseudocode",
				"assembly",
				"comments",
				"calls",
				"references",
				"strings_names",
				"cfg"
			])
		});
		artifactClaimSchema = z.object({
			...commonClaim,
			kind: z.literal("structural-artifact"),
			dimension: z.literal("overall")
		});
		reconstructionClaimSchema = z.discriminatedUnion("kind", [
			behavioralClaimSchema,
			functionClaimSchema,
			artifactClaimSchema
		]);
		reconstructionSpecificationSchema = z.object({
			name: z.string().trim().min(1),
			claims: z.array(reconstructionClaimSchema).min(1)
		}).superRefine((value, context) => {
			const ids = value.claims.map(({ claim_id: id }) => id);
			if (new Set(ids).size !== ids.length) context.addIssue({
				code: "custom",
				message: "Claim IDs must be unique"
			});
			const selectors = value.claims.map(({ kind, comparison_evidence_id: id, dimension }) => `${kind}:${id}:${dimension}`);
			if (new Set(selectors).size !== selectors.length) context.addIssue({
				code: "custom",
				message: "Claim comparison selectors must be unique"
			});
		});
		reconstructionVerificationInputSchema = z.strictObject({ specification: reconstructionSpecificationSchema });
		reconstructionClaimResultSchema = z.object({
			claim_id: claimIdSchema,
			kind: z.enum([
				"behavioral",
				"structural-function",
				"structural-artifact"
			]),
			dimension: z.string().min(1),
			status: verificationStatusSchema,
			observed_status: z.enum([
				"unchanged",
				"added",
				"removed",
				"changed",
				"truncated",
				"unknown",
				"contradiction"
			]),
			comparison_evidence_id: evidenceIdSchema,
			left_evidence_ids: z.array(evidenceIdSchema).min(1),
			right_evidence_ids: z.array(evidenceIdSchema).min(1),
			evidence_links: z.array(evidenceIdSchema).min(2),
			unknown_ids: z.array(unknownIdSchema),
			limitations: z.array(z.string())
		});
		reconstructionVerificationResultSchema = z.object({
			status: verificationStatusSchema,
			specification_sha256: digestSchema,
			summary: z.object({
				total: z.number().int().min(1),
				passed: z.number().int().min(0),
				failed: z.number().int().min(0),
				unknown: z.number().int().min(0),
				behavioral: z.number().int().min(0),
				structural: z.number().int().min(0)
			}),
			claims: z.object({ items: z.array(reconstructionClaimResultSchema) }),
			recommended_probes: z.array(z.object({
				operation: z.string().min(1),
				rationale: z.string().min(1),
				claim_ids: z.array(claimIdSchema).min(1),
				unknown_ids: z.array(unknownIdSchema)
			})),
			evidence_links: z.array(evidenceIdSchema).min(2),
			limitations: z.array(z.string())
		}).superRefine((result, context) => {
			const { summary } = result;
			const expectedStatus = summary.failed > 0 ? "fail" : summary.unknown > 0 ? "unknown" : "pass";
			const issues = [
				[
					summary.total !== summary.passed + summary.failed + summary.unknown,
					"Claim status counts must equal the summary total",
					["summary", "total"]
				],
				[
					summary.total !== summary.behavioral + summary.structural,
					"Claim kind counts must equal the summary total",
					["summary", "total"]
				],
				[
					result.claims.items.length !== summary.total,
					"Retained claims must equal the summary total",
					["claims", "items"]
				],
				[
					result.status !== expectedStatus,
					"Verification status must summarize claim statuses",
					["status"]
				]
			];
			for (const [invalid, message, path] of issues) if (invalid) context.addIssue({
				code: "custom",
				message,
				path: [...path]
			});
		});
	})))();
}

//#endregion
//#region dist/contracts/toolOutputSchemaGroups.js
var contextFacetSchema, bookmarkFacetSchema, officialOutputSchemas, literalTraceOutput, callPathTraceOutput, batchProcedureIdentity, enhancedOutputSchemas, nativeOutputSchemas, artifactOutputSchemas, managedOutputSchemas, managedWorkflowOutputSchemas, lifecycleTargetFields, detectedLifecycleTargetSchema, rawLifecycleTargetSchema, sessionOutputSchemas, electronFuseOutputSchemas;
function init_toolOutputSchemaGroups() {
	return (init_toolOutputSchemaGroups = __esmMin((() => {
		init_functionMatching();
		init_analysisView();
		init_nativeByteRead();
		init_analysisDetail();
		init_nativeInventory();
		init_bytePattern();
		init_evidenceRecordSummary();
		init_binaryTargetTypes();
		init_rawBinary();
		init_nativeFunctionAnnotations();
		init_nativeLoadImage();
		init_nativeUiObservation();
		init_nativeValueTrace();
		init_bundleResourceRoot();
		init_nativeDataType();
		init_nativeCallObservation();
		init_nativeInstruction();
		init_jsonValue();
		init_residualUnknown();
		init_evidenceBundle();
		init_processComparison();
		init_hopperValues();
		init_nativeApiBoundary();
		init_nativeInspection();
		init_artifactGraph();
		init_artifactInspection();
		init_interfaceBuilderGraph();
		init_dylibResolution();
		init_keyedArchive();
		init_appleAssetCatalog();
		init_managedArtifact();
		init_managedMemberComparison();
		init_managedNativeVerificationSchemas();
		init_managedReconstruction();
		init_managedApplicationGraph();
		init_artifactComparison();
		init_functionComparisonSchemas();
		init_bundleComparison();
		init_changedBehavior();
		init_callPathSchemas();
		init_staticRuntimeCorrelation();
		init_reconstructionVerificationSchemas();
		init_errorSchemas();
		init_relationshipCoverage();
		init_objcSwiftMetadata();
		init_nativeInvestigationGraph();
		init_toolOutputSchemaPrimitives();
		init_processCapture();
		init_electronFuses();
		contextFacetSchema = z.discriminatedUnion("state", [z.object({
			state: z.literal("available"),
			value: jsonValueSchema
		}), z.object({
			state: z.literal("unavailable"),
			reason: z.string(),
			remediation: z.string()
		})]);
		bookmarkFacetSchema = z.discriminatedUnion("state", [z.object({
			state: z.literal("available"),
			value: z.array(analysisBookmarkSchema)
		}), z.object({
			state: z.literal("unavailable"),
			reason: z.string(),
			remediation: z.string()
		})]);
		officialOutputSchemas = {
			search_bytes: evidenceResultOf(byteSearchResultSchema),
			annotate_native_function: evidenceResultOf(nativeFunctionAnnotationsSchema),
			inspect_native_load_image: evidenceResultOf(nativeLoadImageSchema),
			inspect_native_data_type: evidenceResultOf(nativeDataTypeSchema),
			inspect_native_instruction: evidenceResultOf(nativeInstructionSchema),
			resolve_native_call_targets: evidenceResultOf(nativeCallTargetsSchema),
			address_name: evidenceResultOf(nullableText),
			comment: evidenceResultOf(nullableText),
			current_address: evidenceResultOf(z.string()),
			current_procedure: evidenceResultOf(z.string()),
			current_document: evidenceResultOf(z.string()),
			goto_address: evidenceResultOf(z.string()),
			inline_comment: evidenceResultOf(nullableText),
			list_bookmarks: evidenceResultOf(z.array(analysisBookmarkSchema)),
			list_documents: evidenceResultOf(z.array(z.string())),
			list_names: analysisDetailOutputSchemaOf(nativeInventoryRowsSchemas.names, nativeInventorySummaryViewResultSchema.extend({ parent_operation: z.literal("list_names") })),
			list_procedures: analysisDetailOutputSchemaOf(nativeInventoryRowsSchemas.names, nativeInventorySummaryViewResultSchema.extend({ parent_operation: z.literal("list_procedures") })),
			list_segments: segmentOutput,
			list_strings: analysisDetailOutputSchemaOf(nativeInventoryRowsSchemas.strings, nativeInventorySummaryViewResultSchema.extend({ parent_operation: z.literal("list_strings") })),
			next_address: evidenceResultOf(z.string()),
			prev_address: evidenceResultOf(z.string()),
			procedure_address: evidenceResultOf(z.string()),
			procedure_assembly: evidenceResultOf(z.string()),
			procedure_callees: evidenceResultOf(addressList),
			procedure_callers: evidenceResultOf(addressList),
			procedure_info: procedureInfoOutput,
			read_function_instructions: evidenceResultOf(functionInstructionWindowSchema),
			read_bytes: evidenceResultOf(nativeByteReadSchema),
			address_to_file_offset: evidenceResultOf(z.object({
				address: z.string(),
				file_offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
				provider_file_offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).exactOptional().describe("Original coordinate returned by the provider's mapping API."),
				image_base_file_offset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).exactOptional().describe("File offset of the loaded image within its source container; zero for a thin executable."),
				source_path: z.string().exactOptional().describe("Observed original executable path used to verify the file mapping.")
			})),
			procedure_references: evidenceResultOf(z.object({
				procedure: procedureIdentitySchema,
				direction: z.enum(["incoming", "outgoing"]),
				reference_kinds_available: z.boolean(),
				unresolved_calls: z.array(unresolvedCallSchema),
				references: z.array(referenceEdgeSchema)
			})),
			procedure_pseudo_code: evidenceResultOf(nullableText),
			resolve_containing_procedure: evidenceResultOf(containingProcedureResolution),
			search_procedures: analysisDetailOutputSchemaOf(z.array(z.object({
				address: z.string(),
				value: z.string()
			})), nativeInventorySummaryViewResultSchema.extend({ parent_operation: z.literal("search_procedures") })),
			search_strings: analysisDetailOutputSchemaOf(nativeInventoryRowsSchemas.strings, nativeInventorySummaryViewResultSchema.extend({ parent_operation: z.literal("search_strings") })),
			set_address_name: evidenceResultOf(z.boolean()),
			set_addresses_names: evidenceResultOf(z.record(z.string(), z.boolean())),
			set_bookmark: evidenceResultOf(z.boolean()),
			set_comment: evidenceResultOf(z.boolean()),
			set_inline_comment: evidenceResultOf(z.boolean()),
			unset_bookmark: evidenceResultOf(z.boolean()),
			xrefs: evidenceResultOf(addressList)
		};
		literalTraceOutput = evidenceResultOf(z.object({
			query: z.string(),
			search_mode: z.literal("literal"),
			matches: z.array(z.object({
				type: z.enum(["string", "procedure"]),
				address: z.string(),
				value: z.string()
			})),
			references: z.array(z.object({
				target_address: z.string(),
				source_address: z.string(),
				containing_procedure: containingProcedureResolution
			})),
			truncated: z.boolean(),
			residual_unknowns: z.array(z.string())
		}));
		callPathTraceOutput = evidenceResultOf(z.object({
			start: z.string(),
			goal: z.string().nullable(),
			direction: z.enum(["forward", "backward"]),
			goal_status: z.enum([
				"not_requested",
				"reached",
				"not_reached",
				"unknown"
			]),
			nodes: z.array(z.object({
				address: z.string(),
				depth: z.number().int().min(0)
			})),
			edges: z.array(z.object({
				source_address: z.string(),
				target_address: z.string(),
				discovery_depth: z.number().int().min(1)
			})),
			traversal_path: z.array(z.string()),
			failures: z.array(z.object({
				address: z.string(),
				error: analysisErrorProjectionSchema
			})),
			relationship_coverage: z.record(z.string(), relationshipCoverageSchema),
			traversal: z.object({ nodes_visited: z.number().int().min(1) }),
			truncated: z.boolean(),
			residual_unknowns: z.array(z.string()),
			limitations: z.array(z.string())
		}));
		batchProcedureIdentity = z.discriminatedUnion("status", [z.object({
			status: z.literal("resolved"),
			address: z.string().min(1).describe("Observed canonical procedure entry."),
			name: z.string().nullable().describe("Provider's entry label, or null when unavailable."),
			name_error: analysisErrorProjectionSchema.optional()
		}), z.object({
			status: z.literal("unknown"),
			error: analysisErrorProjectionSchema
		})]);
		enhancedOutputSchemas = {
			inspect_native_dispatch_metadata: evidenceResultOf(nativeDispatchMetadataResultSchema),
			trace_native_values: evidenceResultOf(nativeValueTraceSchema),
			trace_native_ui_action: evidenceResultOf(nativeInvestigationTraceSchema),
			get_objc_classes: objcClassDiscoveryOutput,
			get_objc_protocols: symbolDiscoveryOutput("protocols"),
			batch_decompile: evidenceResultOf(z.object({
				items: z.array(z.discriminatedUnion("status", [z.object({
					address: z.string().describe("Original caller-selected symbol or address."),
					procedure: batchProcedureIdentity,
					status: z.literal("ok"),
					pseudocode: z.string().min(1)
				}), z.object({
					address: z.string().describe("Original caller-selected symbol or address."),
					procedure: batchProcedureIdentity,
					status: z.literal("error"),
					error: analysisErrorProjectionSchema
				})])),
				total: z.number().int().min(0),
				succeeded: z.number().int().min(0),
				failed: z.number().int().min(0)
			})),
			get_call_graph: evidenceResultOf(z.strictObject({
				graph: z.record(z.string(), z.array(graphNode)),
				limitations: z.array(z.string())
			})),
			analyze_swift_types: evidenceResultOf(z.object({
				total: z.number().int().min(0),
				categories: z.record(z.string(), z.object({
					count: z.number().int().min(0),
					items: z.array(addressedEntry.extend({ mangled_names: z.array(z.string()) }))
				})),
				unclassified: z.array(addressedEntry.extend({
					mangled_names: z.array(z.string()),
					reason: z.enum(["category_not_decoded", "conflicting_categories"])
				})),
				limitations: z.array(z.string()),
				symbol_inventory_error: analysisErrorProjectionSchema.exactOptional()
			})),
			find_xrefs_to_name: evidenceResultOf(z.discriminatedUnion("status", [z.object({
				status: z.literal("resolved"),
				name: z.string(),
				address: z.string(),
				xrefs: addressList
			}), z.object({
				status: z.literal("unresolved"),
				name: z.string(),
				reason: z.literal("name_not_found")
			})])),
			binary_overview: evidenceResultOf(z.object({
				document: z.string(),
				image_base: z.string().min(1).optional(),
				segments: z.array(z.object({
					name: z.string(),
					start: z.string(),
					end: z.string(),
					length: z.number().min(0).nullable(),
					image_base: z.string().exactOptional(),
					address_space: z.string().exactOptional()
				})).optional(),
				segment_count: z.number().int().min(0).optional(),
				procedure_count: z.number().int().min(0),
				string_count: z.number().int().min(0)
			})),
			analyze_function: functionDossierOutput,
			inspect_native_api: evidenceResultOf(nativeApiInspectionResultSchema),
			trace_feature: literalTraceOutput,
			trace_call_path: callPathTraceOutput
		};
		nativeOutputSchemas = {
			observe_native_ui: evidenceResultOf(nativeUiResultSchema),
			capture_native_ui_scenario: evidenceResultOf(nativeUiResultSchema),
			observe_native_calls: evidenceResultOf(nativeCallObservationResultSchema),
			inspect_macho: evidenceResultOf(z.union([inspectMachoSchema, machoSummaryViewResultSchema])),
			inspect_signature: evidenceResultOf(inspectSignatureSchema),
			inspect_plist: evidenceResultOf(inspectPlistSchema),
			list_architectures: evidenceResultOf(listArchitecturesSchema),
			demangle_swift: evidenceResultOf(demangleSwiftSchema)
		};
		artifactOutputSchemas = {
			inspect_artifact: evidenceResultOf(z.union([artifactInspectionResultSchema, artifactInventorySummaryViewResultSchema])),
			extract_artifact: evidenceResultOf(artifactExtractionResultSchema),
			decode_interface_builder: evidenceResultOf(z.union([interfaceBuilderAnalysisSchema, interfaceBuilderSummaryViewResultSchema])),
			inspect_keyed_archive: evidenceResultOf(keyedArchiveResultSchema),
			inspect_asset_catalog: evidenceResultOf(appleAssetCatalogResultSchema),
			trace_dylib_resolution: evidenceResultOf(dylibResolutionResultSchema)
		};
		managedOutputSchemas = {
			inspect_managed_artifact: evidenceResultOf(z.union([managedArtifactInspectionSchema, managedArtifactSummaryViewResultSchema])),
			inspect_managed_members: evidenceResultOf(z.union([managedMemberInspectionSchema, managedMemberSummaryViewResultSchema])),
			inspect_managed_native_boundaries: evidenceResultOf(managedNativeBoundaryInspectionSchema)
		};
		managedWorkflowOutputSchemas = {
			compare_managed_members: evidenceResultOf(managedMemberComparisonResultSchema),
			verify_managed_native_boundaries: evidenceResultOf(managedNativeVerificationResultSchema),
			import_managed_reconstruction: evidenceResultOf(managedReconstructionImportResultSchema),
			project_managed_application_graph: evidenceResultOf(managedApplicationGraphResultSchema)
		};
		lifecycleTargetFields = {
			path: z.string(),
			kind: targetKindSchema,
			sha256: z.string().regex(/^[a-f0-9]{64}$/u)
		};
		detectedLifecycleTargetSchema = z.object({
			...lifecycleTargetFields,
			format: targetFormatSchema.exclude(["raw-binary"]),
			architecture: z.enum(BINARY_ARCHITECTURES$1).exclude([...RAW_ONLY_ARCHITECTURES]).nullable()
		});
		rawLifecycleTargetSchema = z.object({
			...lifecycleTargetFields,
			format: z.literal("raw-binary"),
			kind: z.literal("executable"),
			architecture: binaryArchitectureSchema,
			entry_point: rawBinaryEntryPointSchema.describe("Canonical caller-selected address where raw file offset 0 is mapped and execution is seeded.")
		});
		sessionOutputSchemas = {
			open_binary: lifecycleResultOf(z.discriminatedUnion("format", [detectedLifecycleTargetSchema, rawLifecycleTargetSchema])),
			open_bundle_resources: lifecycleResultOf(bundleResourceRootSchema),
			close_binary: lifecycleResultOf(z.union([z.null(), z.object({
				path: z.string(),
				bytes: z.number().int().min(0),
				primitive_entries: z.number().int().min(0).describe("Retained eligible primitive query bindings."),
				workflow_entries: z.number().int().min(0).describe("Retained eligible composed workflow bindings."),
				evidence_records: z.number().int().min(0).describe("All retained Evidence records, including observations without replay bindings.")
			})])),
			binary_session: lifecycleResultOf(z.union([
				sessionProvider.extend({ open: z.literal(false) }),
				sessionProvider.extend({
					open: z.literal(true),
					session_kind: z.literal("bundle_resources"),
					resource_root: bundleResourceRootSchema
				}),
				sessionProvider.extend({
					open: z.literal(true),
					...detectedLifecycleTargetSchema.shape
				}),
				sessionProvider.extend({
					open: z.literal(true),
					...rawLifecycleTargetSchema.shape
				})
			])),
			export_evidence_bundle: lifecycleResultOf(z.object({
				path: z.string(),
				bytes: z.number().int().min(0),
				records: z.number().int().min(0),
				unknowns: z.number().int().min(0)
			})),
			get_evidence_bundle: lifecycleResultOf(z.union([evidenceBundleSchema, evidenceBundleSummarySchema])),
			get_navigation_context: lifecycleResultOf(z.object({
				document: z.string(),
				address: z.string(),
				procedure: z.union([z.string(), z.null()])
			})),
			inspect_address_context: lifecycleResultOf(z.object({
				address: z.string(),
				document: z.string().nullable(),
				name: contextFacetSchema,
				procedure: contextFacetSchema,
				comment: contextFacetSchema,
				inline_comment: contextFacetSchema,
				bookmarks: bookmarkFacetSchema
			})),
			import_evidence_bundle: lifecycleResultOf(z.object({
				imported: z.number().int().min(0),
				unknowns_added: z.number().int().min(0),
				total: z.number().int().min(0)
			})),
			capture_process_scenario: evidenceResultOf(processCaptureSchema),
			compare_process_captures: evidenceResultOf(processCaptureComparisonSchema),
			compare_artifacts: evidenceResultOf(artifactComparisonResultSchema),
			compare_functions: evidenceResultOf(functionComparisonResultSchema),
			match_native_functions: evidenceResultOf(z.union([nativeFunctionMatchingSchema, nativeFunctionMatchingSummaryViewResultSchema])),
			compare_bundles: evidenceResultOf(bundleComparisonResultSchema),
			find_changed_behavior: evidenceResultOf(changedBehaviorResultSchema),
			build_call_path: evidenceResultOf(callPathResultSchema),
			correlate_static_and_runtime: evidenceResultOf(staticRuntimeCorrelationResultSchema),
			verify_reconstruction: evidenceResultOf(reconstructionVerificationResultSchema),
			list_unknowns: lifecycleResultOf(z.object({
				items: z.array(residualUnknownSchema),
				total: z.number().int().min(0),
				offset: z.number().int().min(0),
				next_offset: z.number().int().min(0).nullable()
			})),
			record_unknown: lifecycleResultOf(residualUnknownSchema),
			update_unknown: lifecycleResultOf(residualUnknownSchema),
			verify_unknown_resolution: lifecycleResultOf(z.object({
				valid: z.boolean(),
				truthVerified: z.boolean(),
				unknown: residualUnknownSchema
			}))
		};
		electronFuseOutputSchemas = { inspect_electron_fuses: evidenceResultOf(electronFuseReportSchema) };
	})))();
}

//#endregion
export { KeyedArchiveKindError, PROCESS_PROVIDER, PROVIDER_EFFECT_NAMES, UnknownPlistScalar, admitRawBinary, analysisDetailOutputSchemaOf, analysisDetailSchema, appleAssetCatalogInputSchema, appleResourceKeyFields, artifactComparisonInputSchema, artifactOutputSchemas, binaryArchitectureSchema, binaryDatePrecisionOverlapLimitation, bundleComparisonInputSchema, bytePatternFields, byteSearchResultSchema, callPathInputSchema, changedBehaviorInputSchema, compareBundles, compareManagedMembers, compareProcessCaptures, dylibResolutionInputSchema, dylibResolutionResultSchema, electronFuseOutputSchemas, enhancedOutputSchemas, evidenceRecordFiltersSchema, evidenceResultOf, importManagedReconstruction, init_analysisDetail, init_appleAssetCatalog, init_artifactComparison, init_bundleComparison, init_bytePattern, init_callPathSchemas, init_changedBehavior, init_dyldPaths, init_dylibResolution, init_evidenceRecordSummary, init_keyedArchive, init_managedMemberComparison, init_managedMemberComparisonMatch, init_managedNativeVerificationSchemas, init_managedReconstruction, init_nativeAddress, init_nativeByteRead, init_nativeCallObservation, init_nativeDataType, init_nativeFunctionAnnotations, init_nativeLoadImage, init_nativeMetadataRecovery, init_nativeUiObservation, init_plistValue, init_pngHeader, init_procedureInfo, init_processComparison, init_processEvidenceProvider, init_processTraceSpecification, init_rawBinary, init_reconstructionVerificationSchemas, init_staticRuntimeCorrelation, init_toolEffects, init_toolOutputSchemaGroups, init_toolOutputSchemaPrimitives, init_unknownPlistScalar, isProcessEvidenceProvider, keyedArchiveInputSchema, keyedArchiveResultSchema, managedNativeVerificationInputSchema, managedNativeVerificationResultSchema, managedOutputSchemas, managedReconstructionImportInputSchema, managedWorkflowOutputSchemas, nativeAddressInputSchema, nativeByteReadSchema, nativeCallEventSchema, nativeCallObservationInputSchema, nativeCallObservationResultSchema, nativeCapturedOutputSchema, nativeCodeLocationSchema, nativeDataTypeInputSchema, nativeDataTypeSchema, nativeFunctionAnnotationsInputSchema, nativeFunctionAnnotationsSchema, nativeLoadImageObservationSchema, nativeLoadImagePartialObservationSchema, nativeLoadImageSchema, nativeMetadataRecoverySummarySchema, nativeOutputSchemas, nativeUiObservationInputSchema, nativeUiResultSchema, nativeUiScenarioInputSchema, nativeUiSnapshotSchema, negativeZeroReal, negativeZeroRealLimitation, nonFiniteRealLimitation, officialOutputSchemas, parseAppleAssetCatalogRecords, parseManagedMemberEvidence, parseNativeAddress, pinvokeVerificationSchema, procedureInfoSchema, processTraceSpecificationSchema, projectAppleAssetCatalogPage, projectKeyedArchive, projectPlistValue, providerCapabilitySet, rawBinaryEntryPointSchema, rawBinarySelectionError, readPngHeaderDimensions, reconstructionVerificationInputSchema, requireOutputSchema, resolveTreePath, sessionOutputSchemas, staticRuntimeCorrelationInputSchema, summarizeEvidenceBundle, toolContractMetadata, traceDylibLoading, unknownDateLimitation, unknownScalarLimitation, validateBytePattern };