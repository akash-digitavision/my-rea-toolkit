import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, o as ok } from "./analysisErrorBase-C1inc3JA.js";
import { Fi as artifactInspectionResultSchema, Li as init_artifactInspection, _o as analysisErrorProjectionSchema, vo as init_errorSchemas } from "./toolOutputSchemaGroups-D--zoCY3.js";
import { _ as init_providerAdapterError, c as EvidenceFileError, d as init_evidenceErrors, g as ProviderAdapterError, l as EvidenceIntegrityError, n as projectAnalysisError, t as init_analysisErrorProjection } from "./analysisErrorProjection-DPMozIkD.js";
import { n as init_BinaryTargetResolver, r as parseBinaryTarget, t as classifyBinaryTargetFilesystemFailure } from "./BinaryTargetResolver-BfIQB5jB.js";
import { A as addressedValueSchema, Nt as init_evidence, Ot as createEvidence, j as init_nativeInventory } from "./nativeValueTrace-Cm--GSDT.js";
import { i as jsonValueSchema, n as init_jsonValue } from "./jsonValue-sVQvKuTs.js";
import { n as createAnalysisExecutionEvidence, r as init_AnalysisProvider } from "./AnalysisProvider-DGkyz5GH.js";
import { a as AnalysisCapabilityUnavailableError, f as init_analysisErrorCore, o as AnalysisInputError, s as AnalysisOutputError } from "./analysisErrorCore-BMJXbfFY.js";
import { n as init_analysisErrorCleanup, t as analysisErrorWithCleanupFailure } from "./analysisErrorCleanup-LFIV2yDc.js";
import { n as init_logger, r as silentLogger } from "./logger-DJs_OLxk.js";
import { a as init_BundleResourceSession, r as BUNDLE_RESOURCE_OPERATIONS } from "./BundleResourceSession-qg6BiqeL.js";
import { D as workflowAnalysisProfile, E as init_InvestigationProviders, S as REA_WORKFLOW_PROVIDER, a as init_callerPath, i as absoluteCallerPath } from "./godotPckFormat-Bh8AriRi.js";
import { n as init_managedToolContracts, r as isManagedToolName } from "./managedToolContracts-CEp8X_RS.js";
import { o as init_artifactToolContracts, t as ARTIFACT_ANALYSIS_OPERATIONS } from "./artifactToolContracts-QNOmMH5D.js";
import { a as init_AnalysisSnapshotFiles, f as init_AnalysisSnapshotCache, g as snapshotEvidenceForQuery, h as init_analysisSnapshot, i as profilelessNativeDispatchProfile, m as requiresNativeSourceAdmissionBeforeReplay, n as init_ProfilelessNativeWorkflowSnapshot, o as readAnalysisSnapshot, v as snapshotMatchesTarget } from "./ProfilelessNativeWorkflowSnapshot-D3voGFDM.js";
import { n as resolveProcedureAddress, t as init_ProcedureAddressResolution } from "./ProcedureAddressResolution-DqULHRa1.js";
import { a as workflowSnapshotRecord, i as recordWorkflowUnknowns, n as executeComposedWorkflow, r as init_WorkflowEvidence, t as createWorkflowEvidence } from "./WorkflowEvidence-BIqPsD0Z.js";
import { access, stat } from "node:fs/promises";

//#region dist/application/XrefsAddressResolution.js
var resolveXrefsAddress;
function init_XrefsAddressResolution() {
	return (init_XrefsAddressResolution = __esmMin((() => {
		init_nativeInventory();
		init_analysisErrorCore();
		init_result();
		init_ProcedureAddressResolution();
		resolveXrefsAddress = async (analysis, selector, signal) => {
			if (selector.length === 0 || /^[0-9a-f]+$/iu.test(selector) || /^0x/iu.test(selector) || /:0x/iu.test(selector)) return ok(selector);
			const inventory = await analysis.execute("list_names", {}, { signal });
			if (!inventory.ok) {
				if (inventory.error instanceof AnalysisCapabilityUnavailableError && inventory.error.operation === "list_names" && !inventory.error.cleanupIncomplete) return resolveProcedureAddress(async (operation, parameters, signal) => {
					const result = await analysis.execute(operation, parameters, signal === undefined ? {} : { signal });
					return result.ok ? ok(result.value.result) : result;
				}, selector, signal);
				return inventory;
			}
			if (!Array.isArray(inventory.value.result)) return err(new AnalysisOutputError("list_names", "Expected a symbol inventory array"));
			const addresses = new Set();
			for (const [index, item] of inventory.value.result.entries()) {
				const parsed = addressedValueSchema.safeParse(item);
				if (!parsed.success || parsed.data.address.length === 0) return err(new AnalysisOutputError("list_names", `Invalid symbol inventory entry at index ${index}`));
				if (parsed.data.value === selector) addresses.add(parsed.data.address);
			}
			const [address] = addresses;
			if (addresses.size === 1 && address !== undefined) return ok(address);
			return err(new AnalysisInputError("xrefs", undefined, [{
				path: ["address"],
				reason: "invalid_value",
				message: addresses.size === 0 ? `Unknown analyzed symbol name ${JSON.stringify(selector)}. Use an exact analyzed name or a hexadecimal address.` : `Analyzed symbol name ${JSON.stringify(selector)} is ambiguous at ${[...addresses].join(", ")}. Select an exact address.`
			}]));
		};
	})))();
}

//#endregion
//#region dist/application/DirectAnalysisCleanup.js
var withSessionCleanup, directAnalysisCleanupFailure, managedAnalysisCleanupFailure;
function init_DirectAnalysisCleanup() {
	return (init_DirectAnalysisCleanup = __esmMin((() => {
		init_errorSchemas();
		init_analysisErrorProjection();
		init_jsonValue();
		init_providerAdapterError();
		init_result();
		init_analysisErrorCleanup();
		withSessionCleanup = async (session, operation, onCleanupFailure) => {
			let value;
			try {
				value = await operation();
			} catch (cause) {
				const closed = await session.close();
				if (!closed.ok) throw new AggregateError([cause, closed.error], "Analysis and provider cleanup both failed", { cause });
				throw cause;
			}
			const closed = await session.close();
			return closed.ok ? value : onCleanupFailure(value, closed.error);
		};
		directAnalysisCleanupFailure = (output, error) => {
			const cleanup = projectAnalysisError(error);
			if (typeof output === "object" && output !== null && !Array.isArray(output)) {
				const { error: label, ...projection } = output;
				const primary = analysisErrorProjectionSchema.safeParse(projection);
				if (typeof label === "string" && primary.success) return {
					error: label,
					...primary.data,
					code: "cleanup_incomplete",
					retryable: false,
					remediation: cleanup.remediation,
					details: {
						resources: error.cleanupResources.slice(),
						...primary.data.details,
						cleanup: "incomplete",
						execution_failure: primary.data.details !== undefined && "execution_failure" in primary.data.details ? primary.data.details.execution_failure ?? primary.data.code : primary.data.code,
						cleanup_error: cleanup
					}
				};
			}
			return {
				error: "Analysis failed",
				...cleanup,
				code: "cleanup_incomplete",
				retryable: false,
				details: {
					...cleanup.details,
					cleanup: "incomplete",
					partial_observation: output
				}
			};
		};
		managedAnalysisCleanupFailure = (result, error) => {
			if (!result.ok) return err(analysisErrorWithCleanupFailure(result.error, error));
			const cleanup = projectAnalysisError(error);
			return err(new ProviderAdapterError(error instanceof ProviderAdapterError ? error.providerId : "rea", "close_binary", {
				cause: error,
				remediationAction: cleanup.remediation.action,
				cleanup: {
					reason: cleanup.message,
					resources: error.cleanupResources
				},
				diagnostics: {
					cleanup_error: cleanup,
					partial_observation: jsonValueSchema.parse(result.value)
				}
			}));
		};
	})))();
}

//#endregion
//#region dist/application/DirectAnalysis.js
var NATIVE_INSPECTION_OPERATIONS, ARTIFACT_ANALYSIS_OPERATION_SET, runDirectAnalysis, runProviderAnalysis, runManagedProviderExecution, runManagedProviderAnalysis, runAnalysis, executeAnalysisTool, withProcessCancellation, prepareSnapshot, inspectBundleResourceInput, allowsSnapshotReplay, analysisProfileForRoute, nativeDispatchBindingProfile, providerIdentityForRoute, analysisProfileForEvidence, isWorkflowEvidenceTool, fileExists, cliError;
function init_DirectAnalysis() {
	return (init_DirectAnalysis = __esmMin((() => {
		init_logger();
		init_evidence();
		init_artifactToolContracts();
		init_managedToolContracts();
		init_evidenceErrors();
		init_analysisErrorProjection();
		init_callerPath();
		init_AnalysisSnapshotFiles();
		init_AnalysisSnapshotCache();
		init_BinaryTargetResolver();
		init_analysisSnapshot();
		init_ProfilelessNativeWorkflowSnapshot();
		init_result();
		init_AnalysisProvider();
		init_InvestigationProviders();
		init_WorkflowEvidence();
		init_artifactInspection();
		init_XrefsAddressResolution();
		init_analysisErrorCore();
		init_DirectAnalysisCleanup();
		init_BundleResourceSession();
		NATIVE_INSPECTION_OPERATIONS = new Set([
			"inspect_macho",
			"inspect_signature",
			"list_architectures",
			"inspect_plist",
			"demangle_swift"
		]);
		ARTIFACT_ANALYSIS_OPERATION_SET = new Set(ARTIFACT_ANALYSIS_OPERATIONS);
		runDirectAnalysis = async (dependencies, path, tool, arguments_, options = {}) => withProcessCancellation(options.signal, (signal) => runAnalysis(dependencies, path, tool, arguments_, {
			logger: options.logger ?? silentLogger,
			snapshotPath: options.snapshotPath,
			signal,
			...options.formatHint === undefined ? {} : { formatHint: options.formatHint },
			...options.architecture === undefined ? {} : { architecture: options.architecture },
			...options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint },
			...options.providerId === undefined ? {} : { providerId: options.providerId }
		}));
		runProviderAnalysis = async (dependencies, ...[path, tool, arguments_, logger = silentLogger, signal]) => {
			if (isManagedToolName(tool)) return runManagedProviderAnalysis(dependencies, path, tool, arguments_, signal);
			return withProcessCancellation(signal, (operationSignal) => runAnalysis(dependencies, path, tool, arguments_, {
				logger,
				snapshotPath: undefined,
				signal: operationSignal,
				...ARTIFACT_ANALYSIS_OPERATION_SET.has(tool) ? { createSession: dependencies.createArtifactBinarySession } : NATIVE_INSPECTION_OPERATIONS.has(tool) ? { createSession: dependencies.createNativeBinarySession } : {}
			}));
		};
		runManagedProviderExecution = async (dependencies, path, tool, signal, parameters = {}) => withProcessCancellation(signal, async (operationSignal) => {
			const session = await dependencies.createManagedBinarySession();
			return withSessionCleanup(session, async () => {
				const opened = await session.open(path, { signal: operationSignal });
				if (!opened.ok) return opened;
				return await session.execute(tool, parameters, { signal: operationSignal });
			}, managedAnalysisCleanupFailure);
		});
		runManagedProviderAnalysis = async (dependencies, path, tool, arguments_, signal) => {
			const execution = await runManagedProviderExecution(dependencies, path, tool, signal, arguments_);
			if (!execution.ok) return cliError(execution.error);
			const value = execution.value;
			return createAnalysisExecutionEvidence(tool, arguments_, value, "observed");
		};
		runAnalysis = async (dependencies, path, tool, arguments_, options) => {
			const { logger, signal, snapshotPath } = options;
			let session;
			if (options.createSession !== undefined) {
				session = await options.createSession();
			} else {
				const config = dependencies.readConfiguration();
				if (!config.ok) return cliError(config.error);
				session = await (tool === "inspect_native_dispatch_metadata" && snapshotPath === undefined ? dependencies.createNativeDispatchBinarySession : dependencies.createBinarySession)(config.value, logger);
			}
			return withSessionCleanup(session, async () => {
				let isDirectory = false;
				if (BUNDLE_RESOURCE_OPERATIONS.has(tool)) {
					const inspected = await inspectBundleResourceInput(path);
					if (!inspected.ok) return cliError(inspected.error);
					isDirectory = inspected.value;
				}
				if (BUNDLE_RESOURCE_OPERATIONS.has(tool) && isDirectory) {
					const opened = await session.openBundleResources(path, { signal });
					if (!opened.ok) return cliError(opened.error);
					const execution = await session.execute(tool, arguments_, { signal });
					if (!execution.ok) return cliError(execution.error);
					return createAnalysisExecutionEvidence(tool, arguments_, execution.value, "observed");
				}
				const prepared = await prepareSnapshot({
					path,
					snapshotPath,
					signal,
					...options.formatHint === undefined ? {} : { formatHint: options.formatHint },
					...options.architecture === undefined ? {} : { architecture: options.architecture },
					...options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint }
				});
				if (!prepared.ok) return cliError(prepared.error);
				const { snapshot } = prepared.value;
				let resolvedTarget;
				if (snapshot !== undefined && prepared.value.target !== undefined) {
					const preview = await session.previewTarget(prepared.value.target, {
						signal,
						snapshot,
						...options.formatHint === undefined ? {} : { formatHint: options.formatHint },
						...options.architecture === undefined ? {} : { architecture: options.architecture },
						...options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint },
						...options.providerId === undefined ? {} : { providerId: options.providerId }
					});
					if (!preview.ok) return cliError(preview.error);
					resolvedTarget = preview.value;
					const route = preview.value.route;
					const bindingProfile = route.profile ?? nativeDispatchBindingProfile(route, tool);
					const evidenceProfile = analysisProfileForRoute(route, tool);
					if (bindingProfile !== undefined && evidenceProfile !== undefined && !requiresNativeSourceAdmissionBeforeReplay(route.binding?.identity.id) && allowsSnapshotReplay(route, tool)) {
						const cached = snapshotEvidenceForQuery(snapshot, {
							target: preview.value.target,
							bindingProfile,
							operation: tool,
							parameters: arguments_,
							provider: isWorkflowEvidenceTool(tool) ? REA_WORKFLOW_PROVIDER : providerIdentityForRoute(route, tool),
							evidenceProfile
						});
						if (cached !== undefined) return cached;
					}
				}
				const openOptions = {
					signal,
					...options.formatHint === undefined ? {} : { formatHint: options.formatHint },
					...options.architecture === undefined ? {} : { architecture: options.architecture },
					...options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint },
					...snapshot === undefined ? {} : { snapshot },
					...options.providerId === undefined ? {} : { providerId: options.providerId }
				};
				const opened = resolvedTarget === undefined ? await session.open(path, openOptions) : await session.openResolvedTarget(resolvedTarget, openOptions);
				if (!opened.ok) return cliError(opened.error);
				const evidenceProfile = analysisProfileForEvidence(session, tool);
				const { output, evidence, cachePolicy } = await executeAnalysisTool({
					session,
					openedTarget: opened.value,
					tool,
					arguments: arguments_,
					signal,
					evidenceProfile
				});
				if (evidence !== undefined) {
					const recorded = session.recordEvidence(evidence);
					if (!recorded.ok) return cliError(recorded.error.retainPartialObservation(evidence));
					if (isWorkflowEvidenceTool(tool)) {
						const unknowns = recordWorkflowUnknowns({
							name: tool,
							result: evidence.normalized_result,
							evidenceId: evidence.evidence_id,
							recordUnknown: (unknown) => session.recordUnknown(unknown)
						});
						if (!unknowns.ok) return cliError(unknowns.error.retainPartialObservation(evidence));
					}
				}
				if (isWorkflowEvidenceTool(tool) && tool !== "trace_native_ui_action" && snapshotPath !== undefined && evidence !== undefined && session.allowsSnapshotReplay(tool)) {
					const workflowRecord = workflowSnapshotRecord(evidence, tool, evidenceProfile, cachePolicy);
					if (workflowRecord !== undefined) {
						const recorded = session.recordWorkflowSnapshot(workflowRecord);
						if (!recorded.ok) return cliError(recorded.error.retainPartialObservation(evidence));
					}
				}
				if (tool !== "trace_native_ui_action" && snapshotPath !== undefined && evidence !== undefined) {
					const snapshot = session.exportAnalysisSnapshot();
					if (!snapshot.ok) return cliError(snapshot.error.retainPartialObservation(evidence));
					const written = await session.writeAnalysisSnapshot(snapshot.value, snapshotPath, true);
					if (!written.ok) {
						const recovered = written.error instanceof EvidenceFileError && written.error.published !== undefined && (await session.closeWriteResources()).ok;
						if (!recovered) return cliError(written.error.retainPartialObservation(evidence));
					}
				}
				return output;
			}, directAnalysisCleanupFailure);
		};
		executeAnalysisTool = async (input) => {
			const { session, tool, signal, evidenceProfile } = input;
			if (tool === "analyze_function") {
				const { executeFunctionAnalysisEvidence } = await import("./main-C-d15_cS.js").then((n) => (n.o(), n.a));
				const result = await executeFunctionAnalysisEvidence(session, input.arguments, input.openedTarget, { signal });
				return result.ok ? {
					output: result.value,
					evidence: result.value
				} : { output: cliError(result.error) };
			}
			if (tool === "binary_overview" || tool === "inspect_native_api" || tool === "inspect_native_dispatch_metadata" || tool === "trace_feature" || tool === "trace_native_values" || tool === "trace_native_ui_action") {
				const { EnhancedTools } = await import("./main-C-d15_cS.js").then((n) => (n.c(), n.s));
				const result = await executeComposedWorkflow(session, (observed) => new EnhancedTools(observed).execute(tool, input.arguments, signal));
				if (!result.ok) return { output: cliError(result.error) };
				const evidence = createWorkflowEvidence({
					target: input.openedTarget,
					operation: tool,
					parameters: input.arguments,
					result: result.value.result,
					upstreamProfile: evidenceProfile,
					upstreamLimitations: result.value.limitations
				});
				return {
					output: evidence,
					evidence,
					...result.value.cachePolicy === undefined ? {} : { cachePolicy: result.value.cachePolicy }
				};
			}
			let result = await session.execute(tool, input.arguments, { signal });
			if (tool === "xrefs" && typeof input.arguments.address === "string" && !result.ok && result.error instanceof AnalysisInputError && !result.error.cleanupIncomplete && result.error.issues.length > 0 && result.error.issues.every(({ path, reason }) => path.length === 1 && path[0] === "address" && reason === "invalid_format")) {
				const address = await resolveXrefsAddress(session, input.arguments.address, signal);
				if (!address.ok) return { output: cliError(address.error) };
				if (address.value !== input.arguments.address) result = await session.execute(tool, {
					...input.arguments,
					address: address.value
				}, { signal });
			}
			if (!result.ok) return { output: cliError(result.error) };
			const evidence = createEvidence(result.value.subject === undefined ? input.openedTarget : result.value.subject ?? undefined, result.value.provider, {
				operation: tool,
				parameters: input.arguments,
				result: result.value.result,
				...result.value.analysisProfile === undefined ? {} : { analysisProfile: result.value.analysisProfile },
				rawResult: result.value.rawResult,
				limitations: result.value.limitations,
				...result.value.relationshipCoverage === undefined ? {} : { relationshipCoverage: result.value.relationshipCoverage },
				locations: result.value.locations,
				evidenceLinks: tool === "inspect_artifact" ? artifactInspectionResultSchema.parse(result.value.result).evidence_links : []
			});
			return {
				output: evidence,
				evidence
			};
		};
		withProcessCancellation = async (suppliedSignal, operation) => {
			if (suppliedSignal !== undefined) return operation(suppliedSignal);
			const controller = new AbortController();
			const cancel = () => controller.abort();
			process.on("SIGINT", cancel);
			process.on("SIGTERM", cancel);
			try {
				return await operation(controller.signal);
			} finally {
				process.off("SIGINT", cancel);
				process.off("SIGTERM", cancel);
			}
		};
		prepareSnapshot = async (options) => {
			const { path, snapshotPath } = options;
			if (snapshotPath === undefined || !await fileExists(snapshotPath)) return ok({});
			const loaded = await readAnalysisSnapshot(snapshotPath, options.signal);
			if (!loaded.ok) return loaded;
			const target = await parseBinaryTarget(path, {
				signal: options.signal,
				...options.formatHint === undefined ? {} : { formatHint: options.formatHint },
				...options.architecture === undefined ? {} : { architecture: options.architecture },
				...options.entryPoint === undefined ? {} : { entryPoint: options.entryPoint }
			});
			if (!target.ok) return target;
			if (!snapshotMatchesTarget(loaded.value.target, target.value)) return err(new EvidenceIntegrityError("Analysis snapshot target does not match the requested binary"));
			return ok({
				snapshot: loaded.value,
				target: target.value
			});
		};
		inspectBundleResourceInput = async (path) => {
			const callerPath = absoluteCallerPath(path);
			try {
				return ok((await stat(callerPath)).isDirectory());
			} catch (cause) {
				const failure = classifyBinaryTargetFilesystemFailure(callerPath, cause);
				if (failure !== undefined) return err(failure);
				throw cause;
			}
		};
		allowsSnapshotReplay = (route, tool) => {
			if (tool === "trace_native_ui_action") return false;
			const descriptor = route.capabilities?.get(tool);
			return descriptor === undefined ? ![...route.capabilities?.values() ?? []].some(({ cachePolicy }) => cachePolicy === "live") : descriptor.cachePolicy !== "live";
		};
		analysisProfileForRoute = (route, tool) => {
			const profile = route.profile;
			const nativeDispatchProfile = profile === null || profile === undefined ? nativeDispatchBindingProfile(route, tool) : undefined;
			if (profile === null || profile === undefined) {
				if (nativeDispatchProfile === undefined) return undefined;
				return isWorkflowEvidenceTool(tool) ? workflowAnalysisProfile(nativeDispatchProfile, tool) : nativeDispatchProfile;
			}
			if (isWorkflowEvidenceTool(tool)) return workflowAnalysisProfile(profile, tool);
			const provider = providerIdentityForRoute(route, tool);
			return provider.id === profile.provider.id ? profile : undefined;
		};
		nativeDispatchBindingProfile = (route, operation) => {
			if (operation !== "inspect_native_dispatch_metadata") return undefined;
			return profilelessNativeDispatchProfile(route);
		};
		providerIdentityForRoute = (route, operation) => route.capabilities?.get(operation)?.provider ?? route.identity;
		analysisProfileForEvidence = (session, tool) => {
			if (!isWorkflowEvidenceTool(tool)) return session.analysisProfile(tool);
			return session.analysisProfile() ?? session.analysisProfile(tool);
		};
		isWorkflowEvidenceTool = (tool) => tool === "binary_overview" || tool === "inspect_native_api" || tool === "inspect_native_dispatch_metadata" || tool === "trace_feature" || tool === "trace_native_values" || tool === "trace_native_ui_action";
		fileExists = async (path) => {
			try {
				await access(path);
				return true;
			} catch (cause) {
				if (typeof cause === "object" && cause !== null && "code" in cause && cause.code === "ENOENT") return false;
				throw cause;
			}
		};
		cliError = (error) => ({
			error: "Analysis failed",
			...projectAnalysisError(error)
		});
	})))();
}

//#endregion
init_DirectAnalysis();
export { runDirectAnalysis, runManagedProviderExecution, runProviderAnalysis };