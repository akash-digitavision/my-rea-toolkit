import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, o as ok } from "./analysisErrorBase-C1inc3JA.js";
import { an as init_residualUnknown, on as recordUnknownInputSchema } from "./toolOutputSchemaGroups-D--zoCY3.js";
import { i as init_unknownRegistryError, r as UnknownRegistryError } from "./analysisErrorProjection-DPMozIkD.js";
import { Gt as analysisProfileSchema, Nt as init_evidence, Ot as createEvidence, Yt as init_analysisProfile, qt as committedProviderSchema } from "./nativeValueTrace-Cm--GSDT.js";
import { D as workflowAnalysisProfile, E as init_InvestigationProviders, S as REA_WORKFLOW_PROVIDER } from "./godotPckFormat-Bh8AriRi.js";
import { a as sourceLimitationKey, i as renderSourceLimitations, r as init_SourceLimitations } from "./ProcedureAddressResolution-DqULHRa1.js";

//#region dist/application/investigation/WorkflowUnknown.js
var workflowUnknownInput;
function init_WorkflowUnknown() {
	return (init_WorkflowUnknown = __esmMin((() => {
		init_residualUnknown();
		init_result();
		init_unknownRegistryError();
		workflowUnknownInput = (evidenceId, input) => {
			const question = recordUnknownInputSchema.shape.question.safeParse(input.question);
			if (!question.success) return err(new UnknownRegistryError("invalid-transition", { cause: question.error }));
			return ok({
				...input,
				question: `${question.data} (Evidence ${evidenceId})`,
				supporting_evidence_ids: [evidenceId],
				contradicting_evidence_ids: []
			});
		};
	})))();
}

//#endregion
//#region dist/application/WorkflowEvidence.js
var executeComposedWorkflow, createWorkflowEvidence, batchProcedureLocations, workflowSnapshotRecord, recordWorkflowUnknowns;
function init_WorkflowEvidence() {
	return (init_WorkflowEvidence = __esmMin((() => {
		init_InvestigationProviders();
		init_result();
		init_analysisProfile();
		init_evidence();
		init_unknownRegistryError();
		init_WorkflowUnknown();
		init_SourceLimitations();
		executeComposedWorkflow = async (analysis, execute) => {
			const limitations = new Map();
			let cachePolicy;
			const result = await execute({ execute: async (operation, parameters, options) => {
				const execution = await analysis.execute(operation, parameters, options);
				if (execution.ok && execution.value.cachePolicy === "live") cachePolicy = "live";
				if (execution.ok) for (const limitation of execution.value.limitations) {
					const fact = {
						provider: execution.value.provider,
						operation,
						limitation
					};
					limitations.set(sourceLimitationKey(fact), fact);
				}
				return execution;
			} });
			if (!result.ok) return result;
			return ok({
				result: result.value,
				limitations: renderSourceLimitations([...limitations.values()]),
				...cachePolicy === undefined ? {} : { cachePolicy }
			});
		};
		createWorkflowEvidence = (input) => createEvidence(input.target, REA_WORKFLOW_PROVIDER, {
			operation: input.operation,
			parameters: input.parameters,
			result: input.result,
			...input.upstreamProfile === undefined ? {} : { analysisProfile: workflowAnalysisProfile(input.upstreamProfile, input.operation) },
			confidence: "derived",
			limitations: ["Derived by an REA composed workflow.", ...input.upstreamLimitations],
			...input.operation === "batch_decompile" ? { locations: batchProcedureLocations(input.result) } : {}
		});
		batchProcedureLocations = (result) => {
			if (result === null || typeof result !== "object" || Array.isArray(result) || !Array.isArray(result.items)) return [];
			const addresses = new Set();
			for (const item of result.items) {
				if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
				const procedure = item.procedure;
				if (procedure !== null && typeof procedure === "object" && !Array.isArray(procedure) && procedure.status === "resolved" && typeof procedure.address === "string") addresses.add(procedure.address);
			}
			return [...addresses].map((address) => ({
				kind: "address",
				address
			}));
		};
		workflowSnapshotRecord = (evidence, operation, bindingProfile, cachePolicy) => {
			if (evidence.analysis_profile === null || bindingProfile === undefined || cachePolicy === "live") return undefined;
			return {
				operation,
				bindingProfile,
				parameters: evidence.parameters,
				execution: {
					result: evidence.normalized_result,
					rawResult: evidence.raw_result,
					provider: committedProviderSchema.parse(evidence.provider),
					analysisProfile: analysisProfileSchema.parse(evidence.analysis_profile),
					limitations: evidence.limitations,
					locations: evidence.locations,
					subject: evidence.subject === null ? null : {
						path: evidence.subject.local_path,
						sha256: evidence.subject.digest.sha256,
						format: evidence.subject.format,
						...evidence.subject.architecture === null ? {} : { architecture: evidence.subject.architecture }
					}
				}
			};
		};
		recordWorkflowUnknowns = ({ name, result, evidenceId, recordUnknown }) => {
			if (![
				"trace_feature",
				"trace_call_path",
				"inspect_native_api"
			].includes(name) || recordUnknown === undefined || typeof result !== "object" || result === null || Array.isArray(result) || !Array.isArray(result.residual_unknowns)) return {
				ok: true,
				value: null
			};
			for (const question of result.residual_unknowns) {
				if (typeof question !== "string") continue;
				const input = workflowUnknownInput(evidenceId, {
					question,
					severity: "medium",
					domain: name === "inspect_native_api" ? "native-api" : "control-flow",
					required_authority: "shipped-artifact",
					required_confidence: "observed",
					required_environment: null,
					recommended_probes: [{
						operation: name,
						rationale: name === "inspect_native_api" ? "Confirm the unsupported boundary with a capable provider or ABI probe." : "Continue with a focused query or another available provider."
					}],
					relationships: []
				});
				if (!input.ok) return input;
				const recorded = recordUnknown(input.value);
				if (!recorded.ok && !(recorded.error instanceof UnknownRegistryError && recorded.error.reason === "already-exists")) return recorded;
			}
			return {
				ok: true,
				value: null
			};
		};
	})))();
}

//#endregion
export { workflowSnapshotRecord as a, recordWorkflowUnknowns as i, executeComposedWorkflow as n, init_WorkflowUnknown as o, init_WorkflowEvidence as r, workflowUnknownInput as s, createWorkflowEvidence as t };