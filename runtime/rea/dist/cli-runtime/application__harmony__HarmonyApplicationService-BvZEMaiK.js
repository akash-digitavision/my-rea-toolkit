import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { harmonyApplicationProjectionInputSchema, init_harmonyApplication, projectHarmonyApplication } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { HARMONY_APPLICATION_PROVIDER, init_InvestigationProviders } from "./InvestigationProviders-CfExhO9k.js";
import { init_InventoryProjectionEvidence, projectInventoryEvidence } from "./InventoryProjectionEvidence-BdHDfaoH.js";

//#region dist/application/harmony/HarmonyApplicationService.js
var OPERATION, projectHarmonyApplicationEvidence;
function init_HarmonyApplicationService() {
	return (init_HarmonyApplicationService = __esmMin((() => {
		init_harmonyApplication();
		init_InvestigationProviders();
		init_InventoryProjectionEvidence();
		OPERATION = "project_harmony_application_graph";
		projectHarmonyApplicationEvidence = (rawInput) => {
			return projectInventoryEvidence({
				rawInput,
				schema: harmonyApplicationProjectionInputSchema,
				project: projectHarmonyApplication,
				operation: OPERATION,
				predicateType: "rea.harmony-application-graph",
				provider: HARMONY_APPLICATION_PROVIDER,
				subjectFormat: (first) => first.subject?.format ?? "unknown",
				protocolError: "HarmonyOS application projection produced an invalid result"
			});
		};
	})))();
}

//#endregion
init_HarmonyApplicationService();
export { projectHarmonyApplicationEvidence };