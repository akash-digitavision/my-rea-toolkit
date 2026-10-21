import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { appleApplicationProjectionInputSchema, init_appleApplication, projectAppleApplication } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { APPLE_APPLICATION_PROVIDER, init_InvestigationProviders } from "./InvestigationProviders-CfExhO9k.js";
import { init_InventoryProjectionEvidence, projectInventoryEvidence } from "./InventoryProjectionEvidence-BdHDfaoH.js";

//#region dist/application/apple/AppleApplicationService.js
var OPERATION, projectAppleApplicationEvidence;
function init_AppleApplicationService() {
	return (init_AppleApplicationService = __esmMin((() => {
		init_appleApplication();
		init_InvestigationProviders();
		init_InventoryProjectionEvidence();
		OPERATION = "project_apple_application_graph";
		projectAppleApplicationEvidence = (rawInput) => {
			return projectInventoryEvidence({
				rawInput,
				schema: appleApplicationProjectionInputSchema,
				project: projectAppleApplication,
				operation: OPERATION,
				predicateType: "rea.apple-application-graph",
				provider: APPLE_APPLICATION_PROVIDER,
				subjectFormat: (first) => first.subject?.format ?? "unknown",
				protocolError: "Apple application projection produced an invalid result"
			});
		};
	})))();
}

//#endregion
init_AppleApplicationService();
export { projectAppleApplicationEvidence };