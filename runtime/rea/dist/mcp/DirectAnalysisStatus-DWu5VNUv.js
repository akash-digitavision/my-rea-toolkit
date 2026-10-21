import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { E as init_CurrentEntrypointPath, T as CURRENT_ENTRYPOINT_PATH, i as sqliteDatabaseCapability, n as init_serverIdentity, r as init_SqliteDatabaseCapability, t as createServerIdentity } from "./serverIdentity-8PwecdEY.js";
import { co as init_toolOutputSchemaPrimitives, lo as providerCapabilitySet } from "./toolOutputSchemaGroups-D--zoCY3.js";
import { n as projectAnalysisError, t as init_analysisErrorProjection } from "./analysisErrorProjection-DPMozIkD.js";
import { n as init_jsonValue, r as jsonObjectSchema } from "./jsonValue-sVQvKuTs.js";
import { n as init_logger, r as silentLogger } from "./logger-DJs_OLxk.js";
import { n as init_BinarySessionStatus, r as providerCapabilitySets } from "./BinarySessionStatus-DqHvnQth.js";

//#region dist/application/DirectAnalysisStatus.js
var runSessionStatus;
function init_DirectAnalysisStatus() {
	return (init_DirectAnalysisStatus = __esmMin((() => {
		init_analysisErrorProjection();
		init_jsonValue();
		init_serverIdentity();
		init_logger();
		init_toolOutputSchemaPrimitives();
		init_BinarySessionStatus();
		init_SqliteDatabaseCapability();
		init_CurrentEntrypointPath();
		runSessionStatus = async (dependencies, logger = silentLogger) => {
			const config = dependencies.readConfiguration();
			if (!config.ok) return { error: projectAnalysisError(config.error) };
			const session = await dependencies.createBinarySession(config.value, logger);
			try {
				const status = jsonObjectSchema.parse(await session.status());
				return {
					...status,
					capabilities: [...providerCapabilitySet.array().parse(status.capabilities), ...providerCapabilitySets([sqliteDatabaseCapability(process.versions.node)])],
					server_identity: createServerIdentity({
						startedAt: new Date().toISOString(),
						commandPath: CURRENT_ENTRYPOINT_PATH
					})
				};
			} finally {
				await session.close();
			}
		};
	})))();
}

//#endregion
init_DirectAnalysisStatus();
export { runSessionStatus };