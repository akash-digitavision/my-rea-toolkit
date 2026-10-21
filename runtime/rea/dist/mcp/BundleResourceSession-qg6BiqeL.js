import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, n as init_analysisErrorBase, o as ok, t as AnalysisError } from "./analysisErrorBase-C1inc3JA.js";
import { a as AnalysisCapabilityUnavailableError, f as init_analysisErrorCore } from "./analysisErrorCore-BMJXbfFY.js";
import { i as init_providerCleanupError, n as init_analysisErrorCleanup, r as ProviderCleanupError, t as analysisErrorWithCleanupFailure } from "./analysisErrorCleanup-LFIV2yDc.js";

//#region dist/providers/AnalysisClientCleanup.js
var closeAnalysisClient;
function init_AnalysisClientCleanup() {
	return (init_AnalysisClientCleanup = __esmMin((() => {
		init_providerCleanupError();
		init_result();
		init_analysisErrorBase();
		closeAnalysisClient = async (client, providerId, options = {}) => {
			try {
				const result = await client.close(options);
				if (!result.ok) options.onCleanupFailure?.(result.error);
				return result;
			} catch (cause) {
				const failure = cause instanceof AnalysisError && cause.cleanupIncomplete ? cause : new ProviderCleanupError(providerId, ["provider-client"], { reason: "provider client close rejected unexpectedly" }, { cause });
				options.onCleanupFailure?.(failure);
				return err(failure);
			}
		};
	})))();
}

//#endregion
//#region dist/application/binary/BundleResourceSession.js
var BUNDLE_NATIVE_RESOURCE_OPERATIONS, BUNDLE_ARTIFACT_RESOURCE_OPERATIONS, BUNDLE_RESOURCE_OPERATIONS, combineBundleResourceClients;
function init_BundleResourceSession() {
	return (init_BundleResourceSession = __esmMin((() => {
		init_analysisErrorCore();
		init_analysisErrorCleanup();
		init_result();
		init_AnalysisClientCleanup();
		BUNDLE_NATIVE_RESOURCE_OPERATIONS = new Set(["inspect_plist"]);
		BUNDLE_ARTIFACT_RESOURCE_OPERATIONS = new Set([
			"decode_interface_builder",
			"inspect_asset_catalog",
			"inspect_keyed_archive"
		]);
		BUNDLE_RESOURCE_OPERATIONS = new Set([...BUNDLE_NATIVE_RESOURCE_OPERATIONS, ...BUNDLE_ARTIFACT_RESOURCE_OPERATIONS]);
		combineBundleResourceClients = (artifactClient, nativeClient) => ({
			execute: (operation, parameters, options) => {
				if (operation === "health") return artifactClient.execute(operation, parameters, options);
				if (!BUNDLE_RESOURCE_OPERATIONS.has(operation)) return Promise.resolve(err(new AnalysisCapabilityUnavailableError("bundle-resources", operation, "This session provides read-only app resource inspection only.")));
				return BUNDLE_NATIVE_RESOURCE_OPERATIONS.has(operation) ? nativeClient.execute(operation, parameters, options) : artifactClient.execute(operation, parameters, options);
			},
			close: async (options) => {
				const [artifact, native] = await Promise.all([closeAnalysisClient(artifactClient, "bundle-resources", options), closeAnalysisClient(nativeClient, "bundle-resources", options)]);
				if (!artifact.ok && !native.ok) return err(analysisErrorWithCleanupFailure(artifact.error, native.error, "close_binary"));
				if (!artifact.ok) return artifact;
				if (!native.ok) return native;
				return ok(null);
			}
		});
	})))();
}

//#endregion
export { init_BundleResourceSession as a, combineBundleResourceClients as i, BUNDLE_NATIVE_RESOURCE_OPERATIONS as n, closeAnalysisClient as o, BUNDLE_RESOURCE_OPERATIONS as r, init_AnalysisClientCleanup as s, BUNDLE_ARTIFACT_RESOURCE_OPERATIONS as t };