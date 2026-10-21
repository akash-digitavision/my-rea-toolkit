import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { z } from "zod";

//#region dist/domain/digests.js
var SHA256_PATTERN, digestSchema, prefixedDigestSchema, isDigest;
function init_digests() {
	return (init_digests = __esmMin((() => {
		SHA256_PATTERN = /^[a-f0-9]{64}$/u;
		digestSchema = z.string().regex(SHA256_PATTERN);
		prefixedDigestSchema = (prefix) => z.string().regex(new RegExp(`^${prefix}_[a-f0-9]{64}$`, "u"), `Expected a ${prefix}_ prefixed lowercase sha256 digest`);
		isDigest = (value) => typeof value === "string" && SHA256_PATTERN.test(value);
	})))();
}

//#endregion
//#region dist/domain/artifactIntegrity.js
var sha256, md5, artifactIntegrityClaimSchema, artifactSha256PairSchema, artifactMd5PairSchema, artifactIntegrityPair, artifactIntegrityPairOf, artifactIntegrityDetails, projectArtifactIntegrityDetails;
function init_artifactIntegrity() {
	return (init_artifactIntegrity = __esmMin((() => {
		sha256 = z.string().regex(/^[a-f0-9]{64}$/u);
		md5 = z.string().regex(/^[a-f0-9]{32}$/u);
		artifactIntegrityClaimSchema = z.discriminatedUnion("algorithm", [z.strictObject({
			algorithm: z.literal("sha256"),
			digest: sha256
		}), z.strictObject({
			algorithm: z.literal("md5"),
			digest: md5
		})]);
		artifactSha256PairSchema = z.object({
			declared_sha256: sha256,
			observed_sha256: sha256
		});
		artifactMd5PairSchema = z.object({
			algorithm: z.literal("md5"),
			declared_md5: md5,
			observed_md5: md5
		});
		artifactIntegrityPair = (claim, observed) => claim.algorithm === "sha256" ? {
			declared_sha256: claim.digest,
			observed_sha256: observed
		} : {
			algorithm: "md5",
			declared_md5: claim.digest,
			observed_md5: observed
		};
		artifactIntegrityPairOf = (pair) => "declared_sha256" in pair ? {
			declared_sha256: pair.declared_sha256,
			observed_sha256: pair.observed_sha256
		} : {
			algorithm: pair.algorithm,
			declared_md5: pair.declared_md5,
			observed_md5: pair.observed_md5
		};
		artifactIntegrityDetails = (logicalPath, claim, observed, unpacked) => ({
			logicalPath,
			unpacked,
			...claim?.algorithm === "md5" ? {
				algorithm: "md5",
				declaredMd5: claim.digest,
				calculatedMd5: observed
			} : {
				declaredSha256: claim?.digest ?? null,
				calculatedSha256: observed
			}
		});
		projectArtifactIntegrityDetails = (details) => ({
			logical_path: details.logicalPath,
			..."declaredSha256" in details ? {
				declared_sha256: details.declaredSha256,
				calculated_sha256: details.calculatedSha256
			} : {
				algorithm: details.algorithm,
				declared_md5: details.declaredMd5,
				calculated_md5: details.calculatedMd5
			},
			unpacked: details.unpacked
		});
	})))();
}

//#endregion
//#region dist/domain/providerOperationHealth.js
var PROVIDER_OPERATION_STATES, PROVIDER_RETRY_ACTIONS, PROVIDER_FAILURE_STAGES, providerRetryAction, sharedProviderFailureStage;
function init_providerOperationHealth() {
	return (init_providerOperationHealth = __esmMin((() => {
		PROVIDER_OPERATION_STATES = [
			"idle",
			"busy",
			"exited",
			"unreachable",
			"not_started",
			"unknown"
		];
		PROVIDER_RETRY_ACTIONS = [
			"retry",
			"wait",
			"restart_provider",
			"unknown"
		];
		PROVIDER_FAILURE_STAGES = [
			"launch",
			"connection",
			"analysis",
			"decompilation",
			"unknown"
		];
		providerRetryAction = (state, startupFailure = false) => {
			if (state === "idle") return null;
			if (startupFailure && state === "exited") return "retry";
			switch (state) {
				case "busy": return "wait";
				case "exited":
				case "unreachable": return "restart_provider";
				case "not_started": return "retry";
				case "unknown": return "unknown";
			}
		};
		sharedProviderFailureStage = (requests) => {
			const first = requests[0]?.stage;
			if (first === undefined) return null;
			return requests.every((request) => request.stage === first) ? first : "unknown";
		};
	})))();
}

//#endregion
export { isDigest as _, providerRetryAction as a, artifactIntegrityDetails as c, artifactMd5PairSchema as d, artifactSha256PairSchema as f, init_digests as g, digestSchema as h, init_providerOperationHealth as i, artifactIntegrityPair as l, projectArtifactIntegrityDetails as m, PROVIDER_OPERATION_STATES as n, sharedProviderFailureStage as o, init_artifactIntegrity as p, PROVIDER_RETRY_ACTIONS as r, artifactIntegrityClaimSchema as s, PROVIDER_FAILURE_STAGES as t, artifactIntegrityPairOf as u, prefixedDigestSchema as v };