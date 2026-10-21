import { __esmMin, __exportAll } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisInputError, immutableJsonSnapshotMember, init_analysisErrorCore, init_immutableJson } from "./errorSchemas-BjJIu7zO.js";
import { browserScenarioCaptureSchema, err, immutableEvidence, init_browserScenarioCapture, init_evidence, init_inputIssueProjection, init_result, init_webNetworkCapture, ok, projectInputIssues, webNetworkCaptureSchema } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { analysisViewResultSchema, init_analysisView, init_recordedResponseBody, init_scenarioCaptureRecords, init_webNetworkRouteTemplates, readRecordedRequestLine, readRecordedResponseBody, scenarioCaptureRecords } from "./analysisView-C5VMVK4R.js";
import { z } from "zod";

//#region dist/application/environment/environmentSource.js
var environmentSource_exports = /* @__PURE__ */ __exportAll({ loadEnvironmentSource: () => loadEnvironmentSource });
var ENVIRONMENT_SERVE_OPERATION, REPLAY_BODY_LIMIT_BYTES, inputError, parseEvidenceFile, recordedExchange, parseManifestEvidence, parseCaptureEvidence, indexExchanges, loadEnvironmentSource;
function init_environmentSource() {
	return (init_environmentSource = __esmMin((() => {
		init_analysisView();
		init_scenarioCaptureRecords();
		init_recordedResponseBody();
		init_webNetworkRouteTemplates();
		init_browserScenarioCapture();
		init_analysisErrorCore();
		init_evidence();
		init_inputIssueProjection();
		init_immutableJson();
		init_result();
		init_webNetworkCapture();
		ENVIRONMENT_SERVE_OPERATION = "environment-serve";
		REPLAY_BODY_LIMIT_BYTES = 256 * 1024;
		inputError = (operation, issues, userMessage) => new AnalysisInputError(operation, userMessage === undefined ? undefined : { userMessage }, issues);
		parseEvidenceFile = (operation, role, value) => {
			try {
				for (const key of [
					"parameters",
					"raw_result",
					"normalized_result"
				]) immutableJsonSnapshotMember(value, key);
				return ok(immutableEvidence(value));
			} catch (cause) {
				if (!(cause instanceof z.ZodError)) throw cause;
				return err(inputError(operation, projectInputIssues(cause.issues, value).map((issue) => ({
					...issue,
					path: [role, ...issue.path]
				})), `The ${role} file is not authenticated REA Evidence JSON.`));
			}
		};
		recordedExchange = (record) => {
			const line = readRecordedRequestLine(record.reported, true, () => true);
			if (line === null || line.kind !== "line") return undefined;
			return {
				ordinal: record.ordinal,
				path: line.path,
				query: line.query === undefined || line.query === "" ? null : line.query,
				status: line.status,
				contentType: line.rawMime === "" ? null : line.rawMime,
				...readRecordedResponseBody(record, REPLAY_BODY_LIMIT_BYTES)
			};
		};
		parseManifestEvidence = (operation, value) => {
			const evidence = parseEvidenceFile(operation, "manifest", value);
			if (!evidence.ok) return evidence;
			const view = analysisViewResultSchema.safeParse(evidence.value.normalized_result);
			if (evidence.value.operation !== "inspect_analysis_view" || !view.success || view.data.kind !== "environment-manifest") return err(inputError(operation, [{
				path: [
					"manifest",
					"normalized_result",
					"kind"
				],
				reason: "invalid_value",
				expected: "environment-manifest",
				message: "The manifest file must be inspect_analysis_view Evidence of kind environment-manifest."
			}], "The manifest file is not environment-manifest view Evidence."));
			return ok({
				manifest: view.data,
				evidenceId: evidence.value.evidence_id
			});
		};
		parseCaptureEvidence = (operation, value) => {
			const evidence = parseEvidenceFile(operation, "evidence", value);
			if (!evidence.ok) return evidence;
			const { evidence_id: evidenceId } = evidence.value;
			const normalized = immutableJsonSnapshotMember(evidence.value, "normalized_result");
			if (evidence.value.operation === "capture_browser_scenario") {
				const scenario = browserScenarioCaptureSchema.safeParse(normalized);
				const definition = z.object({ scenario_sha256: z.string() }).safeParse(evidence.value.parameters);
				if (scenario.success) return ok({
					records: scenarioCaptureRecords(scenario.data, "replay").records,
					evidenceId,
					captureKind: "browser-scenario",
					captureSha256: definition.success ? definition.data.scenario_sha256 : null
				});
			} else if (evidence.value.operation === "inspect_web_network_capture") {
				const records = immutableJsonSnapshotMember(normalized, "records");
				if (Array.isArray(records)) for (let index = 0; index < records.length; index += 1) {
					const record = immutableJsonSnapshotMember(records, String(index));
					immutableJsonSnapshotMember(record, "reported");
				}
				const capture = webNetworkCaptureSchema.safeParse(normalized);
				if (capture.success) {
					if (capture.data.format !== "har") return err(inputError(operation, [{
						path: [
							"evidence",
							"normalized_result",
							"format"
						],
						reason: "invalid_value",
						expected: "har",
						message: `Agent environments replay HAR captures; this capture's format is ${capture.data.format}.`
					}], "The evidence file is not a HAR capture."));
					return ok({
						records: capture.data.records,
						evidenceId,
						captureKind: "web-network-capture",
						captureSha256: capture.data.artifact.sha256
					});
				}
			}
			return err(inputError(operation, [{
				path: ["evidence", "operation"],
				reason: "invalid_value",
				expected: "inspect_web_network_capture or capture_browser_scenario",
				message: "The evidence file must be complete inspect_web_network_capture or capture_browser_scenario Evidence."
			}], "The evidence file is not web network capture or browser scenario Evidence."));
		};
		indexExchanges = (manifest, records) => {
			const byOrdinal = new Map(records.map((record) => [record.ordinal, record]));
			const exchanges = new Map();
			for (const tool of manifest.tools) for (const ordinal of tool.record_ordinals) {
				if (exchanges.has(ordinal)) continue;
				const record = byOrdinal.get(ordinal);
				const exchange = record === undefined ? undefined : recordedExchange(record);
				if (exchange !== undefined) exchanges.set(ordinal, exchange);
			}
			return exchanges;
		};
		loadEnvironmentSource = (manifestValue, evidenceValue, operation = ENVIRONMENT_SERVE_OPERATION) => {
			const manifest = parseManifestEvidence(operation, manifestValue);
			if (!manifest.ok) return manifest;
			const capture = parseCaptureEvidence(operation, evidenceValue);
			if (!capture.ok) return capture;
			const parentId = manifest.value.manifest.parent_evidence_id;
			if (parentId !== capture.value.evidenceId) return err(inputError(operation, [{
				path: ["evidence", "evidence_id"],
				reason: "invalid_value",
				expected: parentId,
				message: `The manifest cites parent Evidence ${parentId}; the evidence file is ${capture.value.evidenceId}.`
			}], "The manifest was projected from a different capture than the supplied evidence file."));
			return ok({
				manifest: manifest.value.manifest,
				manifestEvidenceId: manifest.value.evidenceId,
				evidenceId: capture.value.evidenceId,
				captureKind: capture.value.captureKind,
				captureSha256: capture.value.captureSha256,
				exchanges: indexExchanges(manifest.value.manifest, capture.value.records)
			});
		};
	})))();
}

//#endregion
export { ENVIRONMENT_SERVE_OPERATION, REPLAY_BODY_LIMIT_BYTES, environmentSource_exports, init_environmentSource };