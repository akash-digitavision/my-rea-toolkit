import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, o as ok } from "./analysisErrorBase-C1inc3JA.js";
import { Jt as createAnalysisProfile, Yt as init_analysisProfile } from "./nativeValueTrace-Cm--GSDT.js";
import { posix, win32 } from "node:path";

//#region dist/domain/dosMz.js
var dosMzImageByteLength, observeMzWindowsHeader, windowsHeaderSignature, parseDosMzHeader, validateRelocations;
function init_dosMz() {
	return (init_dosMz = __esmMin((() => {
		init_result();
		dosMzImageByteLength = (bytes) => {
			if (bytes.length < 28 || bytes.toString("latin1", 0, 2) !== "MZ") return err("invalid or truncated DOS MZ header");
			const lastPageBytes = bytes.readUInt16LE(2);
			const pages = bytes.readUInt16LE(4);
			if (pages === 0 || lastPageBytes > 511) return err("invalid DOS MZ page count or final-page size");
			return ok((pages - 1) * 512 + (lastPageBytes === 0 ? 512 : lastPageBytes));
		};
		observeMzWindowsHeader = (bytes, fileSize = bytes.length, signatureAtOffset) => {
			if (bytes.length < 64) return fileSize >= 64 ? { state: "header-needed" } : { state: "absent" };
			const headerBytes = bytes.readUInt16LE(8) * 16;
			const relocationCount = bytes.readUInt16LE(6);
			const tableStart = bytes.readUInt16LE(24);
			if (headerBytes !== 0 && relocationCount > 0 && tableStart < 64 && tableStart + relocationCount * 4 > 60) return { state: "absent" };
			const offset = bytes.readUInt32LE(60);
			if (offset === 0) return { state: "absent" };
			const inlineSignature = offset < bytes.length ? bytes.subarray(offset, Math.min(offset + 4, bytes.length)) : undefined;
			const available = signatureAtOffset ?? inlineSignature;
			const signature = windowsHeaderSignature(available);
			if (headerBytes === 0 || headerBytes >= 64) return {
				state: "declared",
				offset,
				signature
			};
			if (signature !== "other" && signature !== "unobserved") return {
				state: "declared",
				offset,
				signature
			};
			if (signature === "other") return { state: "absent" };
			const observedPePrefix = available !== undefined && available.length >= 2 && available.toString("latin1", 0, 2) === "PE";
			if (fileSize - offset < (observedPePrefix ? 4 : 2)) return { state: "absent" };
			return {
				state: "signature-needed",
				offset
			};
		};
		windowsHeaderSignature = (bytes) => {
			if (bytes === undefined || bytes.length < 2) return "unobserved";
			const first = bytes[0];
			const second = bytes[1];
			if (first === 78 && second === 69) return "NE";
			if (first === 76 && second === 69) return "LE";
			if (first === 76 && second === 88) return "LX";
			if (first !== 80 || second !== 69) return "other";
			if (bytes.length < 4) return "unobserved";
			return bytes[2] === 0 && bytes[3] === 0 ? "PE" : "other";
		};
		parseDosMzHeader = (bytes, fileSize = bytes.length, signatureAtOffset) => {
			if (bytes.length < 28 || bytes.toString("latin1", 0, 2) !== "MZ") return err("invalid or truncated DOS MZ header");
			if (!Number.isSafeInteger(fileSize) || fileSize < bytes.length) return err("invalid DOS MZ file length");
			const windowsHeader = observeMzWindowsHeader(bytes, fileSize, signatureAtOffset);
			if (windowsHeader.state === "declared") return err("MZ declares a Windows new header; it is not a DOS-only image");
			if (windowsHeader.state === "signature-needed") return err("MZ Windows new-header signature is outside the bounded prefix");
			const extent = dosMzImageByteLength(bytes);
			if (!extent.ok) return extent;
			const imageBytes = extent.value;
			const headerBytes = bytes.readUInt16LE(8) * 16;
			if (headerBytes < 28 || headerBytes >= imageBytes) return err("invalid DOS MZ header size or empty load module");
			if (imageBytes > fileSize) return err("truncated DOS MZ load module");
			const relocationCount = bytes.readUInt16LE(6);
			const relocationTableOffset = bytes.readUInt16LE(24);
			const tableEnd = relocationTableOffset + relocationCount * 4;
			if (relocationCount > 0 && (relocationTableOffset < 28 || tableEnd > headerBytes)) return err("DOS MZ relocation table lies outside its header");
			if (relocationCount > 0 && tableEnd > bytes.length) return err("truncated DOS MZ relocation table");
			if (windowsHeader.state === "header-needed") return err("MZ Windows new-header pointer is outside the bounded prefix");
			const moduleBytes = imageBytes - headerBytes;
			const relocations = validateRelocations(bytes, relocationTableOffset, relocationCount, moduleBytes);
			if (!relocations.ok) return relocations;
			const entryOffset = bytes.readUInt16LE(20);
			const entrySegment = bytes.readUInt16LE(22);
			if (entrySegment * 16 + entryOffset >= moduleBytes) return err("DOS MZ entry point lies outside its initialized load module");
			return ok({
				headerBytes,
				imageBytes,
				moduleBytes,
				overlayBytes: fileSize - imageBytes,
				relocationCount,
				relocationTableOffset,
				entrySegment,
				entryOffset
			});
		};
		validateRelocations = (bytes, relocationTableOffset, relocationCount, moduleBytes) => {
			for (let index = 0; index < relocationCount; index += 1) {
				const record = relocationTableOffset + index * 4;
				const offset = bytes.readUInt16LE(record);
				const segment = bytes.readUInt16LE(record + 2);
				if (segment * 16 + offset + 2 > moduleBytes) return err(`DOS MZ relocation ${index} points outside its load module`);
			}
			return ok(undefined);
		};
	})))();
}

//#endregion
//#region dist/application/InvestigationProviders.js
var REA_WORKFLOW_PROVIDER, workflowAnalysisProfile, ARTIFACT_GRAPH_PROVIDER, MANAGED_STATIC_PROVIDER, PE_RESOURCES_PROVIDER, MANAGED_WORKFLOW_PROVIDER, APPLE_APPLICATION_PROVIDER, ANDROID_APPLICATION_PROVIDER, HARMONY_APPLICATION_PROVIDER, WEB_SCRIPT_EXPORT_PROVIDER, JAVASCRIPT_APPLICATION_PROVIDER, JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER, ANALYSIS_VIEW_PROVIDER, JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER, ARTIFACT_COMPARISON_PROVIDER, FUNCTION_COMPARISON_PROVIDER, BUNDLE_COMPARISON_PROVIDER, CHANGED_BEHAVIOR_PROVIDER, CALL_PATH_PROVIDER, STATIC_RUNTIME_PROVIDER, RECONSTRUCTION_PROVIDER;
function init_InvestigationProviders() {
	return (init_InvestigationProviders = __esmMin((() => {
		init_analysisProfile();
		REA_WORKFLOW_PROVIDER = {
			id: "rea-workflow",
			name: "REA composed investigation workflow",
			version: "1"
		};
		workflowAnalysisProfile = (upstream, operation) => createAnalysisProfile(REA_WORKFLOW_PROVIDER, {
			upstream_analysis_profile: upstream,
			source_limitations: "provider-operation-caveats-v1",
			...operation === "binary_overview" ? { workflow_revision: 4 } : operation === "batch_decompile" || operation === "get_call_graph" || operation === "trace_feature" ? { workflow_revision: 3 } : { workflow_revision: 1 }
		});
		ARTIFACT_GRAPH_PROVIDER = Object.freeze({
			id: "rea-artifact-graph",
			name: "REA safe artifact graph provider",
			version: "1"
		});
		MANAGED_STATIC_PROVIDER = Object.freeze({
			id: "rea-dotnet-static",
			name: "REA managed static analysis provider",
			version: "1"
		});
		PE_RESOURCES_PROVIDER = Object.freeze({
			id: "rea-pe-resources",
			name: "REA PE resource parser",
			version: "1"
		});
		MANAGED_WORKFLOW_PROVIDER = {
			id: "rea-dotnet-workflows",
			name: "REA managed-code workflows",
			version: "1"
		};
		APPLE_APPLICATION_PROVIDER = {
			id: "rea-apple-application",
			name: "REA Apple application workflows",
			version: "1"
		};
		ANDROID_APPLICATION_PROVIDER = {
			id: "rea-android-application",
			name: "REA Android application workflows",
			version: "1"
		};
		HARMONY_APPLICATION_PROVIDER = {
			id: "rea-harmony-application",
			name: "REA HarmonyOS application workflows",
			version: "1"
		};
		WEB_SCRIPT_EXPORT_PROVIDER = {
			id: "rea-web-script-export",
			name: "REA captured script export",
			version: "1"
		};
		JAVASCRIPT_APPLICATION_PROVIDER = {
			id: "rea-javascript-application",
			name: "REA JavaScript application analyzer",
			version: "1"
		};
		JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER = {
			id: "rea-javascript-runtime-reconciliation",
			name: "REA JavaScript runtime reconciliation",
			version: "1"
		};
		ANALYSIS_VIEW_PROVIDER = {
			id: "rea-analysis-view",
			name: "REA analysis view projection",
			version: "1"
		};
		JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER = {
			id: "rea-javascript-application-workflows",
			name: "REA JavaScript application workflows",
			version: "1"
		};
		ARTIFACT_COMPARISON_PROVIDER = {
			id: "rea-artifact-comparison",
			name: "REA artifact comparison",
			version: "1"
		};
		FUNCTION_COMPARISON_PROVIDER = {
			id: "rea-function-comparison",
			name: "REA function comparison",
			version: "1"
		};
		BUNDLE_COMPARISON_PROVIDER = {
			id: "rea-bundle-comparison",
			name: "REA Evidence bundle comparison",
			version: "1"
		};
		CHANGED_BEHAVIOR_PROVIDER = {
			id: "rea-changed-behavior",
			name: "REA changed behavior investigation",
			version: "1"
		};
		CALL_PATH_PROVIDER = {
			id: "rea-call-path",
			name: "REA call path reconstruction",
			version: "1"
		};
		STATIC_RUNTIME_PROVIDER = {
			id: "rea-static-runtime-correlation",
			name: "REA static/runtime correlation",
			version: "1"
		};
		RECONSTRUCTION_PROVIDER = {
			id: "rea-reconstruction-verifier",
			name: "REA reconstruction verifier",
			version: "1"
		};
	})))();
}

//#endregion
//#region dist/filesystem/callerPath.js
var absoluteCallerPath;
function init_callerPath() {
	return (init_callerPath = __esmMin((() => {
		absoluteCallerPath = (path, { cwd = process.cwd(), platform = process.platform } = {}) => {
			if (platform === "win32") return win32.resolve(cwd, path);
			if (!posix.isAbsolute(path)) {
				const base = posix.isAbsolute(cwd) ? cwd : absoluteCallerPath(cwd, { platform });
				return absoluteCallerPath(`${base}/${path}`, { platform });
			}
			const segments = path.split("/").filter((segment) => segment !== "" && segment !== ".");
			const directory = /\/\.?$/u.test(path) && segments.length > 0;
			return `/${segments.join("/")}${directory ? "/" : ""}`;
		};
	})))();
}

//#endregion
//#region dist/domain/godotPckFormat.js
var GODOT_PCK_MAGIC, hasGodotPckHeader;
function init_godotPckFormat() {
	return (init_godotPckFormat = __esmMin((() => {
		GODOT_PCK_MAGIC = 1129333831;
		hasGodotPckHeader = (bytes) => bytes.length >= 4 && bytes[0] === 71 && bytes[1] === 68 && bytes[2] === 80 && bytes[3] === 67;
	})))();
}

//#endregion
export { observeMzWindowsHeader as A, RECONSTRUCTION_PROVIDER as C, workflowAnalysisProfile as D, init_InvestigationProviders as E, dosMzImageByteLength as O, REA_WORKFLOW_PROVIDER as S, WEB_SCRIPT_EXPORT_PROVIDER as T, JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER as _, init_callerPath as a, MANAGED_WORKFLOW_PROVIDER as b, APPLE_APPLICATION_PROVIDER as c, BUNDLE_COMPARISON_PROVIDER as d, CALL_PATH_PROVIDER as f, JAVASCRIPT_APPLICATION_PROVIDER as g, HARMONY_APPLICATION_PROVIDER as h, absoluteCallerPath as i, parseDosMzHeader as j, init_dosMz as k, ARTIFACT_COMPARISON_PROVIDER as l, FUNCTION_COMPARISON_PROVIDER as m, hasGodotPckHeader as n, ANALYSIS_VIEW_PROVIDER as o, CHANGED_BEHAVIOR_PROVIDER as p, init_godotPckFormat as r, ANDROID_APPLICATION_PROVIDER as s, GODOT_PCK_MAGIC as t, ARTIFACT_GRAPH_PROVIDER as u, JAVASCRIPT_RUNTIME_RECONCILIATION_PROVIDER as v, STATIC_RUNTIME_PROVIDER as w, PE_RESOURCES_PROVIDER as x, MANAGED_STATIC_PROVIDER as y };