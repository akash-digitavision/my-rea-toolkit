import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { n as init_ProviderDeadline, t as ProviderStartupDeadline } from "./ProviderDeadline-BHJfBmfF.js";
import { o as classifyBrowserCompleteness, s as init_browserCompleteness } from "./browserObservationSchemas-DN3PLoKY.js";
import { n as init_webRuntime, t as WEB_RUNTIME_LIMITS } from "./webRuntime-DIU4Kl5j.js";
import { h as init_CdpCommandRejection, m as CdpCommandRejection, p as init_CdpConnection } from "./CdpEndpoint-D1v2Wf7q.js";

//#region dist/browser/CdpCaptureCompleteness.js
var EVENT_SECTIONS, POLICY_REASONS, CdpCaptureCompleteness, emptyDropped;
function init_CdpCaptureCompleteness() {
	return (init_CdpCaptureCompleteness = __esmMin((() => {
		init_browserCompleteness();
		EVENT_SECTIONS = {
			scripts: "scripts",
			network_requests: "network_requests",
			console_events: "console_events",
			websocket_connections: "websocket_connections",
			websocket_frames: "websocket_frames",
			webmcp_tools: "webmcp_tools",
			timeline_events: "timeline"
		};
		POLICY_REASONS = new Set([
			"disallowed_origin",
			"unsupported_url",
			"unattributed_origin",
			"not_approved",
			"out_of_target_scope"
		]);
		CdpCaptureCompleteness = class {
			#initialAttachLimited;
			#policyFiltered = new Set();
			#attachLimited = new Set();
			#truncated = new Set();
			#unavailable = new Set();
			#excluded = new Map();
			#dropped = emptyDropped();
			constructor(initialAttachLimited = []) {
				this.#initialAttachLimited = [...initialAttachLimited];
				this.reset();
			}
			reset() {
				this.#policyFiltered.clear();
				this.#attachLimited.clear();
				this.#truncated.clear();
				this.#unavailable.clear();
				this.#excluded.clear();
				Object.assign(this.#dropped, emptyDropped());
				for (const section of this.#initialAttachLimited) this.#attachLimited.add(section);
			}
			exclude(section, reason, count = 1) {
				if (POLICY_REASONS.has(reason)) this.#policyFiltered.add(section);
				if (reason === "provider_unavailable" || reason === "invalid_protocol_value") this.#unavailable.add(section);
				if (reason === "resource_budget_exhausted") this.#truncated.add(section);
				const key = `${section}\0${reason}`;
				const existing = this.#excluded.get(key);
				const combined = count === null || existing?.count === null ? null : (existing?.count ?? 0) + count;
				this.#excluded.set(key, {
					section,
					reason,
					count: combined
				});
			}
			attachLimited(section) {
				this.#attachLimited.add(section);
			}
			unavailable(section) {
				this.#unavailable.add(section);
				this.exclude(section, "provider_unavailable", null);
			}
			truncate(section) {
				this.#truncated.add(section);
			}
			drop(kind, count = 1) {
				this.#dropped[kind] += count;
				this.#truncated.add(EVENT_SECTIONS[kind]);
			}
			get droppedTotal() {
				return Object.values(this.#dropped).reduce((sum, count) => sum + count, 0);
			}
			snapshot() {
				return classifyBrowserCompleteness({
					policyFilteredSections: this.#policyFiltered,
					attachLimitedSections: this.#attachLimited,
					truncatedSections: this.#truncated,
					unavailableSections: this.#unavailable,
					excluded: [...this.#excluded.values()],
					droppedEvents: this.#dropped
				});
			}
		};
		emptyDropped = () => ({
			scripts: 0,
			network_requests: 0,
			console_events: 0,
			websocket_connections: 0,
			websocket_frames: 0,
			webmcp_tools: 0,
			timeline_events: 0
		});
	})))();
}

//#endregion
//#region dist/browser/CdpOptionalCommand.js
var optionalCdpCommand;
function init_CdpOptionalCommand() {
	return (init_CdpOptionalCommand = __esmMin((() => {
		init_CdpCommandRejection();
		init_CdpConnection();
		optionalCdpCommand = async (context, method, parameters, limitations) => {
			try {
				return await context.connection.send(method, parameters, context.sessionId, context.signal);
			} catch (cause) {
				if (!(cause instanceof CdpCommandRejection) || cause.code !== -32601) throw cause;
				limitations.push(`${method} was unavailable from this browser target.`);
				return undefined;
			}
		};
	})))();
}

//#endregion
//#region dist/browser/CdpScriptSourceBudget.js
var MIB, CDP_SCRIPT_SOURCE_BYTES_OMISSION_REASON, CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON, CdpScriptSourceBudget;
function init_CdpScriptSourceBudget() {
	return (init_CdpScriptSourceBudget = __esmMin((() => {
		init_webRuntime();
		init_ProviderDeadline();
		MIB = 1024 * 1024;
		CDP_SCRIPT_SOURCE_BYTES_OMISSION_REASON = `script source was omitted because the aggregate ${String(WEB_RUNTIME_LIMITS.sourceBytes / MIB)} MiB source budget was exhausted`;
		CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON = `script source was omitted because the ${String(WEB_RUNTIME_LIMITS.commandTimeoutMs / 1e3)}-second source collection deadline elapsed`;
		CdpScriptSourceBudget = class {
			#deadline;
			#retainedBytes = 0;
			constructor(signal) {
				this.#deadline = new ProviderStartupDeadline(WEB_RUNTIME_LIMITS.commandTimeoutMs, signal);
			}
			get signal() {
				return this.#deadline.signal;
			}
			get timedOut() {
				return this.#deadline.interruption === "timeout";
			}
			/** Admit exact UTF-8 source bytes before building or retaining its artifact. */
			admit(text) {
				const bytes = Buffer.byteLength(text, "utf8");
				if (bytes > WEB_RUNTIME_LIMITS.sourceBytes - this.#retainedBytes) return false;
				this.#retainedBytes += bytes;
				return true;
			}
			dispose() {
				this.#deadline.dispose();
			}
		};
	})))();
}

//#endregion
export { init_CdpOptionalCommand as a, init_CdpCaptureCompleteness as c, init_CdpScriptSourceBudget as i, CDP_SCRIPT_SOURCE_DEADLINE_OMISSION_REASON as n, optionalCdpCommand as o, CdpScriptSourceBudget as r, CdpCaptureCompleteness as s, CDP_SCRIPT_SOURCE_BYTES_OMISSION_REASON as t };