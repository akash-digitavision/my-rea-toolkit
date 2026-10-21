import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { n as init_analysisErrorBase, t as AnalysisError } from "./analysisErrorBase-C1inc3JA.js";
import { f as BrowserObservationError, p as init_browserObservationError } from "./analysisErrorProjection-DPMozIkD.js";
import { n as init_analysisErrorCleanup, t as analysisErrorWithCleanupFailure } from "./analysisErrorCleanup-LFIV2yDc.js";
import { a as init_CdpEndpoint, c as withCdpDiscoveryDeadline, d as init_CdpTargetSessionOwner, f as CdpConnection, n as discoverCdpBrowserSocket, p as init_CdpConnection, r as discoverCdpEndpoint, t as cdpTargetWebSocket, u as bindCdpTransportCleanup } from "./CdpEndpoint-D1v2Wf7q.js";

//#region dist/browser/CdpTargetSession.js
var openCdpEndpoint, openCdpTargetSession, attachCdpTargetSession, combineOpenFailure, closeCdpTargetSession, cleanupCdpTargetCommands, attachedSessionId;
function init_CdpTargetSession() {
	return (init_CdpTargetSession = __esmMin((() => {
		init_analysisErrorBase();
		init_analysisErrorCleanup();
		init_browserObservationError();
		init_CdpConnection();
		init_CdpTargetSessionOwner();
		init_CdpEndpoint();
		openCdpEndpoint = async (endpoint, operation, signal, timeoutMs, owner) => {
			if (endpoint.transport === "http_discovery") return {
				discovery: await discoverCdpEndpoint(endpoint.url, operation, signal),
				connection: undefined
			};
			return await withCdpDiscoveryDeadline(operation, signal, async (deadlineSignal) => {
				const connection = owner === undefined ? await CdpConnection.connect(endpoint.url, operation, deadlineSignal) : await owner.connect(endpoint.url, operation, { signal: deadlineSignal }, "browser-endpoint");
				try {
					return {
						discovery: await discoverCdpBrowserSocket(connection, endpoint.url, operation, deadlineSignal),
						connection
					};
				} catch (cause) {
					if (owner === undefined) {
						await connection.close();
						throw cause;
					}
					try {
						await owner.finish(connection);
					} catch (cleanupCause) {
						throw combineOpenFailure(cause, cleanupCause, operation);
					}
					throw cause;
				}
			}, timeoutMs);
		};
		openCdpTargetSession = async (discovery, target, operation, signal, limits, owner) => {
			const webSocket = cdpTargetWebSocket(discovery, target, operation);
			const connection = owner === undefined ? await CdpConnection.connect(webSocket.url, operation, signal, limits) : await owner.connect(webSocket.url, operation, signal === undefined ? {} : { signal }, target.id, limits);
			if (webSocket.scope === "page") return {
				connection,
				sessionId: undefined
			};
			try {
				return await attachCdpTargetSession(connection, target, operation, signal, owner);
			} catch (cause) {
				if (owner === undefined) throw cause;
				try {
					await owner.finish(connection);
				} catch (cleanupCause) {
					throw combineOpenFailure(cause, cleanupCause, operation);
				}
				throw cause;
			}
		};
		attachCdpTargetSession = async (connection, target, operation, signal, owner) => {
			try {
				const attached = await connection.send("Target.attachToTarget", {
					targetId: target.id,
					flatten: true
				}, undefined, signal);
				return {
					connection,
					sessionId: attachedSessionId(attached, operation)
				};
			} catch (cause) {
				if (owner === undefined) {
					await connection.close();
					throw cause;
				}
				throw cause;
			}
		};
		combineOpenFailure = (primary, cleanup, operation) => primary instanceof AnalysisError && cleanup instanceof AnalysisError ? bindCdpTransportCleanup(cleanup, analysisErrorWithCleanupFailure(primary, cleanup, operation)) : new AggregateError([primary, cleanup], `CDP operation ${operation} failed and its transport cleanup is incomplete.`, { cause: primary });
		closeCdpTargetSession = async (targetSession, enabledDomains, signal, owner) => {
			if (owner !== undefined) {
				await owner.finish(targetSession.connection, () => cleanupCdpTargetCommands(targetSession, enabledDomains, signal));
				return;
			}
			await cleanupCdpTargetCommands(targetSession, enabledDomains, signal);
			await targetSession.connection.close();
		};
		cleanupCdpTargetCommands = async (targetSession, enabledDomains, signal) => {
			const { connection, sessionId } = targetSession;
			const cleanup = new AbortController();
			const domainSignal = signal === undefined ? cleanup.signal : AbortSignal.any([cleanup.signal, signal]);
			const timeout = setTimeout(() => cleanup.abort(), 1e3);
			timeout.unref();
			try {
				if (signal?.aborted !== true) {
					for (const domain of enabledDomains) {
						if (domainSignal.aborted) break;
						try {
							await connection.send(`${domain}.disable`, {}, sessionId, domainSignal);
						} catch {}
					}
				}
				if (!cleanup.signal.aborted && sessionId !== undefined) try {
					await connection.send("Target.detachFromTarget", { sessionId }, undefined, cleanup.signal);
				} catch {}
			} finally {
				clearTimeout(timeout);
				cleanup.abort();
			}
		};
		attachedSessionId = (value, operation) => {
			if (typeof value !== "object" || value === null || !("sessionId" in value) || typeof value.sessionId !== "string" || value.sessionId.length === 0) throw new BrowserObservationError(operation, "protocol_error");
			return value.sessionId;
		};
	})))();
}

//#endregion
export { openCdpTargetSession as a, openCdpEndpoint as i, closeCdpTargetSession as n, init_CdpTargetSession as r, attachCdpTargetSession as t };