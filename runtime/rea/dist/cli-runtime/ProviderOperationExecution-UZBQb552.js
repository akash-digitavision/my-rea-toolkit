import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisCancelledError, AnalysisInputError, AnalysisOutputError, freezeJsonSnapshot, init_analysisErrorCore, init_immutableJson, init_jsonValue, isImmutableJsonSnapshot, jsonValueSchema } from "./errorSchemas-BjJIu7zO.js";
import { err, init_inputIssueProjection, init_result, ok, projectInputIssues } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { createAnalysisExecutionEvidence, init_AnalysisProvider } from "./AnalysisProvider-DbGpjE6B.js";
import { z } from "zod";

//#region dist/application/ProviderOperationExecution.js
var executeProviderOperation, completeProviderEvidence, keepIncompleteObservation;
function init_ProviderOperationExecution() {
	return (init_ProviderOperationExecution = __esmMin((() => {
		init_analysisErrorCore();
		init_immutableJson();
		init_jsonValue();
		init_inputIssueProjection();
		init_result();
		init_AnalysisProvider();
		executeProviderOperation = async (operation, input, options, schema, provider, confidence) => {
			if (options?.signal?.aborted) return err(new AnalysisCancelledError(operation, { cause: options.signal.reason }));
			const request = schema.safeParse({
				operation,
				input
			});
			if (!request.success) return err(new AnalysisInputError(operation, { cause: request.error }, projectInputIssues(request.error.issues, {
				operation,
				input
			}).map((issue) => issue.path[0] === "input" ? {
				...issue,
				path: issue.path.slice(1)
			} : issue)));
			const executed = await provider.execute(request.data, options);
			if (!executed.ok) return executed;
			const evidence = createAnalysisExecutionEvidence(operation, request.data.input, executed.value, confidence);
			return completeProviderEvidence(evidence, options?.signal);
		};
		completeProviderEvidence = (evidence, signal, capturedOutput) => {
			if (signal?.aborted) return err(new AnalysisCancelledError(evidence.operation, {
				cause: signal.reason,
				partialObservation: evidence,
				...capturedOutput === undefined ? {} : { capturedOutput }
			}));
			return ok(evidence);
		};
		keepIncompleteObservation = (error, operation, reason) => {
			const seen = new Set();
			const judged = new Map();
			let current = error;
			while (current !== undefined && !seen.has(current)) {
				seen.add(current);
				const partial = current.partialObservation;
				if (partial !== undefined && !isImmutableJsonSnapshot(partial) && typeof partial === "object") {
					let snapshot = judged.get(partial);
					if (!judged.has(partial)) {
						const parsed = jsonValueSchema.safeParse(partial);
						snapshot = parsed.success ? freezeJsonSnapshot(parsed.data) : undefined;
						judged.set(partial, snapshot);
					}
					if (snapshot === undefined) {
						current.partialObservation = undefined;
						current.retainSecondaryFailure(new AnalysisOutputError(operation, reason));
					} else current.partialObservation = snapshot;
				}
				current = current.cleanupPrimary;
			}
			return error;
		};
	})))();
}

//#endregion
export { completeProviderEvidence, executeProviderOperation, init_ProviderOperationExecution, keepIncompleteObservation };