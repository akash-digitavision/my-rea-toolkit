import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { AnalysisCancelledError, AnalysisInputError, AnalysisUnsupportedTargetError, BinaryTargetError, init_analysisErrorCore, init_configurationErrors } from "./errorSchemas-BjJIu7zO.js";
import { ArtifactOperationError, init_artifactOperationError } from "./cliResultOutput-sm6qfiuc.js";
import { ArtifactReaderFailure, init_ArtifactReader } from "./ArtifactReader-CGZcqzzo.js";
import { artifactFileCancellationCause, bindArtifactFileCleanup, init_ArtifactFileOperation } from "./ArtifactFileOperation-ynaKMviK.js";

//#region dist/artifacts/ArtifactOperationFailure.js
var translateArtifactFailure;
function init_ArtifactOperationFailure() {
	return (init_ArtifactOperationFailure = __esmMin((() => {
		init_analysisErrorCore();
		init_artifactOperationError();
		init_configurationErrors();
		init_ArtifactReader();
		init_ArtifactFileOperation();
		translateArtifactFailure = (operation, cause) => {
			if (cause instanceof ArtifactReaderFailure) {
				const error = new ArtifactOperationError(operation, cause.reason, cause.details, cause.message, {
					cause: cause.reason === "cancelled" ? artifactFileCancellationCause(cause) : cause,
					...cause.cleanup === undefined ? {} : { cleanup: cause.cleanup },
					...cause.partialObservation === undefined ? {} : { partialObservation: cause.partialObservation }
				});
				bindArtifactFileCleanup(cause, error);
				return error;
			}
			if (cause instanceof AnalysisInputError || cause instanceof AnalysisCancelledError || cause instanceof AnalysisUnsupportedTargetError || cause instanceof BinaryTargetError) return cause;
			return new ArtifactOperationError(operation, "io");
		};
	})))();
}

//#endregion
export { init_ArtifactOperationFailure, translateArtifactFailure };