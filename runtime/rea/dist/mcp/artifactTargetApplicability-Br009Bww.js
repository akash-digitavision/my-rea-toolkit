import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { en as init_binaryTargetTypes, nn as isMachOFormat } from "./nativeValueTrace-Cm--GSDT.js";

//#region dist/domain/apple/artifactTargetApplicability.js
var artifactTargetRefusal;
function init_artifactTargetApplicability() {
	return (init_artifactTargetApplicability = __esmMin((() => {
		init_binaryTargetTypes();
		artifactTargetRefusal = (operation, target) => {
			const bundle = target.kind === "executable" && target.bundleInfoPlist !== undefined;
			const refuse = (reason) => ({
				code: "target_kind_unsupported",
				reason
			});
			switch (operation) {
				case "decode_interface_builder":
				case "inspect_asset_catalog": return bundle ? undefined : refuse(`${operation} requires an active .app bundle target`);
				case "inspect_keyed_archive": return bundle || target.kind === "artifact" && target.format === "plist" ? undefined : refuse("inspect_keyed_archive requires an active plist or .app bundle");
				case "trace_dylib_resolution":
					if (target.kind !== "executable") return refuse("trace_dylib_resolution requires an active Mach-O or .app bundle target");
					return isMachOFormat(target.format) ? undefined : {
						code: "target_format_unsupported",
						reason: "trace_dylib_resolution requires an active Mach-O or .app bundle target"
					};
				default: return undefined;
			}
		};
	})))();
}

//#endregion
export { init_artifactTargetApplicability as n, artifactTargetRefusal as t };