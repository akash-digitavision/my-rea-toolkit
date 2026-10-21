import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { init_result, ok } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";
import { init_environment, parseEnvironment } from "./SupportedClients-DClvgj4R.js";
import { homeDirectoryFromEnvironment, init_homeDirectory } from "./homeDirectory-DC_DeJIg.js";
import { REA_MANAGED_LINUX_HOPPER_LAUNCHER, init_LinuxHopper, linuxHopperLauncherCandidates } from "./SharedStartupAttempt-BgaliXAe.js";
import { join } from "node:path";
import { accessSync, constants, readdirSync, statSync } from "node:fs";

//#region dist/application/MacHopperPaths.js
/** Yield canonical paths first; enumerate renamed bundles only if needed. */
function* macHopperLauncherCandidates(homeDirectory) {
	yield* macHopperCanonicalLauncherCandidates(homeDirectory);
	for (const root of macHopperApplicationRoots(homeDirectory)) yield* macHopperRenamedLauncherCandidates(homeDirectory, new Map([[root, localBundleNames(root)]]));
}
var MAC_HOPPER_APPLICATION_DIRECTORY, MAC_HOPPER_APPLICATION_NAME, MAC_HOPPER_USER_APPLICATIONS_DIRECTORY, MAC_HOPPER_SYSTEM_LAUNCHER, macHopperUserApplicationPath, macHopperApplicationRoots, macHopperCanonicalLauncherCandidates, macHopperRenamedLauncherCandidates, localBundleNames;
function init_MacHopperPaths() {
	return (init_MacHopperPaths = __esmMin((() => {
		MAC_HOPPER_APPLICATION_DIRECTORY = "/Applications";
		MAC_HOPPER_APPLICATION_NAME = "Hopper Disassembler.app";
		MAC_HOPPER_USER_APPLICATIONS_DIRECTORY = "Applications";
		MAC_HOPPER_SYSTEM_LAUNCHER = join(MAC_HOPPER_APPLICATION_DIRECTORY, MAC_HOPPER_APPLICATION_NAME, "Contents/MacOS/hopper");
		macHopperUserApplicationPath = (homeDirectory) => join(homeDirectory, MAC_HOPPER_USER_APPLICATIONS_DIRECTORY, MAC_HOPPER_APPLICATION_NAME);
		macHopperApplicationRoots = (homeDirectory) => [MAC_HOPPER_APPLICATION_DIRECTORY, join(homeDirectory, MAC_HOPPER_USER_APPLICATIONS_DIRECTORY)];
		macHopperCanonicalLauncherCandidates = (homeDirectory) => [MAC_HOPPER_SYSTEM_LAUNCHER, join(macHopperUserApplicationPath(homeDirectory), "Contents/MacOS/hopper")];
		macHopperRenamedLauncherCandidates = (homeDirectory, bundleNamesByRoot) => macHopperApplicationRoots(homeDirectory).flatMap((root) => [...new Set(bundleNamesByRoot.get(root) ?? [])].filter((name) => /^Hopper.*\.app$/iu.test(name) && name.toLocaleLowerCase("en-US") !== "Hopper Disassembler.app".toLocaleLowerCase("en-US")).sort().map((name) => join(root, name, "Contents/MacOS/hopper")));
		localBundleNames = (root) => {
			try {
				return readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory() && /^Hopper.*\.app$/iu.test(entry.name)).map(({ name }) => name);
			} catch (cause) {
				void cause;
				return [];
			}
		};
	})))();
}

//#endregion
//#region dist/config/parseConfig.js
var executableAvailable, defaultHopperLauncherPath, nativeAnalysisEnvironment, nativeAnalysisConfigurationError, parseConfig;
function init_parseConfig() {
	return (init_parseConfig = __esmMin((() => {
		init_result();
		init_environment();
		init_homeDirectory();
		init_LinuxHopper();
		init_MacHopperPaths();
		executableAvailable = (path) => {
			try {
				accessSync(path, constants.X_OK);
				return statSync(path).isFile();
			} catch {
				return false;
			}
		};
		defaultHopperLauncherPath = (platform, homeDirectory, executable = executableAvailable) => {
			if (platform === "darwin") {
				for (const candidate of macHopperLauncherCandidates(homeDirectory)) if (executable(candidate)) return candidate;
				return MAC_HOPPER_SYSTEM_LAUNCHER;
			}
			if (platform !== "linux") return MAC_HOPPER_SYSTEM_LAUNCHER;
			return linuxHopperLauncherCandidates(homeDirectory).find(executable) ?? "/opt/hopper/bin/Hopper";
		};
		nativeAnalysisEnvironment = (environment) => {
			const { REA_JEB_MCP_TIMEOUT_MS: _jebTimeout, ...appEnvironment } = environment;
			return appEnvironment;
		};
		nativeAnalysisConfigurationError = (environment) => {
			const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
			return parsed.ok ? undefined : parsed.error;
		};
		parseConfig = (environment) => {
			const parsed = parseEnvironment(nativeAnalysisEnvironment(environment));
			if (!parsed.ok) return parsed;
			const env = parsed.value;
			return ok({
				...env.REA_MCP_MAX_RESPONSE_BYTES === undefined ? {} : { mcpMaxResponseBytes: env.REA_MCP_MAX_RESPONSE_BYTES },
				...env.REA_MCP_INPUT_SCHEMA_PROFILE === undefined ? {} : { mcpInputSchemaProfile: env.REA_MCP_INPUT_SCHEMA_PROFILE },
				analysisProvider: env.REA_ANALYSIS_PROVIDER,
				...env.REA_IDA_MCP_CONFIG === undefined ? {} : { idaMcpConfigPath: env.REA_IDA_MCP_CONFIG },
				ghidraInstallDir: env.GHIDRA_INSTALL_DIR,
				ghidraJavaHome: env.JAVA_HOME,
				ghidraStartupTimeoutMs: env.REA_GHIDRA_STARTUP_TIMEOUT_MS,
				...env.REA_GHIDRA_LANGUAGE_ID === undefined ? {} : { ghidraLanguageOverride: {
					languageId: env.REA_GHIDRA_LANGUAGE_ID,
					...env.REA_GHIDRA_COMPILER_SPEC_ID === undefined ? {} : { compilerSpecId: env.REA_GHIDRA_COMPILER_SPEC_ID }
				} },
				...env.REA_GHIDRA_SEED_FILE === undefined ? {} : { ghidraSeedFile: env.REA_GHIDRA_SEED_FILE },
				...env.REA_GHIDRA_DISABLED_ANALYZERS === undefined ? {} : { ghidraDisabledAnalyzers: env.REA_GHIDRA_DISABLED_ANALYZERS },
				...env.REA_GHIDRA_NATIVEAOT_JAR === undefined ? {} : { ghidraNativeAotJar: env.REA_GHIDRA_NATIVEAOT_JAR },
				ilspyCmdPath: env.REA_ILSPY_CMD_PATH,
				hopperLauncherPath: env.HOPPER_LAUNCHER_PATH ?? defaultHopperLauncherPath(process.platform, homeDirectoryFromEnvironment(environment, process.platform)),
				hopperStartupTimeoutMs: env.REA_HOPPER_STARTUP_TIMEOUT_MS,
				hopperTargetPath: env.HOPPER_TARGET_PATH,
				hopperTargetKind: env.HOPPER_TARGET_KIND,
				hopperLoaderArgs: env.loaderArgs,
				logLevel: env.REA_LOG_LEVEL,
				referenceSourcePolicy: { secretPatterns: env.referenceSecretPatterns }
			});
		};
	})))();
}

//#endregion
export { MAC_HOPPER_SYSTEM_LAUNCHER, init_MacHopperPaths, init_parseConfig, macHopperApplicationRoots, macHopperCanonicalLauncherCandidates, macHopperRenamedLauncherCandidates, macHopperUserApplicationPath, nativeAnalysisConfigurationError, parseConfig };