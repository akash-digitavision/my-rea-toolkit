import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { a as init_result, i as err, o as ok } from "./analysisErrorBase-C1inc3JA.js";
import { i as init_configurationErrors, n as ConfigurationError } from "./configurationErrors-CUPdDkdb.js";
import { z } from "zod";
import pino from "pino";

//#region dist/logger.js
var PROCESS_START_CONFIGURATION_SETTINGS, blocksProcessStart, logLevelSchema, parseLogLevel, createLogger, silentLogger;
function init_logger() {
	return (init_logger = __esmMin((() => {
		init_configurationErrors();
		init_result();
		PROCESS_START_CONFIGURATION_SETTINGS = ["REA_LOG_LEVEL"];
		blocksProcessStart = (setting) => PROCESS_START_CONFIGURATION_SETTINGS.some((candidate) => candidate === setting);
		logLevelSchema = z.enum([
			"trace",
			"debug",
			"info",
			"warn",
			"error",
			"fatal",
			"silent"
		]).default("info");
		parseLogLevel = (value) => {
			const parsed = logLevelSchema.safeParse(value);
			if (parsed.success) return ok(parsed.data);
			return err(new ConfigurationError("Invalid REA environment configuration", {
				cause: parsed.error,
				settings: parsed.error.issues.map(({ message }) => ({
					setting: "REA_LOG_LEVEL",
					constraint: message
				}))
			}));
		};
		createLogger = (mode, level) => pino({
			level,
			base: {
				application: "rea",
				mode
			}
		}, pino.destination({
			dest: 2,
			sync: false
		}));
		silentLogger = pino({ level: "silent" });
	})))();
}

//#endregion
export { init_logger as n, silentLogger as r, createLogger as t };