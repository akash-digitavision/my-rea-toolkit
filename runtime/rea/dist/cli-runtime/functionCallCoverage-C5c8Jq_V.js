import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { canonicalJson, compareUnicodeCodePoints, init_canonicalOrdering, init_comparisonSemantics, init_relationshipCoverage, init_unicodeCodePointOrder, relationshipCoverageLimitations, uniqueSorted } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";

//#region dist/domain/functionComparisonNormalization.js
var identityProjection, functionMatch, normalizeCfg, commentProjection, stringAndNameProjection, swiftLiteralSitesConflict, swiftLiteralSites, sorted, isAutoName, parseAddress, relativeAddress;
function init_functionComparisonNormalization() {
	return (init_functionComparisonNormalization = __esmMin((() => {
		init_comparisonSemantics();
		init_unicodeCodePointOrder();
		identityProjection = (snapshot) => ({
			name: snapshot.dossier.procedure.name,
			signature: snapshot.dossier.procedure.signature,
			locals: snapshot.dossier.procedure.locals.map(({ description }) => description).sort()
		});
		functionMatch = (left, right) => {
			const leftName = left.dossier.procedure.name;
			const rightName = right.dossier.procedure.name;
			const stableNames = !isAutoName(leftName) && !isAutoName(rightName);
			if (stableNames && leftName === rightName) return {
				status: "matched",
				method: "symbol",
				left_name: leftName,
				right_name: rightName
			};
			return {
				status: stableNames ? "mismatched" : "ambiguous",
				method: "explicit",
				left_name: leftName,
				right_name: rightName
			};
		};
		normalizeCfg = (blocks) => {
			const parsed = [];
			for (const block of blocks) {
				const start = parseAddress(block.start);
				const end = parseAddress(block.end);
				if (start === null || end === null || end <= start) return null;
				parsed.push({
					block,
					start,
					end
				});
			}
			const ordered = parsed.sort((left, right) => left.start < right.start ? -1 : left.start > right.start ? 1 : 0);
			if (new Set(ordered.map(({ start }) => start)).size !== ordered.length) return null;
			const indices = new Map(ordered.map(({ start }, index) => [start, index]));
			const graph = [];
			for (const { block, start, end } of ordered) {
				const successors = [];
				for (const address of block.successors) {
					const parsedAddress = parseAddress(address);
					if (parsedAddress === null) return null;
					const index = indices.get(parsedAddress);
					if (index === undefined) return null;
					successors.push(index);
				}
				graph.push({
					size: String(end - start),
					successors: successors.sort((left, right) => left - right)
				});
			}
			return graph;
		};
		commentProjection = (snapshot) => {
			const values = snapshot.dossier.comments.map(({ address, kind, text }) => ({
				offset: relativeAddress(address, snapshot.dossier.procedure.address),
				kind,
				text
			}));
			return values.some(({ offset }) => offset === null) ? null : sorted(values);
		};
		stringAndNameProjection = (snapshot, includeSwiftLiterals = true) => {
			const values = [
				...snapshot.dossier.referenced_strings.map(({ source_address: sourceAddress, value }) => ({
					kind: "string",
					source_offset: relativeAddress(sourceAddress, snapshot.dossier.procedure.address),
					value
				})),
				...snapshot.dossier.referenced_names.map(({ source_address: sourceAddress, value }) => ({
					kind: "name",
					source_offset: relativeAddress(sourceAddress, snapshot.dossier.procedure.address),
					value
				})),
				...(includeSwiftLiterals ? snapshot.dossier.swift_string_literals ?? [] : []).map(({ source_address: sourceAddress, value, representation, registers }) => ({
					kind: "swift_string",
					source_offset: relativeAddress(sourceAddress, snapshot.dossier.procedure.address),
					value,
					representation,
					registers
				}))
			];
			return values.some(({ source_offset: offset }) => offset === null) ? null : sorted(values);
		};
		swiftLiteralSitesConflict = (left, right) => {
			const leftSites = swiftLiteralSites(left);
			const rightSites = swiftLiteralSites(right);
			for (const site of new Set([...leftSites.values.keys(), ...rightSites.values.keys()])) {
				const leftValues = leftSites.values.get(site) ?? (leftSites.complete ? [] : undefined);
				const rightValues = rightSites.values.get(site) ?? (rightSites.complete ? [] : undefined);
				if (leftValues === undefined || rightValues === undefined) continue;
				const leftFacts = new Set(leftValues);
				const rightFacts = new Set(rightValues);
				if (rightSites.complete && leftValues.some((value) => !rightFacts.has(value)) || leftSites.complete && rightValues.some((value) => !leftFacts.has(value))) return true;
			}
			return false;
		};
		swiftLiteralSites = (snapshot) => {
			const base = snapshot.dossier.procedure.address;
			const omissions = snapshot.dossier.swift_string_literal_omissions ?? [];
			const site = (sourceAddress, registers) => {
				const offset = relativeAddress(sourceAddress, base);
				return offset === null ? null : canonicalJson([offset, registers]);
			};
			const values = new Map();
			for (const literal of snapshot.dossier.swift_string_literals ?? []) {
				const key = site(literal.source_address, literal.registers);
				if (key === null) continue;
				values.set(key, [...values.get(key) ?? [], canonicalJson([literal.value, literal.representation])].sort(compareUnicodeCodePoints));
			}
			const complete = snapshot.dossier.swift_string_literals !== undefined && omissions.length === 0;
			return {
				values,
				complete
			};
		};
		sorted = (values) => values.map((value) => ({
			value,
			json: canonicalJson(value, "Function normalization")
		})).sort((left, right) => compareUnicodeCodePoints(left.json, right.json)).map(({ value }) => value);
		isAutoName = (name) => /^(?:sub_[0-9a-f]+|fcn\.[0-9a-f]+|FUN_[0-9a-f]+)$/iu.test(name);
		parseAddress = (value) => /^0x[0-9a-f]+$/iu.test(value) ? BigInt(value) : null;
		relativeAddress = (value, base) => {
			const parsed = parseAddress(value);
			const parsedBase = parseAddress(base);
			return parsed === null || parsedBase === null || parsed < parsedBase ? null : String(parsed - parsedBase);
		};
	})))();
}

//#endregion
//#region dist/domain/functionCallCoverage.js
var callerCoveragePrefix, calleeCoveragePrefix, combineFunctionRelationshipCoverage, isCallerOnlyIncompleteCoverage, assessFunctionCallCoverage;
function init_functionCallCoverage() {
	return (init_functionCallCoverage = __esmMin((() => {
		init_relationshipCoverage();
		init_canonicalOrdering();
		callerCoveragePrefix = "Callers: ";
		calleeCoveragePrefix = "Callees: ";
		combineFunctionRelationshipCoverage = (callers, callees) => {
			const reads = [{
				direction: "callers",
				coverage: callers
			}, {
				direction: "callees",
				coverage: callees
			}];
			const diagnostics = uniqueSorted(reads.flatMap(({ coverage }) => coverage?.diagnostics ?? []));
			const details = diagnostics.length > 0 ? { diagnostics } : {};
			const callersLimited = callers?.status !== "complete";
			const calleesLimited = callees?.status !== "complete";
			const limited_directions = callersLimited ? calleesLimited ? ["callers", "callees"] : ["callers"] : ["callees"];
			const reasons = reads.flatMap(({ direction, coverage }) => {
				const label = direction === "callers" ? callerCoveragePrefix : calleeCoveragePrefix;
				return relationshipCoverageLimitations(coverage).map((reason) => `${label}${reason}`);
			});
			if (reads.some(({ coverage }) => coverage === undefined || coverage.status === "unknown")) return {
				status: "unknown",
				reason: uniqueSorted(reasons).join(" "),
				limited_directions,
				...details
			};
			if (reasons.length > 0) return {
				status: "partial",
				limitations: uniqueSorted(reasons),
				limited_directions,
				...details
			};
			return {
				status: "complete",
				...details
			};
		};
		isCallerOnlyIncompleteCoverage = (coverage) => {
			if (coverage.status === "complete") return false;
			if (coverage.limited_directions !== undefined) return !coverage.limited_directions.some((direction) => direction === "callees");
			return coverage.status === "unknown" && coverage.reason.startsWith(callerCoveragePrefix) && !coverage.reason.includes(calleeCoveragePrefix);
		};
		assessFunctionCallCoverage = (coverage, dossier) => ({
			blockers: uniqueSorted([...relationshipCoverageLimitations(coverage), ...(dossier.unresolved_calls ?? []).map(({ address, reason }) => `Unresolved call at ${address}: ${reason}`)]),
			diagnostics: uniqueSorted(coverage?.diagnostics ?? [])
		});
	})))();
}

//#endregion
export { assessFunctionCallCoverage, combineFunctionRelationshipCoverage, commentProjection, functionMatch, identityProjection, init_functionCallCoverage, init_functionComparisonNormalization, isAutoName, normalizeCfg, sorted, stringAndNameProjection, swiftLiteralSitesConflict };