import { t as __esmMin } from "./rolldown-runtime-BjeaiXFo.js";
import { z } from "zod";
import { types } from "node:util";
import { isProxy } from "node:util/types";

//#region dist/domain/immutableJson.js
/**
* Seal exclusively owned JSON in bounded steps, authenticating only completion.
* Abandonment or failure can leave the provisional input partly frozen.
*/
function* freezeOwnedJsonSnapshotSteps(value) {
	const pending = [{
		value,
		exiting: false
	}];
	const visited = new Set();
	const ancestors = new Set();
	let examined = 0;
	try {
		while (pending.length > 0) {
			if (examined++ === 4096) {
				examined = 0;
				yield;
			}
			const entry = pending.pop();
			if (entry === undefined) break;
			const item = entry.value;
			if (entry.exiting && typeof item === "object" && item !== null) {
				ancestors.delete(item);
				visited.add(item);
				continue;
			}
			if (isImmutableJsonSnapshot(item)) continue;
			if (typeof item !== "object" || item === null) throw new TypeError("Immutable JSON snapshots require JSON values");
			if (ancestors.has(item)) throw new TypeError("Immutable JSON snapshots cannot contain circular references");
			if (visited.has(item)) continue;
			ancestors.add(item);
			pending.push({
				value: item,
				exiting: true
			});
			pushSnapshotChildren(item, pending);
			Object.freeze(item);
		}
		if (typeof value === "object" && value !== null) immutableSnapshots.add(value);
		return value;
	} finally {
		pending.length = 0;
		visited.clear();
		ancestors.clear();
	}
}
var immutableSnapshots, isImmutableJsonSnapshot, immutableJsonSnapshotMember, canBorrowParsedJsonSnapshot, freezeJsonSnapshot, pushSnapshotChildren;
function init_immutableJson() {
	return (init_immutableJson = __esmMin((() => {
		immutableSnapshots = new WeakSet();
		isImmutableJsonSnapshot = (value) => value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number" && Number.isFinite(value) || typeof value === "object" && immutableSnapshots.has(value);
		immutableJsonSnapshotMember = (snapshot, key) => {
			if (typeof snapshot !== "object" || snapshot === null || !immutableSnapshots.has(snapshot)) return undefined;
			const descriptor = Object.getOwnPropertyDescriptor(snapshot, key);
			if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) return undefined;
			const member = descriptor.value;
			if (typeof member === "object" && member !== null) immutableSnapshots.add(member);
			return member;
		};
		canBorrowParsedJsonSnapshot = (source, parsed) => {
			if (!isImmutableJsonSnapshot(source)) return false;
			if (Object.is(source, parsed)) return true;
			const pending = [source, parsed];
			const compared = new Map();
			const sources = new Map();
			while (pending.length > 0) {
				const right = pending.pop();
				const left = pending.pop();
				if (typeof left !== "object" || left === null || typeof right !== "object" || right === null) {
					if (!Object.is(left, right)) return false;
					continue;
				}
				if (isProxy(right) || Object.getPrototypeOf(left) !== Object.getPrototypeOf(right)) return false;
				const previous = compared.get(left);
				if (previous !== undefined) {
					if (previous !== right) return false;
					continue;
				}
				if (sources.has(right)) return false;
				compared.set(left, right);
				sources.set(right, left);
				const keys = Reflect.ownKeys(left);
				if (keys.length !== Reflect.ownKeys(right).length) return false;
				for (const key of keys) {
					if (typeof key !== "string") return false;
					const a = Object.getOwnPropertyDescriptor(left, key);
					const b = Object.getOwnPropertyDescriptor(right, key);
					if (a === undefined || b === undefined || !Object.hasOwn(a, "value") || !Object.hasOwn(b, "value") || a.enumerable !== b.enumerable) return false;
					pending.push(a.value, b.value);
				}
			}
			return true;
		};
		freezeJsonSnapshot = (value) => {
			const pending = [{
				value,
				exiting: false
			}];
			const visited = new Set();
			const ancestors = new Set();
			const objects = [];
			while (pending.length > 0) {
				const entry = pending.pop();
				if (entry === undefined) break;
				const item = entry.value;
				if (entry.exiting && typeof item === "object" && item !== null) {
					ancestors.delete(item);
					visited.add(item);
					objects.push(item);
					continue;
				}
				if (isImmutableJsonSnapshot(item)) continue;
				if (typeof item !== "object" || item === null) throw new TypeError("Immutable JSON snapshots require JSON values");
				if (ancestors.has(item)) throw new TypeError("Immutable JSON snapshots cannot contain circular references");
				if (visited.has(item)) continue;
				ancestors.add(item);
				pending.push({
					value: item,
					exiting: true
				});
				pushSnapshotChildren(item, pending);
			}
			for (const item of objects) Object.freeze(item);
			if (typeof value === "object" && value !== null) immutableSnapshots.add(value);
			return value;
		};
		pushSnapshotChildren = (item, pending) => {
			if (isProxy(item)) throw new TypeError("Immutable JSON snapshots cannot contain proxies");
			const prototype = Object.getPrototypeOf(item);
			if (!Array.isArray(item) && prototype !== Object.prototype && prototype !== null) throw new TypeError("Immutable JSON snapshots require ordinary objects");
			if (Array.isArray(item)) {
				for (let index = 0; index < item.length; index += 1) if (!Object.hasOwn(item, index)) throw new TypeError("Immutable JSON snapshots cannot contain sparse arrays");
			}
			for (const key of Object.getOwnPropertyNames(item)) {
				const descriptor = Object.getOwnPropertyDescriptor(item, key);
				if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) throw new TypeError("Immutable JSON snapshots cannot contain accessors");
				const child = descriptor.value;
				pending.push({
					value: child,
					exiting: false
				});
			}
		};
	})))();
}

//#endregion
//#region dist/domain/jsonValue.js
/** Validate JSON in bounded steps; cache only authenticated immutable roots. */
function* jsonValueValidationSteps(root) {
	const immutable = typeof root === "object" && root !== null && isImmutableJsonSnapshot(root) ? root : undefined;
	if (immutable !== undefined && immutableValidation.has(immutable)) return immutableValidation.get(immutable);
	const finish = (issue) => {
		if (immutable !== undefined) immutableValidation.set(immutable, issue);
		return issue;
	};
	const pending = [{
		value: root,
		depth: 0
	}];
	let examined = 0;
	while (pending.length > 0) {
		if (examined++ === 4096) {
			examined = 0;
			yield;
		}
		const item = pending.pop();
		if (item === undefined) break;
		if (item.depth > 1e3) return finish(`JSON value exceeds maximum nesting depth of ${MAX_JSON_DEPTH}`);
		const value = item.value;
		if (typeof value === "object" && value !== null && types.isProxy(value)) return finish("JSON values cannot contain proxies");
		if (value === null || typeof value === "string" || typeof value === "boolean") continue;
		if (typeof value === "number") {
			if (!Number.isFinite(value)) return finish("JSON numbers must be finite");
		} else if (Array.isArray(value)) {
			for (let index = 0; index < value.length; index += 1) {
				const descriptor = Object.getOwnPropertyDescriptor(value, index);
				if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) return finish("JSON arrays require dense data properties without accessors");
				pending.push({
					value: descriptor.value,
					depth: item.depth + 1
				});
			}
		} else if (isRecord(value)) {
			const prototype = Object.getPrototypeOf(value);
			if (prototype !== Object.prototype && prototype !== null) return finish("JSON objects require ordinary data properties");
			for (const key of Reflect.ownKeys(value)) {
				const descriptor = Object.getOwnPropertyDescriptor(value, key);
				if (descriptor?.enumerable !== true) continue;
				if (typeof key !== "string") return finish("JSON object keys must be strings");
				if (!Object.hasOwn(descriptor, "value")) return finish("JSON objects cannot contain accessors");
				pending.push({
					value: descriptor.value,
					depth: item.depth + 1
				});
			}
		} else return finish("Invalid JSON value");
	}
	return finish(undefined);
}
var MAX_JSON_DEPTH, isRecord, immutableValidation, jsonValueValidationIssue, preserveJsonValue, validatedJsonValue, jsonValueSchema, objectValidation, objectProjection, jsonObjectSchema;
function init_jsonValue() {
	return (init_jsonValue = __esmMin((() => {
		init_immutableJson();
		MAX_JSON_DEPTH = 1e3;
		isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
		immutableValidation = new WeakMap();
		jsonValueValidationIssue = (root) => {
			const steps = jsonValueValidationSteps(root);
			for (;;) {
				const step = steps.next();
				if (step.done) return step.value;
			}
		};
		preserveJsonValue = (value) => {
			const immutableCandidate = value;
			if (isImmutableJsonSnapshot(immutableCandidate)) return value;
			if (Array.isArray(value)) {
				const copy = [];
				for (let index = 0; index < value.length; index += 1) copy.push(preserveJsonValue(value[index]));
				return copy;
			}
			if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, preserveJsonValue(child)]));
			return value;
		};
		validatedJsonValue = z.unknown().superRefine((value, context) => {
			const issue = jsonValueValidationIssue(value);
			if (issue !== undefined) context.addIssue({
				code: "custom",
				message: issue,
				continue: false
			});
		}).transform((value) => value);
		validatedJsonValue._zod.toJSONSchema = () => ({});
		jsonValueSchema = z.unknown().nonoptional().pipe(validatedJsonValue).transform(preserveJsonValue);
		jsonValueSchema._zod.toJSONSchema = () => ({});
		objectValidation = z.custom(isRecord, "Expected JSON object");
		objectProjection = () => ({
			type: "object",
			additionalProperties: {}
		});
		objectValidation._zod.toJSONSchema = objectProjection;
		jsonObjectSchema = jsonValueSchema.pipe(objectValidation);
		jsonObjectSchema._zod.toJSONSchema = objectProjection;
	})))();
}

//#endregion
export { jsonValueValidationIssue as a, freezeJsonSnapshot as c, init_immutableJson as d, isImmutableJsonSnapshot as f, jsonValueSchema as i, freezeOwnedJsonSnapshotSteps as l, init_jsonValue as n, jsonValueValidationSteps as o, jsonObjectSchema as r, canBorrowParsedJsonSnapshot as s, MAX_JSON_DEPTH as t, immutableJsonSnapshotMember as u };