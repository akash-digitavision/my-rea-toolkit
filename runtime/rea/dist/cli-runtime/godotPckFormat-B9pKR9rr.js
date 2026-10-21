import { __esmMin } from "./rolldown-runtime-DXoylpqc.js";
import { err, init_result, ok } from "./reconstructionObligationLedgerSchemas-B5WvxjEy.js";

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
//#region dist/domain/godotPckFormat.js
var GODOT_PCK_MAGIC, hasGodotPckHeader;
function init_godotPckFormat() {
	return (init_godotPckFormat = __esmMin((() => {
		GODOT_PCK_MAGIC = 1129333831;
		hasGodotPckHeader = (bytes) => bytes.length >= 4 && bytes[0] === 71 && bytes[1] === 68 && bytes[2] === 80 && bytes[3] === 67;
	})))();
}

//#endregion
export { GODOT_PCK_MAGIC, dosMzImageByteLength, hasGodotPckHeader, init_dosMz, init_godotPckFormat, observeMzWindowsHeader, parseDosMzHeader };