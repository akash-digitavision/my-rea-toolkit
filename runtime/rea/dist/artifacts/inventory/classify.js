import { locateGodotPck } from "../GodotPckLocation.js";
import { sameRegularFileState } from "../../filesystem/RegularFile.js";
import { containsPyInstallerArchive } from "../pyinstaller/CArchiveLayout.js";
import { classifyArtifactContent } from "./ArtifactGraphConstruction.js";
import { abortIfNeeded } from "../ArtifactHash.js";
import { createArtifactClassificationProbe } from "../ArtifactClassificationProbe.js";
import { hasZipSignature, isZipPackageFormat, zipPackageFormatForPath, } from "../../domain/zipPackageFormat.js";
import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { hashStableRootArtifactHandle, openRootArtifact, } from "./hashStableRootArtifact.js";
import { readMachoHeaderPrefixFacts } from "../../domain/apple/machoContainer.js";
/** Classify and hash one file root through the same stable open descriptor. */
export const classifyAndHashRoot = async (path, directory, expectedMetadata, options) => {
    return options.resourceScope.run(async () => {
        const result = await classifyAndHashRootForInventory(path, directory, expectedMetadata, options);
        const rootSource = result.rootSource;
        if (rootSource !== undefined) {
            const owner = {
                kind: "file-handle",
                handle: rootSource.owner,
                resource: `root artifact descriptor for ${path}`,
            };
            const cleanupAttempt = await options.resourceScope.release(owner);
            if (cleanupAttempt.kind === "failed")
                throw options.resourceScope.cleanupFailure({ kind: "completed" }, [
                    cleanupAttempt,
                ]);
        }
        return { format: result.format, digest: result.digest };
    });
};
/** Classify a root and retain its admitted ZIP descriptor for child inventory. */
export const classifyAndHashRootForInventory = async (path, directory, expectedMetadata, options) => {
    if (directory)
        return { format: "directory", digest: null, rootSource: undefined };
    const ownedHandle = await openRootArtifact(path, options.resourceScope, options.signal);
    const handle = ownedHandle.handle;
    const owner = {
        kind: "file-handle",
        handle: ownedHandle,
        resource: `root artifact descriptor for ${path}`,
    };
    let outcome;
    try {
        const initial = await handle.stat();
        if (!sameRegularFileState(expectedMetadata, initial))
            throw new ArtifactReaderFailure("integrity", `Root artifact changed before inventory: ${path}`);
        const format = await classifyRootFormat(path, handle, options.signal);
        const digest = await hashStableRootArtifactHandle(path, handle, initial, options.signal);
        const retainSource = isZipPackageFormat(format) ||
            format === "mach-o-universal" ||
            format === "godot-pck" ||
            format === "pyinstaller";
        outcome = {
            kind: "completed",
            value: {
                format,
                digest,
                rootSource: retainSource
                    ? { handle, initial, owner: ownedHandle }
                    : undefined,
            },
        };
    }
    catch (cause) {
        outcome = { kind: "failed", cause };
    }
    if (outcome.kind === "failed" || outcome.value.rootSource === undefined) {
        const cleanupAttempt = await options.resourceScope.release(owner);
        if (cleanupAttempt.kind === "failed")
            throw options.resourceScope.cleanupFailure(outcome, [cleanupAttempt]);
    }
    if (outcome.kind === "failed")
        throw outcome.cause;
    return outcome.value;
};
const classifyRootFormat = async (path, handle, signal) => {
    const probe = createArtifactClassificationProbe();
    const chunk = Buffer.alloc(64 * 1024);
    while (probe.length < probe.limit) {
        abortIfNeeded(signal);
        const read = await handle.read(chunk, 0, Math.min(chunk.length, probe.limit - probe.length), probe.length);
        abortIfNeeded(signal);
        if (read.bytesRead === 0)
            break;
        probe.write(chunk.subarray(0, read.bytesRead));
    }
    const archiveBytes = (await handle.stat()).size;
    const evidence = probe.finish(archiveBytes);
    abortIfNeeded(signal);
    const lower = path.toLowerCase();
    if (hasZipSignature(evidence.prefix))
        return zipRootPackageFormat(lower);
    if (lower.endsWith(".pkg") &&
        evidence.prefix.subarray(0, 4).equals(Buffer.from("xar!")))
        return "pkg";
    if (lower.endsWith(".dmg") &&
        (await hasKolyTrailer(handle, archiveBytes, signal)))
        return "dmg";
    if (await locateGodotPck(handle, archiveBytes, signal, evidence.prefix))
        return "godot-pck";
    const fatSliceHeaders = await readRootFatSliceHeaders(handle, evidence.fatSliceHeaders, signal);
    const format = classifyArtifactContent(path, {
        ...evidence,
        ...(fatSliceHeaders === undefined ? {} : { fatSliceHeaders }),
    }, archiveBytes).format;
    if (["elf", "pe", "mach-o", "mach-o-universal"].includes(format)) {
        const packaged = await containsPyInstallerArchive(handle, archiveBytes, signal);
        abortIfNeeded(signal);
        if (packaged)
            return "pyinstaller";
    }
    return format;
};
/** Read exact FAT header windows missed by the bounded prefix probe. */
const readRootFatSliceHeaders = async (handle, existing, signal) => {
    if (existing === undefined)
        return undefined;
    const { header } = existing;
    const sliceHeadersByOffset = new Map(existing.sliceHeadersByOffset);
    for (let index = 0; index < header.slices.length; index += 1) {
        const slice = header.slices[index];
        const observed = slice === undefined ? undefined : sliceHeadersByOffset.get(slice.offset);
        if (slice === undefined ||
            header.rangeIssues[index] !== null ||
            slice.size < 4 ||
            (observed !== undefined && observed.magic !== null))
            continue;
        const headerLength = Math.min(12, slice.size);
        const thinHeader = Buffer.alloc(headerLength);
        let bytesRead = 0;
        while (bytesRead < thinHeader.length) {
            abortIfNeeded(signal);
            const read = await handle.read(thinHeader, bytesRead, thinHeader.length - bytesRead, slice.offset + bytesRead);
            abortIfNeeded(signal);
            if (read.bytesRead === 0)
                break;
            bytesRead += read.bytesRead;
        }
        sliceHeadersByOffset.set(slice.offset, readMachoHeaderPrefixFacts(thinHeader.subarray(0, bytesRead)));
    }
    return { header, sliceHeadersByOffset };
};
/** App Pack is a verified ZIP root role; nested .app members retain their observed format. */
const zipRootPackageFormat = (lower) => lower.endsWith(".app")
    ? "app-pack"
    : (zipPackageFormatForPath(lower) ?? "zip");
const hasKolyTrailer = async (handle, size, signal) => {
    if (size < 512)
        return false;
    const trailer = Buffer.alloc(4);
    let bytes = 0;
    while (bytes < trailer.length) {
        abortIfNeeded(signal);
        const read = await handle.read(trailer, bytes, trailer.length - bytes, size - 512 + bytes);
        abortIfNeeded(signal);
        if (read.bytesRead === 0)
            return false;
        bytes += read.bytesRead;
    }
    return trailer.equals(Buffer.from("koly"));
};
