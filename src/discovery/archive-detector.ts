import fs from 'node:fs';

export interface ArchiveInspection {
  isArchive: boolean;
  type: string;
  entryCount: number;
  totalUncompressedBytes: number;
  isSuspicious: boolean;
  isZipBomb: boolean;
  hasPathTraversal: boolean;
  suspiciousEntries: string[];
}

export function inspectZipArchiveSafe(filePath: string): ArchiveInspection {
  const result: ArchiveInspection = {
    isArchive: false,
    type: 'ZIP',
    entryCount: 0,
    totalUncompressedBytes: 0,
    isSuspicious: false,
    isZipBomb: false,
    hasPathTraversal: false,
    suspiciousEntries: []
  };

  try {
    const stats = fs.statSync(filePath);
    const fileSize = stats.size;
    if (fileSize < 22) return result;

    const buffer = fs.readFileSync(filePath);
    if (buffer[0] !== 0x50 || buffer[1] !== 0x4b) return result;

    result.isArchive = true;

    let eocdOffset = -1;
    for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--) {
      if (buffer[i] === 0x50 && buffer[i + 1] === 0x4b && buffer[i + 2] === 0x05 && buffer[i + 3] === 0x06) {
        eocdOffset = i;
        break;
      }
    }

    if (eocdOffset !== -1) {
      result.entryCount = buffer.readUInt16LE(eocdOffset + 10);
      const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

      let currentOffset = cdOffset;
      let totalUncompressed = 0;

      for (let i = 0; i < result.entryCount && currentOffset + 46 <= buffer.length; i++) {
        if (
          buffer[currentOffset] !== 0x50 ||
          buffer[currentOffset + 1] !== 0x4b ||
          buffer[currentOffset + 2] !== 0x01 ||
          buffer[currentOffset + 3] !== 0x02
        ) {
          break;
        }

        const uncompressedSize = buffer.readUInt32LE(currentOffset + 24);
        const fileNameLength = buffer.readUInt16LE(currentOffset + 28);
        const extraFieldLength = buffer.readUInt16LE(currentOffset + 30);
        const fileCommentLength = buffer.readUInt16LE(currentOffset + 32);

        totalUncompressed += uncompressedSize;

        const nameStart = currentOffset + 46;
        const nameEnd = nameStart + fileNameLength;
        if (nameEnd <= buffer.length) {
          const entryName = buffer.subarray(nameStart, nameEnd).toString('utf-8');

          if (entryName.includes('../') || entryName.includes('..\\') || entryName.startsWith('/') || entryName.startsWith('\\')) {
            result.hasPathTraversal = true;
            result.isSuspicious = true;
            result.suspiciousEntries.push(`Path Traversal Entry: ${entryName}`);
          }

          if (entryName.endsWith('.zip') || entryName.endsWith('.tar.gz') || entryName.endsWith('.7z')) {
            result.suspiciousEntries.push(`Nested Archive: ${entryName}`);
          }

          if (entryName.endsWith('.exe') || entryName.endsWith('.dll') || entryName.endsWith('.bat') || entryName.endsWith('.vbs') || entryName.endsWith('.ps1')) {
            result.suspiciousEntries.push(`Executable Entry: ${entryName}`);
          }
        }

        currentOffset += 46 + fileNameLength + extraFieldLength + fileCommentLength;
      }

      result.totalUncompressedBytes = totalUncompressed;

      if (fileSize > 0 && totalUncompressed / fileSize > 100 && totalUncompressed > 20 * 1024 * 1024) {
        result.isZipBomb = true;
        result.isSuspicious = true;
        result.suspiciousEntries.push(`Potential Zip Bomb: ratio ${(totalUncompressed / fileSize).toFixed(0)}:1`);
      }
    }

    return result;
  } catch {
    return result;
  }
}
