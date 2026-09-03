import fs from 'node:fs';

export interface FileMagic {
  type: string;
  isBinary: boolean;
  isExecutable: boolean;
  isArchive: boolean;
  mime?: string;
}

export async function detectMagicBytes(filePath: string): Promise<FileMagic> {
  const buffer = Buffer.alloc(1024);
  let fd: number | null = null;
  try {
    fd = fs.openSync(filePath, 'r');
    const bytesRead = fs.readSync(fd, buffer, 0, 1024, 0);
    const header = buffer.subarray(0, bytesRead);

    // PE: 'MZ'
    if (bytesRead >= 2 && header[0] === 0x4d && header[1] === 0x5a) {
      return { type: 'PE', isBinary: true, isExecutable: true, isArchive: false, mime: 'application/x-dosexec' };
    }

    // ELF: 0x7F 'E' 'L' 'F'
    if (bytesRead >= 4 && header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
      return { type: 'ELF', isBinary: true, isExecutable: true, isArchive: false, mime: 'application/x-executable' };
    }

    // Mach-O
    if (
      bytesRead >= 4 &&
      ((header[0] === 0xfe && header[1] === 0xed && header[2] === 0xfa && (header[3] === 0xce || header[3] === 0xcf)) ||
        (header[0] === 0xcf && header[1] === 0xfa && header[2] === 0xed && header[3] === 0xfe) ||
        (header[0] === 0xca && header[1] === 0xfe && header[2] === 0xba && header[3] === 0xbe))
    ) {
      return { type: 'Mach-O', isBinary: true, isExecutable: true, isArchive: false, mime: 'application/x-mach-binary' };
    }

    // ZIP
    if (bytesRead >= 4 && header[0] === 0x50 && header[1] === 0x4b && (header[2] === 0x03 || header[2] === 0x05)) {
      return { type: 'ZIP', isBinary: true, isExecutable: false, isArchive: true, mime: 'application/zip' };
    }

    // GZIP
    if (bytesRead >= 2 && header[0] === 0x1f && header[1] === 0x8b) {
      return { type: 'GZIP', isBinary: true, isExecutable: false, isArchive: true, mime: 'application/gzip' };
    }

    // PNG
    if (bytesRead >= 4 && header[0] === 0x89 && header[1] === 0x50 && header[2] === 0x4e && header[3] === 0x47) {
      return { type: 'PNG', isBinary: true, isExecutable: false, isArchive: false, mime: 'image/png' };
    }

    // JPEG
    if (bytesRead >= 3 && header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff) {
      return { type: 'JPEG', isBinary: true, isExecutable: false, isArchive: false, mime: 'image/jpeg' };
    }

    let nonTextCount = 0;
    const sampleSize = Math.min(bytesRead, 512);
    for (let i = 0; i < sampleSize; i++) {
      const b = header[i];
      if (b === 0 || (b < 7 && b !== 9 && b !== 10 && b !== 13)) {
        nonTextCount++;
      }
    }

    const isBinary = sampleSize > 0 && nonTextCount / sampleSize > 0.05;
    return {
      type: isBinary ? 'BINARY' : 'TEXT',
      isBinary,
      isExecutable: false,
      isArchive: false,
      mime: isBinary ? 'application/octet-stream' : 'text/plain'
    };
  } catch {
    return { type: 'UNKNOWN', isBinary: false, isExecutable: false, isArchive: false };
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // ignore
      }
    }
  }
}

export async function readTextFileSafe(filePath: string, maxBytes = 5 * 1024 * 1024): Promise<string | null> {
  try {
    const stats = fs.statSync(filePath);
    if (stats.size > maxBytes) {
      return null;
    }
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

export function extractPrintableStrings(buffer: Buffer, minLen = 4, maxCount = 5000): string[] {
  const strings: string[] = [];
  let current: number[] = [];

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte >= 32 && byte <= 126) {
      current.push(byte);
    } else {
      if (current.length >= minLen) {
        strings.push(Buffer.from(current).toString('ascii'));
        if (strings.length >= maxCount) break;
      }
      current = [];
    }
  }
  if (current.length >= minLen && strings.length < maxCount) {
    strings.push(Buffer.from(current).toString('ascii'));
  }
  return strings;
}
