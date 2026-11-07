/** 单条文件提交记录：身份仅为 seedHashHex（内容哈希，64 位小写 hex）。 */
export interface FileRecord {
  /** 内容哈希，64 位小写 hex。Content hash, 64 lowercase hex chars. */
  seedHashHex: string;
  /** 文件名，1..255 UTF-8 字节 basename。File name, basename. */
  fileName: string;
  /** 介绍，0..2048 UTF-8 字节，缺省空字符串。Description, defaults to "". */
  description: string;
  /** 长度，十进制规范字符串（避免整数精度差异）。Size, canonical decimal string. */
  fileSizeBytes: string;
  /** 小写 type/subtype。Lower-case MIME type. */
  mediaType: string;
}

/** 当前唯一的提交版本号。The only valid submission version. */
export const SUBMISSION_VERSION = 1;

/** 摘要域前缀，防止 BitFS wire 签名跨协议重放。Domain prefix against cross-protocol replay. */
export const SIGNATURE_DOMAIN = "BitFSCollector/submission-v1\n";

/** 当前唯一的签名版本号。The only valid signature version. */
export const SIG_VERSION = 1;

const HASH_HEX = /^[0-9a-f]{64}$/;
const UINT64 = /^(0|[1-9][0-9]*)$/;
const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/;
const UINT64_MAX = (1n << 64n) - 1n;

function assertFileName(value: string): void {
  const byteLength = new TextEncoder().encode(value).byteLength;
  if (byteLength < 1 || byteLength > 255) {
    throw new CollectorError("invalid_request", "fileName", "fileName must be 1..255 UTF-8 bytes");
  }
  if (value === "." || value === ".." || value.includes("/") || value.includes("\\")) {
    throw new CollectorError("invalid_request", "fileName", "fileName must be a basename");
  }
  for (const unit of value) {
    const code = unit.codePointAt(0) ?? 0;
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f)) {
      throw new CollectorError("invalid_request", "fileName", "fileName contains control characters");
    }
  }
}

/** 校验单条记录字段边界。Validate one record's field limits. */
export function validateFileRecord(record: FileRecord): void {
  if (!HASH_HEX.test(record.seedHashHex)) {
    throw new CollectorError("invalid_request", "seedHashHex", "seedHashHex must be 64 lower-case hex characters");
  }
  assertFileName(record.fileName);
  if (new TextEncoder().encode(record.description).byteLength > 2048) {
    throw new CollectorError("invalid_request", "description", "description must be 0..2048 UTF-8 bytes");
  }
  if (!UINT64.test(record.fileSizeBytes) || BigInt(record.fileSizeBytes) > UINT64_MAX) {
    throw new CollectorError("invalid_request", "fileSizeBytes", "fileSizeBytes must be a canonical decimal string within uint64");
  }
  if (record.mediaType.length < 1 || record.mediaType.length > 255 || !MEDIA_TYPE.test(record.mediaType)) {
    throw new CollectorError("invalid_request", "mediaType", "mediaType must be lower-case type/subtype");
  }
}

/**
 * 编码跨语言逐字节一致的规范 JSON：键顺序固定、无空白、文件按
 * seedHashHex 升序。Encode byte-identical canonical JSON.
 */
export function encodeSubmission(records: FileRecord[]): string {
  if (records.length === 0) throw new CollectorError("invalid_request", "files", "files must not be empty");
  const sorted = [...records].sort((a, b) => (a.seedHashHex < b.seedHashHex ? -1 : a.seedHashHex > b.seedHashHex ? 1 : 0));
  sorted.forEach((record, index) => {
    try {
      validateFileRecord(record);
    } catch (error) {
      throw new CollectorError("invalid_request", `files[${index}]`, error instanceof Error ? error.message : String(error));
    }
    if (index > 0 && sorted[index - 1]?.seedHashHex === record.seedHashHex) {
      throw new CollectorError("invalid_request", "files", "duplicate seedHashHex");
    }
  });
  let out = '{"version":1,"files":[';
  sorted.forEach((record, index) => {
    if (index > 0) out += ",";
    out += `{"seedHashHex":${JSON.stringify(record.seedHashHex)},"fileName":${JSON.stringify(record.fileName)},"description":${JSON.stringify(record.description)},"fileSizeBytes":${JSON.stringify(record.fileSizeBytes)},"mediaType":${JSON.stringify(record.mediaType)}}`;
  });
  return `${out}]}`;
}

/** 稳定错误码。Stable error codes. */
export type CollectorErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "storage_failed"
  | "rate_limited"
  | "invalid_evidence"
  | "signer_unavailable"
  | "canceled";

/** 统一错误。SDK error type. */
export class CollectorError extends Error {
  constructor(
    public readonly code: CollectorErrorCode,
    public readonly field: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "CollectorError";
  }
}
