import { CollectorError, SIG_VERSION } from "./record.js";
import { bytesToHex, hexToBytes, verifyDigestSignature } from "./crypto.js";

/** 请求头与端点。Request headers and endpoint. */
export const HEADER_PUBKEY = "X-BitFSCollector-Pubkey";
/** low-S DER 小写 hex。low-S DER lowercase hex. */
export const HEADER_SIGNATURE = "X-BitFSCollector-Signature";
/** 签名版本。Signature version. */
export const HEADER_SIG_VERSION = "X-BitFSCollector-SigVersion";
/** 提交端点。Submission endpoint. */
export const SUBMISSIONS_PATH = "/v1/submissions";
/** 请求体类型。Request body type. */
export const CONTENT_TYPE = "application/gzip";

/**
 * 归一化提交地址：已含提交路径（含自定义前缀）则原样使用，
 * 否则补上默认路径。兼容旧配置（只填基地址）。
 * Normalize the endpoint: use as-is with a path, else append the default.
 */
export function submissionUrl(endpoint: string): string {
  let trimmed = endpoint.trim();
  while (trimmed.endsWith("/")) trimmed = trimmed.slice(0, -1);
  if (trimmed.endsWith(SUBMISSIONS_PATH)) return trimmed;
  return trimmed + SUBMISSIONS_PATH;
}

/** 服务端成功响应。Server success response. */
export interface Receipt {
  version: number;
  archiveId: string;
  receivedAt: string;
  pubkeyHex: string;
  digestHex: string;
  bytes: string;
}

/** 服务端失败响应。Server error response. */
export interface ErrorBody {
  code: string;
  message: string;
}

function errorForStatus(status: number, body: ErrorBody): CollectorError {
  const message = body.message || `http ${status}`;
  if (status === 401) return new CollectorError("unauthorized", "signature", message);
  if (status === 429) return new CollectorError("rate_limited", "server", message);
  if (status === 400 || status === 413) return new CollectorError("invalid_request", "server", message);
  return new CollectorError("storage_failed", "server", message);
}

/**
 * 发送实际 gzip 字节并返回归档回执；endpoint 为完整提交 URL
 * （可带自定义前缀），只填基地址时自动补默认路径。
 * 重试必须复用同一 gzip 与签名。
 * Post the exact gzip bytes; endpoint is the full submission URL.
 */
export async function submit(
  endpoint: string,
  gzip: Uint8Array,
  signature: Uint8Array,
  pubkey: Uint8Array,
  digest: Uint8Array,
  signal?: AbortSignal,
): Promise<Receipt> {
  if (gzip.byteLength === 0) throw new CollectorError("invalid_request", "body", "gzip bytes must not be empty");
  verifyDigestSignature(pubkey, digest, signature);
  const url = submissionUrl(endpoint);
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": CONTENT_TYPE,
        [HEADER_PUBKEY]: bytesToHex(pubkey),
        [HEADER_SIGNATURE]: bytesToHex(signature),
        [HEADER_SIG_VERSION]: String(SIG_VERSION),
      },
      body: gzip as BodyInit,
      ...(signal === undefined ? {} : { signal }),
    });
  } catch (error) {
    if (signal?.aborted) throw new CollectorError("canceled", "context", "submission was cancelled");
    throw new CollectorError("storage_failed", "transport", error instanceof Error ? error.message : String(error));
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => ({ code: "", message: "" }))) as ErrorBody;
    throw errorForStatus(response.status, body);
  }
  const receipt = (await response.json()) as Receipt;
  if (!receipt.archiveId) throw new CollectorError("storage_failed", "receipt", "missing archiveId");
  if (receipt.pubkeyHex.toLowerCase() !== bytesToHex(pubkey)) {
    throw new CollectorError("storage_failed", "receipt", "pubkey mismatch");
  }
  if (receipt.digestHex.toLowerCase() !== bytesToHex(digest)) {
    throw new CollectorError("storage_failed", "receipt", "digest mismatch");
  }
  return receipt;
}

/** .sig 文件的固定封装。Fixed .sig envelope. */
export interface SigFile {
  digestHex: string;
  pubkeyHex: string;
  signatureHex: string;
  sigVersion: number;
}

/** 编码 .sig 规范 JSON（键排序、无空白）。Encode canonical .sig JSON. */
export function encodeSigFile(digest: Uint8Array, pubkey: Uint8Array, signature: Uint8Array): string {
  if (signature.byteLength === 0) throw new CollectorError("invalid_evidence", "signature", "signature must not be empty");
  const doc: SigFile = {
    digestHex: bytesToHex(digest),
    pubkeyHex: bytesToHex(pubkey),
    signatureHex: bytesToHex(signature),
    sigVersion: SIG_VERSION,
  };
  return JSON.stringify(doc);
}

/** 解析并核验 .sig 封装（版本与签名值，不解析文件信息）。Parse a .sig envelope. */
export function parseSigFile(text: string): SigFile {
  const doc = JSON.parse(text) as SigFile;
  if (doc.sigVersion !== SIG_VERSION || typeof doc.digestHex !== "string" || typeof doc.pubkeyHex !== "string" || typeof doc.signatureHex !== "string") {
    throw new CollectorError("invalid_evidence", "sigfile", "invalid .sig envelope");
  }
  verifyDigestSignature(hexToBytes(doc.pubkeyHex), hexToBytes(doc.digestHex), hexToBytes(doc.signatureHex));
  return doc;
}
