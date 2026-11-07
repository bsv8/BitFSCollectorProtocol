import { gzipSync, gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { CollectorError, SIGNATURE_DOMAIN } from "./record.js";

/** secp256k1 群阶定值，half 用于 low-S 判定。secp256k1 order for low-S checks. */
const HALF_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") >> 1n;

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-f]*$/i.test(hex) || hex.length % 2 !== 0) {
    throw new CollectorError("invalid_evidence", "hex", "expected even-length hex");
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/**
 * 压缩规范 JSON。不同实现允许输出不同压缩字节，签名只认实际字节。
 * Compress canonical JSON; byte-identical output is not required.
 */
export function gzipJson(canonical: string): Uint8Array {
  // @types/node 未声明 mtime，但运行时支持；mtime=0 使向量可复现。
  // mtime is untyped yet supported at runtime; zero keeps vectors reproducible.
  return gzipSync(Buffer.from(canonical, "utf8"), { mtime: 0 } as unknown as Parameters<typeof gzipSync>[1]);
}

/** 解压并返回规范 JSON 原文（SDK 自检用，服务端不解析）。Decompress to canonical JSON. */
export function gunzipJson(gzip: Uint8Array): string {
  return gunzipSync(gzip).toString("utf8");
}

/**
 * 计算签名摘要：SHA-256(域前缀 + gzip 原始字节）。
 * Digest is SHA-256(domain prefix + raw gzip bytes).
 */
export function digestGzip(gzip: Uint8Array): Uint8Array {
  return new Uint8Array(
    createHash("sha256").update(Buffer.from(SIGNATURE_DOMAIN, "utf8")).update(gzip).digest(),
  );
}

/** 校验 33 字节压缩公钥。Validate a 33-byte compressed public key. */
export function parsePublicKey(raw: Uint8Array): Uint8Array {
  if (raw.byteLength !== 33) throw new CollectorError("invalid_evidence", "public_key", "public key must be 33 bytes");
  const point = secp256k1.Point.fromBytes(raw);
  const canonical = point.toBytes(true);
  if (bytesToHex(canonical) !== bytesToHex(raw)) {
    throw new CollectorError("invalid_evidence", "public_key", "public key is not canonical compressed");
  }
  return raw.slice();
}

/**
 * SDK 唯一的密钥操作端口：固定公钥 + 对给定摘要签名。
 * The only signing port: fixed key + sign the given digest.
 */
export interface Signer {
  /** 固定压缩公钥，调用周期内不得变化。Fixed compressed key. */
  publicKey(): Uint8Array;
  /** 对 32 字节摘要签名，返回 low-S DER。Sign the digest, return low-S DER. */
  sign(digest: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
}

/**
 * 对实际 gzip 字节求摘要并签名，返回 low-S DER 与公钥。
 * Digest the exact gzip bytes and sign via the host Signer.
 */
export async function signGzip(signer: Signer, gzip: Uint8Array, signal?: AbortSignal): Promise<{ signature: Uint8Array; pubkey: Uint8Array }> {
  if (signal?.aborted) throw new CollectorError("canceled", "context", "signing was cancelled");
  const pubkey = parsePublicKey(signer.publicKey());
  const digest = digestGzip(gzip);
  const signature = await signer.sign(digest, signal);
  verifyDigestSignature(pubkey, digest, signature);
  return { signature: signature.slice(), pubkey: pubkey.slice() };
}

/**
 * 校验摘要签名：严格 DER、low-S、ECDSA 三门。
 * Enforce strict DER, low-S and ECDSA verification.
 */
export function verifyDigestSignature(pubkey: Uint8Array, digest: Uint8Array, signature: Uint8Array): void {
  parsePublicKey(pubkey);
  if (digest.byteLength !== 32) throw new CollectorError("invalid_evidence", "digest", "digest must be 32 bytes");
  let sig: ReturnType<typeof secp256k1.Signature.fromBytes>;
  try {
    sig = secp256k1.Signature.fromBytes(signature, "der");
  } catch {
    throw new CollectorError("invalid_evidence", "signature", "malformed DER signature");
  }
  const s = BigInt(`0x${sig.s.toString(16)}`);
  if (s === 0n || s > HALF_N) throw new CollectorError("invalid_evidence", "signature", "high-S signature rejected");
  if (bytesToHex(sig.toBytes("der")) !== bytesToHex(signature)) {
    throw new CollectorError("invalid_evidence", "signature", "non-canonical DER signature");
  }
  // 摘要已是 32 字节，必须关闭预哈希，否则会被二次哈希。
  // The digest is final: prehash must be off, or it gets hashed twice.
  if (!secp256k1.verify(sig.toBytes(), digest, pubkey, { prehash: false })) {
    throw new CollectorError("unauthorized", "signature", "ecdsa verify failed");
  }
}

/** 从软件私钥构造本地 Signer（测试与工具用，生产由宿主提供）。Local software Signer. */
export function privateKeySigner(privateKey: Uint8Array): Signer {
  if (privateKey.byteLength !== 32) throw new CollectorError("invalid_evidence", "private_key", "private key must be 32 bytes");
  const pubkey = secp256k1.getPublicKey(privateKey, true);
  return {
    publicKey: () => pubkey.slice(),
    sign: async (digest: Uint8Array, signal?: AbortSignal) => {
      if (signal?.aborted) throw new CollectorError("canceled", "context", "signing was cancelled");
      if (digest.byteLength !== 32) throw new CollectorError("invalid_evidence", "digest", "digest must be 32 bytes");
      const signature = secp256k1.sign(digest, privateKey, { lowS: true, prehash: false, format: "der" });
      verifyDigestSignature(pubkey, digest, signature);
      return signature.slice();
    },
  };
}

export { bytesToHex, hexToBytes };
