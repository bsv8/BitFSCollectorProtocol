import { describe, expect, it } from "vitest";
import {
  CollectorError,
  digestGzip,
  encodeSubmission,
  gunzipJson,
  gzipJson,
  privateKeySigner,
  signGzip,
  verifyDigestSignature,
  type FileRecord,
} from "../src/index.js";

const RECORDS: FileRecord[] = [
  {
    seedHashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    fileName: "example.pdf",
    description: "",
    fileSizeBytes: "123456",
    mediaType: "application/pdf",
  },
  {
    seedHashHex: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    fileName: "notes.txt",
    description: "lorem ipsum",
    fileSizeBytes: "42",
    mediaType: "text/plain",
  },
];

// 固定向量：与 Go 测试、工程仓 parity 向量同一记录集。
const PINNED_CANONICAL =
  '{"version":1,"files":[{"seedHashHex":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","fileName":"notes.txt","description":"lorem ipsum","fileSizeBytes":"42","mediaType":"text/plain"},{"seedHashHex":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","fileName":"example.pdf","description":"","fileSizeBytes":"123456","mediaType":"application/pdf"}]}';
const PINNED_DIGEST = "bd8ede08118a2a6cf376e0d4c7692e6d2d0e68fbd8fbc975348789d14e66c68d";
const PINNED_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

function priv(): Uint8Array {
  return new Uint8Array(32).fill(0x11);
}

describe("encodeSubmission", () => {
  it("逆序输入输出排序后的固定字节", () => {
    expect(encodeSubmission([RECORDS[1]!, RECORDS[0]!])).toBe(PINNED_CANONICAL);
  });
  it("空集与重复哈希拒绝", () => {
    expect(() => encodeSubmission([])).toThrowError(CollectorError);
    expect(() => encodeSubmission([RECORDS[0]!, RECORDS[0]!])).toThrowError(CollectorError);
  });
});

describe("digest/sign/verify", () => {
  it("摘要、签名、验签往返一致", async () => {
    const canonical = encodeSubmission(RECORDS);
    const gzip = gzipJson(canonical);
    expect(gunzipJson(gzip)).toBe(canonical);
    const signer = privateKeySigner(priv());
    const { signature, pubkey } = await signGzip(signer, gzip);
    const digest = digestGzip(gzip);
    expect(Buffer.from(pubkey).toString("hex")).toBe(PINNED_PUBKEY);
    // 同一 zlib 设置下自产 gzip 与工程仓向量字节一致，摘要相同。
    expect(Buffer.from(digest).toString("hex")).toBe(PINNED_DIGEST);
    verifyDigestSignature(pubkey, digest, signature);
    // 工程仓固定向量签名在本 SDK 下可验（跨实现一致）。
    const pinnedSig = new Uint8Array(
      Buffer.from(
        "3044022046cf9047bf446ac07f2fc19c82c4ef621377b22457cedb1de677b627cdab9203022014b4464103e80e9efba8e89768e507ad9769723c965e5132910eb84105228744",
        "hex",
      ),
    );
    verifyDigestSignature(pubkey, digest, pinnedSig);
    const evil = new Uint8Array(gzip);
    evil[evil.byteLength >> 1]! ^= 0x01;
    expect(() => verifyDigestSignature(pubkey, digestGzip(evil), signature)).toThrowError(CollectorError);
  });
});
