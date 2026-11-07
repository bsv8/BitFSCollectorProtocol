package collector

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// PublicKey 是协议身份公钥：33 字节压缩 secp256k1 规范编码。
// PublicKey is the 33-byte compressed secp256k1 identity key.
type PublicKey [33]byte

// Digest32 是 32 字节签名摘要。Digest32 is a 32-byte signing digest.
type Digest32 [32]byte

// Bytes 返回副本。Bytes returns a copy.
func (d Digest32) Bytes() []byte {
	out := make([]byte, 32)
	copy(out, d[:])
	return out
}

// IsZero 报告是否为全零哨兵。IsZero reports the all-zero sentinel.
func (d Digest32) IsZero() bool { return d == Digest32{} }

// ParsePublicKey 解析并校验 33 字节压缩公钥，拒绝非规范编码。
// ParsePublicKey parses a compressed key and rejects non-canonical encodings.
func ParsePublicKey(raw []byte) (PublicKey, error) {
	if len(raw) != 33 {
		return PublicKey{}, fmt.Errorf("%w: public key must be 33 bytes", ErrInvalidEvidence)
	}
	key, err := ec.ParsePubKey(raw)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	if !bytes.Equal(key.Compressed(), raw) {
		return PublicKey{}, fmt.Errorf("%w: public key is not canonical compressed", ErrInvalidEvidence)
	}
	var out PublicKey
	copy(out[:], raw)
	return out, nil
}

// ParsePublicKeyHex 解析小写 hex 公钥。ParsePublicKeyHex parses lowercase hex.
func ParsePublicKeyHex(s string) (PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return ParsePublicKey(raw)
}

// DigestGzip 计算签名摘要：SHA-256(域前缀 + gzip 原始字节)。
// DigestGzip is SHA-256(domain prefix + raw gzip bytes).
func DigestGzip(gzipBytes []byte) Digest32 {
	h := sha256.New()
	h.Write([]byte(SignatureDomain))
	h.Write(gzipBytes)
	var out Digest32
	copy(out[:], h.Sum(nil))
	return out
}

// GzipJSON 压缩规范 JSON。不同实现允许输出不同压缩字节，签名只认实际字节。
// GzipJSON compresses canonical JSON; byte-identical output is not required.
func GzipJSON(canonical []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(canonical); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GunzipJSON 解压并返回规范 JSON 原文（SDK 自检用，服务端不解析）。
// GunzipJSON decompresses back to canonical JSON (self-check only).
func GunzipJSON(gzipBytes []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(gzipBytes))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
