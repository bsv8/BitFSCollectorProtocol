package collector

import (
	"bytes"
	"context"
	"math/big"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// secp256k1N 是群阶定值，half 用于 low-S 判定。
var secpN, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
var halfOrder = new(big.Int).Rsh(secpN, 1)

// Signer 是 SDK 唯一的密钥操作端口：固定公钥 + 对给定摘要的 secp256k1 签名。
// Signer signs the given 32-byte digest and returns low-S DER; the private
// key never enters the SDK. Signer 只签摘要，绝不自行哈希。
type Signer interface {
	// PublicKey 返回固定压缩公钥，调用周期内不得变化。
	PublicKey() PublicKey
	// Sign 对 digest 做 secp256k1 签名，返回 low-S DER。
	Sign(ctx context.Context, digest Digest32) ([]byte, error)
}

// SignGzip 对实际 gzip 字节求摘要并签名，返回 low-S DER 与公钥。
// SignGzip digests the exact gzip bytes and signs via the host Signer.
func SignGzip(ctx context.Context, signer Signer, gzipBytes []byte) (signature []byte, pubkey PublicKey, err error) {
	if signer == nil {
		return nil, PublicKey{}, Errorf("SignGzip", CodeSignerUnavailable, "signer", "signer is required")
	}
	pubkey = signer.PublicKey()
	if _, err := ParsePublicKey(pubkey[:]); err != nil {
		return nil, PublicKey{}, err
	}
	digest := DigestGzip(gzipBytes)
	if digest.IsZero() {
		return nil, PublicKey{}, Errorf("SignGzip", CodeInvalidEvidence, "digest", "digest is zero")
	}
	signature, err = signer.Sign(ctx, digest)
	if err != nil {
		if ctx.Err() != nil {
			return nil, PublicKey{}, Wrap(ctx.Err(), "SignGzip", CodeCanceled, "context")
		}
		return nil, PublicKey{}, Wrap(err, "SignGzip", CodeSignerUnavailable, "signer")
	}
	if err := VerifyDigestSignature(pubkey, digest, signature); err != nil {
		return nil, PublicKey{}, err
	}
	out := make([]byte, len(signature))
	copy(out, signature)
	return out, pubkey, nil
}

// VerifyDigestSignature 校验摘要签名：严格 DER、low-S、ECDSA 三门。
// VerifyDigestSignature enforces strict DER, low-S and ECDSA verification.
func VerifyDigestSignature(pubkey PublicKey, digest Digest32, signature []byte) error {
	if _, err := ParsePublicKey(pubkey[:]); err != nil {
		return err
	}
	if digest.IsZero() {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "digest", "digest is zero")
	}
	sig, err := ec.ParseDERSignature(signature)
	if err != nil {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "signature", "malformed DER: %v", err)
	}
	roundTrip, err := sig.ToDER()
	if err != nil {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "signature", "DER re-encode failed: %v", err)
	}
	if !bytes.Equal(roundTrip, signature) {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "signature", "non-canonical DER")
	}
	if sig.S.Cmp(halfOrder) == 1 {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "signature", "high-S signature rejected")
	}
	pub, err := ec.ParsePubKey(pubkey[:])
	if err != nil {
		return Errorf("VerifyDigestSignature", CodeInvalidEvidence, "public_key", "%v", err)
	}
	if !sig.Verify(digest.Bytes(), pub) {
		return Errorf("VerifyDigestSignature", CodeUnauthorized, "signature", "ecdsa verify failed")
	}
	return nil
}

// PrivateKeySigner 是 *ec.PrivateKey 的本地 Signer 适配器：私钥不外泄。
// PrivateKeySigner adapts a software key; it never exposes the key.
type PrivateKeySigner struct {
	key       *ec.PrivateKey
	publicKey PublicKey
}

// NewPrivateKeySigner 封装软件私钥。NewPrivateKeySigner wraps a software key.
func NewPrivateKeySigner(privateKey *ec.PrivateKey) (*PrivateKeySigner, error) {
	if privateKey == nil {
		return nil, Errorf("NewPrivateKeySigner", CodeInvalidEvidence, "private_key", "private key is required")
	}
	pubkey, err := ParsePublicKey(privateKey.PubKey().Compressed())
	if err != nil {
		return nil, err
	}
	return &PrivateKeySigner{key: privateKey, publicKey: pubkey}, nil
}

// PublicKey 返回构造时固定的压缩公钥。PublicKey returns the fixed key.
func (s *PrivateKeySigner) PublicKey() PublicKey { return s.publicKey }

// Sign 对摘要签名并归一化为 low-S DER。Sign signs and normalizes to low-S DER.
func (s *PrivateKeySigner) Sign(_ context.Context, digest Digest32) ([]byte, error) {
	if s == nil || s.key == nil {
		return nil, Errorf("PrivateKeySigner.Sign", CodeInvalidEvidence, "private_key", "signer is not initialized")
	}
	if digest.IsZero() {
		return nil, Errorf("PrivateKeySigner.Sign", CodeInvalidEvidence, "digest", "digest is zero")
	}
	sig, err := s.key.Sign(digest.Bytes())
	if err != nil {
		return nil, Wrap(err, "PrivateKeySigner.Sign", CodeSignerUnavailable, "signer")
	}
	if sig.S.Cmp(halfOrder) == 1 {
		sig.S.Sub(secpN, sig.S)
	}
	der, err := sig.ToDER()
	if err != nil {
		return nil, Wrap(err, "PrivateKeySigner.Sign", CodeSignerUnavailable, "signer")
	}
	if len(der) == 0 {
		return nil, Errorf("PrivateKeySigner.Sign", CodeSignerUnavailable, "signer", "empty signature")
	}
	if err := VerifyDigestSignature(s.publicKey, digest, der); err != nil {
		return nil, err
	}
	return der, nil
}
