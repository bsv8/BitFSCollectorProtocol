package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// SigFile 是 .sig 文件的固定封装：只记录签名版本与签名值及核验所需
// 公钥、摘要，不包含文件信息解析结果。
// SigFile is the fixed .sig envelope: version + signature + verification inputs.
type SigFile struct {
	DigestHex    string `json:"digestHex"`
	PubkeyHex    string `json:"pubkeyHex"`
	SignatureHex string `json:"signatureHex"`
	SigVersion   int    `json:"sigVersion"`
}

// EncodeSigFile 编码规范 JSON（键排序、无空白）。EncodeSigFile encodes canonical JSON.
func EncodeSigFile(digest Digest32, pubkey PublicKey, signature []byte) ([]byte, error) {
	if _, err := ParsePublicKey(pubkey[:]); err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("%w: signature must not be empty", ErrInvalidEvidence)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	doc := SigFile{
		DigestHex:    fmt.Sprintf("%x", digest),
		PubkeyHex:    fmt.Sprintf("%x", pubkey),
		SignatureHex: fmt.Sprintf("%x", signature),
		SigVersion:   SigVersion,
	}
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
