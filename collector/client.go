package collector

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// 请求头与端点。Request headers and endpoint.
const (
	// HeaderPubkey 携带 33 字节压缩公钥小写 hex。HeaderPubkey carries the compressed public key hex.
	HeaderPubkey = "X-BitFSCollector-Pubkey"
	// HeaderSignature 携带 low-S DER 小写 hex。HeaderSignature carries the low-S DER hex.
	HeaderSignature = "X-BitFSCollector-Signature"
	// HeaderSigVersion 携带签名版本。HeaderSigVersion carries the signature version.
	HeaderSigVersion = "X-BitFSCollector-SigVersion"
	// SubmissionsPath 是提交端点。SubmissionsPath is the submission endpoint.
	SubmissionsPath = "/v1/submissions"
	// ContentType 是请求体类型。ContentType is the request body type.
	ContentType = "application/gzip"
)

// Receipt 是服务端成功响应。Receipt is the server success response.
type Receipt struct {
	Version    int    `json:"version"`
	ArchiveID  string `json:"archiveId"`
	ReceivedAt string `json:"receivedAt"`
	PubkeyHex  string `json:"pubkeyHex"`
	DigestHex  string `json:"digestHex"`
	Bytes      string `json:"bytes"`
}

// ErrorBody 是服务端失败响应。ErrorBody is the server error response.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Submit 发送实际 gzip 字节并返回归档回执；重试必须复用同一 gzip 与签名。
// Submit posts the exact gzip bytes; retries must reuse the same bytes and signature.
func Submit(ctx context.Context, client *http.Client, endpoint string, gzipBytes, signature []byte, pubkey PublicKey) (*Receipt, error) {
	if client == nil {
		return nil, Errorf("Submit", CodeMalformedRequest, "client", "http client is required")
	}
	if len(gzipBytes) == 0 {
		return nil, Errorf("Submit", CodeMalformedRequest, "body", "gzip bytes must not be empty")
	}
	digest := DigestGzip(gzipBytes)
	if err := VerifyDigestSignature(pubkey, digest, signature); err != nil {
		return nil, err
	}
	url := strings.TrimSuffix(endpoint, "/") + SubmissionsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(gzipBytes))
	if err != nil {
		return nil, Wrap(err, "Submit", CodeMalformedRequest, "request")
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set(HeaderPubkey, fmt.Sprintf("%x", pubkey))
	req.Header.Set(HeaderSignature, hex.EncodeToString(signature))
	req.Header.Set(HeaderSigVersion, fmt.Sprintf("%d", SigVersion))
	res, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, Wrap(ctx.Err(), "Submit", CodeCanceled, "context")
		}
		return nil, Wrap(err, "Submit", CodeStorageFailed, "transport")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, Wrap(err, "Submit", CodeStorageFailed, "response")
	}
	if res.StatusCode != http.StatusOK {
		var eb ErrorBody
		_ = json.Unmarshal(body, &eb)
		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, Errorf("Submit", CodeUnauthorized, "signature", "%s", eb.Message)
		case http.StatusTooManyRequests:
			return nil, Errorf("Submit", CodeRateLimited, "server", "%s", eb.Message)
		case http.StatusRequestEntityTooLarge, http.StatusBadRequest:
			return nil, Errorf("Submit", CodeMalformedRequest, "server", "%s", eb.Message)
		default:
			return nil, Errorf("Submit", CodeStorageFailed, "server", "http %d %s", res.StatusCode, eb.Message)
		}
	}
	var receipt Receipt
	if err := json.Unmarshal(body, &receipt); err != nil {
		return nil, Wrap(err, "Submit", CodeStorageFailed, "receipt")
	}
	if receipt.ArchiveID == "" {
		return nil, Errorf("Submit", CodeStorageFailed, "receipt", "missing archiveId")
	}
	if !strings.EqualFold(receipt.PubkeyHex, fmt.Sprintf("%x", pubkey)) {
		return nil, Errorf("Submit", CodeStorageFailed, "receipt", "pubkey mismatch")
	}
	if !strings.EqualFold(receipt.DigestHex, fmt.Sprintf("%x", digest)) {
		return nil, Errorf("Submit", CodeStorageFailed, "receipt", "digest mismatch")
	}
	return &receipt, nil
}
