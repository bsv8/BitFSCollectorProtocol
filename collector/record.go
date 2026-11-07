package collector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// SubmissionVersion 是当前唯一的提交版本号。The only valid submission version.
const SubmissionVersion = 1

// SignatureDomain 是摘要域前缀，防止 BitFS wire 签名跨协议重放。
// SignatureDomain separates collector digests from BitFS wire signatures.
const SignatureDomain = "BitFSCollector/submission-v1\n"

// SigVersion 是当前唯一的签名版本号。The only valid signature version.
const SigVersion = 1

// FileRecord 是一条文件提交记录：身份仅为 SeedHashHex（内容哈希，64 位小写 hex）。
// FileRecord: identity is SeedHashHex only; FileSizeBytes 用十进制字符串
// (decimal string) 避免 Go 与 JavaScript 整数精度差异。
type FileRecord struct {
	SeedHashHex   string `json:"seedHashHex"`
	FileName      string `json:"fileName"`
	Description   string `json:"description"`
	FileSizeBytes string `json:"fileSizeBytes"`
	MediaType     string `json:"mediaType"`
}

// Submission 是一次提交的批量记录。Submission is one batch of records.
type Submission struct {
	Version int          `json:"version"`
	Files   []FileRecord `json:"files"`
}

// EncodeSubmission 校验记录并编码跨语言逐字节一致的规范 JSON：
// 键顺序固定、无空白、文件按 SeedHashHex 升序、不转义 HTML。
// EncodeSubmission validates records and encodes byte-identical canonical JSON.
func EncodeSubmission(records []FileRecord) ([]byte, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("%w: files must not be empty", ErrMalformedRequest)
	}
	sorted := append([]FileRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].SeedHashHex < sorted[j].SeedHashHex })
	for i, r := range sorted {
		if err := ValidateFileRecord(r); err != nil {
			return nil, fmt.Errorf("%w: files[%d]: %v", ErrMalformedRequest, i, err)
		}
		if i > 0 && sorted[i-1].SeedHashHex == r.SeedHashHex {
			return nil, fmt.Errorf("%w: duplicate seedHashHex", ErrMalformedRequest)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(Submission{Version: SubmissionVersion, Files: sorted}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
