package collector

import (
	"fmt"
	"math/big"
	"regexp"
	"unicode/utf8"
)

var (
	hashHexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uint64Pattern   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	mediaTypeRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$`)
	uint64Max       = func() *big.Int { v, _ := new(big.Int).SetString("18446744073709551615", 10); return v }()
)

// ValidateFileRecord 校验单条记录的字段边界（长度、字符集、规范整数）。
// ValidateFileRecord checks field limits, charsets and canonical integers.
func ValidateFileRecord(r FileRecord) error {
	if !hashHexPattern.MatchString(r.SeedHashHex) {
		return fmt.Errorf("seedHashHex must be 64 lower-case hex characters")
	}
	nameBytes := len(r.FileName)
	if nameBytes < 1 || nameBytes > 255 || !utf8.ValidString(r.FileName) {
		return fmt.Errorf("fileName must be 1..255 UTF-8 bytes")
	}
	for _, c := range r.FileName {
		if c < 0x20 || (c >= 0x7f && c <= 0x9f) {
			return fmt.Errorf("fileName contains control characters")
		}
	}
	if r.FileName == "." || r.FileName == ".." {
		return fmt.Errorf("fileName must be a basename")
	}
	for i := 0; i < len(r.FileName); i++ {
		if r.FileName[i] == '/' || r.FileName[i] == '\\' {
			return fmt.Errorf("fileName must be a basename")
		}
	}
	if len(r.Description) > 2048 || !utf8.ValidString(r.Description) {
		return fmt.Errorf("description must be 0..2048 UTF-8 bytes")
	}
	if !uint64Pattern.MatchString(r.FileSizeBytes) {
		return fmt.Errorf("fileSizeBytes must be a canonical decimal string")
	}
	size, _ := new(big.Int).SetString(r.FileSizeBytes, 10)
	if size.Cmp(uint64Max) > 0 {
		return fmt.Errorf("fileSizeBytes exceeds uint64")
	}
	if len(r.MediaType) < 1 || len(r.MediaType) > 255 || !mediaTypeRegexp.MatchString(r.MediaType) {
		return fmt.Errorf("mediaType must be lower-case type/subtype")
	}
	return nil
}
