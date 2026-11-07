package collector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

var testRecords = []FileRecord{
	{SeedHashHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", FileName: "example.pdf", Description: "", FileSizeBytes: "123456", MediaType: "application/pdf"},
	{SeedHashHex: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", FileName: "notes.txt", Description: "lorem ipsum", FileSizeBytes: "42", MediaType: "text/plain"},
}

// 固定向量：与工程仓 parity 向量同一记录集，规范字节必须逐字节一致。
const pinnedCanonical = `{"version":1,"files":[{"seedHashHex":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae","fileName":"notes.txt","description":"lorem ipsum","fileSizeBytes":"42","mediaType":"text/plain"},{"seedHashHex":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","fileName":"example.pdf","description":"","fileSizeBytes":"123456","mediaType":"application/pdf"}]}`

const pinnedDigestHex = "bd8ede08118a2a6cf376e0d4c7692e6d2d0e68fbd8fbc975348789d14e66c68d"

// pinnedGzipBase64 是同一记录集经 TS 侧压缩的 gzip 字节：摘要与签名跨语言
// 核对以它为共同输入（不要求两端压缩字节相同）。
const pinnedGzipBase64 = "H4sIAAAAAAAAA23OP0/DMBCH4a+Cbo7a2D47dkamTiywIYazcxaW8seKDUqp+t1RgIWCdLrt9+q5wDuvJS0z9KKBmEYu0D9foDAPJyqvJ96gBxmk8Wi8sTGG/TnnUasgBtWiUPtJOXStQat8pDY6S5qtNdIY7ojhO/1AE0MP81K5HOpWoYGBS1hTrl8CGJeVp7uUy9v0M3lMH3x/rrsKUEIDEw+Jns55D1Xe6jGPlGa4NrdmVr4NiNLZGEQQ6Cj6iME6Z6J3EmVHjILRoPNOYSB02jnhO6ult1r/NvNGUx75kIf4R/0PVUiF2txwKecxBdpXx71zfbl+Ap8g/Xd/AQAA"

func testPrivKey(t *testing.T) *ec.PrivateKey {
	t.Helper()
	// go-sdk v1.2.18 的 PrivateKeyFromBytes 返回 (priv, pub)，无 error。
	key, _ := ec.PrivateKeyFromBytes(bytes.Repeat([]byte{0x11}, 32))
	if key == nil {
		t.Fatal("nil private key")
	}
	return key
}

func TestEncodeSubmissionCanonical(t *testing.T) {
	// 故意逆序输入，输出必须排序且与固定向量逐字节一致。
	reversed := []FileRecord{testRecords[1], testRecords[0]}
	got, err := EncodeSubmission(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != pinnedCanonical {
		t.Fatalf("canonical mismatch:\n%s", got)
	}
}

func TestEncodeSubmissionRejects(t *testing.T) {
	if _, err := EncodeSubmission(nil); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("empty files must be invalid_request, got %v", err)
	}
	dup := []FileRecord{testRecords[0], testRecords[0]}
	if _, err := EncodeSubmission(dup); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("duplicate hash must be invalid_request, got %v", err)
	}
	bad := []FileRecord{{SeedHashHex: "xyz", FileName: "a", Description: "", FileSizeBytes: "1", MediaType: "text/plain"}}
	if _, err := EncodeSubmission(bad); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("bad hash must be invalid_request, got %v", err)
	}
}

func TestDigestSignVerifyRoundTrip(t *testing.T) {
	canonical, err := EncodeSubmission(testRecords)
	if err != nil {
		t.Fatal(err)
	}
	// Go 自产 gzip 只要求解压往返一致，不要求与 TS 字节相同。
	selfGzip, err := GzipJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := GunzipJSON(selfGzip)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, canonical) {
		t.Fatal("gzip round-trip mismatch")
	}
	// 跨语言核对输入：TS 侧压缩字节。
	gzipBytes, err := base64.StdEncoding.DecodeString(pinnedGzipBase64)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = GunzipJSON(gzipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != pinnedCanonical {
		t.Fatal("pinned gzip does not decompress to pinned canonical")
	}
	signer, err := NewPrivateKeySigner(testPrivKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sig, pub, err := SignGzip(context.Background(), signer, gzipBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pub[:]); got != "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa" {
		t.Fatalf("unexpected pubkey %s", got)
	}
	digest := DigestGzip(gzipBytes)
	if hex.EncodeToString(digest[:]) != pinnedDigestHex {
		t.Fatalf("digest mismatch %x", digest)
	}
	// low-S 断言：S 必须 ≤ 群阶一半。
	parsed, err := ec.ParseDERSignature(sig)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.S.Cmp(halfOrder) == 1 {
		t.Fatal("signature is high-S")
	}
	// 篡改字节必须验签失败。
	evil := append([]byte(nil), gzipBytes...)
	evil[len(evil)/2] ^= 0x01
	if err := VerifyDigestSignature(pub, DigestGzip(evil), sig); !IsCode(err, CodeUnauthorized) {
		t.Fatalf("tampered bytes must be unauthorized, got %v", err)
	}
	// 非压缩/错误长度公钥拒绝。
	var badPub PublicKey
	if err := VerifyDigestSignature(badPub, digest, sig); err == nil {
		t.Fatal("zero pubkey must fail")
	}
}

func TestSubmitAgainstStub(t *testing.T) {
	canonical, err := EncodeSubmission(testRecords)
	if err != nil {
		t.Fatal(err)
	}
	gzipBytes, err := GzipJSON(canonical)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewPrivateKeySigner(testPrivKey(t))
	if err != nil {
		t.Fatal(err)
	}
	sig, pub, err := SignGzip(context.Background(), signer, gzipBytes)
	if err != nil {
		t.Fatal(err)
	}
	var gotBody []byte
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != SubmissionsPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get(HeaderSigVersion) != "1" || r.Header.Get(HeaderPubkey) == "" || r.Header.Get(HeaderSignature) == "" {
			t.Errorf("missing headers %+v", r.Header)
		}
		var buf bytes.Buffer
		buf.ReadFrom(r.Body)
		gotBody = buf.Bytes()
		digest := DigestGzip(gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":1,"archiveId":"abc","receivedAt":"2026-01-01T00:00:00Z","pubkeyHex":"` + hex.EncodeToString(pub[:]) + `","digestHex":"` + hex.EncodeToString(digest[:]) + `","bytes":"` + strconv.Itoa(len(gotBody)) + `"}`))
	}))
	defer stub.Close()
	receipt, err := Submit(context.Background(), stub.Client(), stub.URL, gzipBytes, sig, pub)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ArchiveID != "abc" {
		t.Fatalf("unexpected receipt %+v", receipt)
	}
	if !bytes.Equal(gotBody, gzipBytes) {
		t.Fatal("stub did not receive exact gzip bytes")
	}
}
