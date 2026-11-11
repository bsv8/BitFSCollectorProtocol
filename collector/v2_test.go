package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestValidateArchiveID(t *testing.T) {
	if err := ValidateArchiveID("0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateArchiveID("ABC"); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("short id must be invalid_request, got %v", err)
	}
	if err := ValidateArchiveID("0123456789ABCDEF0123456789ABCDEF"); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("upper-case id must be invalid_request, got %v", err)
	}
}

func TestValidateListParams(t *testing.T) {
	if err := ValidateListParams(0, 100); err != nil {
		t.Fatal(err)
	}
	if err := ValidateListParams(-1, 10); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("negative after must fail, got %v", err)
	}
	if err := ValidateListParams(0, 0); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("zero limit must fail, got %v", err)
	}
	if err := ValidateListParams(0, 1001); !IsCode(err, CodeMalformedRequest) {
		t.Fatalf("oversize limit must fail, got %v", err)
	}
}

func TestParseBearer(t *testing.T) {
	tok, err := ParseBearer("Bearer abc123")
	if err != nil || tok != "abc123" {
		t.Fatalf("parse failed: %q %v", tok, err)
	}
	if _, err := ParseBearer("Basic abc"); err == nil {
		t.Fatal("non-bearer must fail")
	}
	if _, err := ParseBearer("Bearer "); err == nil {
		t.Fatal("empty token must fail")
	}
}

func TestParseRetryAfter(t *testing.T) {
	res := &http.Response{Header: http.Header{"Retry-After": []string{"3"}}}
	if d := ParseRetryAfter(res); d != 3*time.Second {
		t.Fatalf("seconds retry-after mismatch: %v", d)
	}
	future := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	res2 := &http.Response{Header: http.Header{"Retry-After": []string{future}}}
	if d := ParseRetryAfter(res2); d <= 0 || d > 11*time.Second {
		t.Fatalf("date retry-after out of range: %v", d)
	}
	if d := ParseRetryAfter(&http.Response{Header: http.Header{}}); d != 0 {
		t.Fatalf("missing header must be 0, got %v", d)
	}
}

func TestPullClientAgainstStub(t *testing.T) {
	const archiveID = "0123456789abcdef0123456789abcdef"
	summaries := []ArchiveSummary{{ArchiveID: archiveID, Sequence: 7, ReceivedAt: "2026-01-01T00:00:00Z", PubkeyHex: "ab", DigestHex: "cd", Bytes: 5}}
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ArchiveAuthHeader) != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"unauthorized","message":"bad token"}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == ArchivesPath:
			after, _ := strconv.Atoi(r.URL.Query().Get("after"))
			_ = after
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(ListArchivesResponse{Archives: summaries, NextAfter: 7})
		case r.Method == http.MethodGet && r.URL.Path == ArchivesPath+"/"+archiveID+"/gzip":
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write([]byte("gzip-bytes"))
		case r.Method == http.MethodGet && r.URL.Path == ArchivesPath+"/"+archiveID+"/sig":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"digestHex":"cd"}`))
		case r.Method == http.MethodPost && r.URL.Path == ArchivesPath+"/"+archiveID+"/ack":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"archiveId":"` + archiveID + `","acknowledgedAt":"2026-01-01T01:00:00Z","repeated":false}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"invalid_request","message":"not found"}`))
		}
	}))
	defer stub.Close()
	c := &PullClient{BaseURL: stub.URL, Token: "test-token", Client: stub.Client()}
	list, err := c.List(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Archives) != 1 || list.NextAfter != 7 {
		t.Fatalf("unexpected list %+v", list)
	}
	gzip, err := c.FetchGzip(context.Background(), archiveID)
	if err != nil || string(gzip) != "gzip-bytes" {
		t.Fatalf("gzip fetch failed: %q %v", gzip, err)
	}
	sig, err := c.FetchSig(context.Background(), archiveID)
	if err != nil || len(sig) == 0 {
		t.Fatalf("sig fetch failed: %v", err)
	}
	ack, err := c.Ack(context.Background(), archiveID)
	if err != nil || ack.Repeated {
		t.Fatalf("ack failed: %+v %v", ack, err)
	}
	// 401 映射为 unauthorized（配置错误不停重试）。
	bad := &PullClient{BaseURL: stub.URL, Token: "wrong", Client: stub.Client()}
	if _, err := bad.List(context.Background(), 0, 10); !IsCode(err, CodeUnauthorized) {
		t.Fatalf("bad token must be unauthorized, got %v", err)
	}
	// 空 token 本地拒绝。
	empty := &PullClient{BaseURL: stub.URL, Client: stub.Client()}
	if _, err := empty.List(context.Background(), 0, 10); !IsCode(err, CodeInvalidEvidence) {
		t.Fatalf("empty token must be invalid_evidence, got %v", err)
	}
}
