package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// v2 接管接口的数据契约：内网拉取、下载、确认只用 Go SDK，v1 上传保持兼容。
// v2 takeover contract: intranet pull/download/ack in Go only; v1 upload unchanged.

const (
	// ArchivesPath 是清单根路径。ArchivesPath lists pending archives.
	ArchivesPath = "/v2/archives"
	// ArchiveAuthHeader 是 Bearer 认证头。ArchiveAuthHeader carries the pull token.
	ArchiveAuthHeader = "Authorization"
	// ArchiveBearerPrefix 是认证头前缀。ArchiveBearerPrefix is the auth scheme.
	ArchiveBearerPrefix = "Bearer "
)

// ArchiveState 是公网清单状态：待接管、已接管、已清理。
// ArchiveState is the public manifest state.
type ArchiveState string

const (
	// ArchiveStatePending 待接管。Pending takeover.
	ArchiveStatePending ArchiveState = "pending"
	// ArchiveStateAcknowledged 已接管（已 ack）。Acknowledged.
	ArchiveStateAcknowledged ArchiveState = "acknowledged"
	// ArchiveStateCleaned 已清理（文件已删）。Cleaned.
	ArchiveStateCleaned ArchiveState = "cleaned"
)

// ArchiveSummary 是一条待接管归档的清单项：按 Sequence 升序分页。
// ArchiveSummary is one manifest entry for pagination by Sequence.
type ArchiveSummary struct {
	// ArchiveID 是归档编号（32 位小写 hex）。Archive ID.
	ArchiveID string `json:"archiveId"`
	// Sequence 是服务端持久接收顺序（从 1 起，不代表客户端修改顺序）。Server receive order.
	Sequence int64 `json:"sequence"`
	// ReceivedAt 是固定接收时间（UTC RFC3339）。Fixed receive time.
	ReceivedAt string `json:"receivedAt"`
	// PubkeyHex 是提交者公钥小写 hex（66 字符）。Submitter public key hex.
	PubkeyHex string `json:"pubkeyHex"`
	// DigestHex 是签名摘要小写 hex（64 字符）。Signature digest hex.
	DigestHex string `json:"digestHex"`
	// Bytes 是 gzip 字节数。Gzip byte length.
	Bytes int64 `json:"bytes"`
}

// ListArchivesResponse 是分页清单响应。
// ListArchivesResponse is the paged manifest response.
type ListArchivesResponse struct {
	// Archives 按 Sequence 升序。Archives in ascending Sequence.
	Archives []ArchiveSummary `json:"archives"`
	// NextAfter 是下一页的 after 参数（本页最大 Sequence，无更多时与请求 after 相同）。Next page cursor.
	NextAfter int64 `json:"nextAfter"`
}

// AckResponse 是确认响应：重复确认同样成功，Repeated 置 true。
// AckResponse is the ack result; repeated acks succeed with Repeated=true.
type AckResponse struct {
	// ArchiveID 是确认的归档编号。Acknowledged archive ID.
	ArchiveID string `json:"archiveId"`
	// AcknowledgedAt 是确认时间（UTC RFC3339）。Ack time.
	AcknowledgedAt string `json:"acknowledgedAt"`
	// Repeated 是是否为重复确认。Whether this ack repeats a prior one.
	Repeated bool `json:"repeated"`
}

// ValidateArchiveID 校验归档编号（32 位小写 hex）。
// ValidateArchiveID checks the archive ID shape.
func ValidateArchiveID(id string) error {
	if len(id) != 32 {
		return Errorf("ValidateArchiveID", CodeMalformedRequest, "archiveId", "archiveId must be 32 hex characters")
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return Errorf("ValidateArchiveID", CodeMalformedRequest, "archiveId", "archiveId must be lower-case hex")
		}
	}
	return nil
}

// ValidateListParams 校验分页参数（limit 1..1000，after >= 0）。
// ValidateListParams checks pagination bounds.
func ValidateListParams(after int64, limit int) error {
	if after < 0 {
		return Errorf("ValidateListParams", CodeMalformedRequest, "after", "after must be >= 0")
	}
	if limit < 1 || limit > 1000 {
		return Errorf("ValidateListParams", CodeMalformedRequest, "limit", "limit must be 1..1000")
	}
	return nil
}

// ListArchivesURL 拼接清单地址。ListArchivesURL builds the list URL.
func ListArchivesURL(base string, after int64, limit int) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(base), "/")
	return trimmed + ArchivesPath + "?after=" + strconv.FormatInt(after, 10) + "&limit=" + strconv.Itoa(limit)
}

// ArchiveGzipURL 拼接下载地址（kind 为 gzip 或 sig）。ArchiveGzipURL builds download URLs.
func ArchiveGzipURL(base, archiveID, kind string) string {
	return strings.TrimSuffix(strings.TrimSpace(base), "/") + ArchivesPath + "/" + url.PathEscape(archiveID) + "/" + kind
}

// ArchiveAckURL 拼接确认地址。ArchiveAckURL builds the ack URL.
func ArchiveAckURL(base, archiveID string) string {
	return strings.TrimSuffix(strings.TrimSpace(base), "/") + ArchivesPath + "/" + url.PathEscape(archiveID) + "/ack"
}

// bearerHeader 构造认证头（token 为空则不设，由调用方判错）。
func bearerHeader(req *http.Request, token string) {
	if token != "" {
		req.Header.Set(ArchiveAuthHeader, ArchiveBearerPrefix+token)
	}
}

// ParseBearer 从认证头解析 token，失败返回 invalid_evidence。
// ParseBearer extracts the bearer token.
func ParseBearer(header string) (string, error) {
	if !strings.HasPrefix(header, ArchiveBearerPrefix) {
		return "", Errorf("ParseBearer", CodeInvalidEvidence, "authorization", "missing bearer token")
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, ArchiveBearerPrefix))
	if token == "" {
		return "", Errorf("ParseBearer", CodeInvalidEvidence, "authorization", "empty bearer token")
	}
	return token, nil
}

// IsRetryableStatus 报告状态码是否可重试（网络错误由调用方另判；429 与 5xx 可重试）。
// IsRetryableStatus reports retryable HTTP statuses.
func IsRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// ParseRetryAfter 解析 Retry-After（秒或 HTTP 日期），无则返回 0。
// ParseRetryAfter parses Retry-After seconds or HTTP dates.
func ParseRetryAfter(res *http.Response) time.Duration {
	if res == nil {
		return 0
	}
	v := strings.TrimSpace(res.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

// PullClient 是内网拉取客户端：清单、下载、确认，统一 Bearer。
// PullClient pulls, downloads and acks with one bearer token.
type PullClient struct {
	// BaseURL 是公网基地址（不含路径后缀也可）。Public base URL.
	BaseURL string
	// Token 是拉取凭据（独立于上传签名）。Pull credential.
	Token string
	// Client 是 HTTP 客户端。HTTP client.
	Client *http.Client
	// MaxBodyBytes 是下载上限。Download cap.
	MaxBodyBytes int64
}

func (c *PullClient) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

func (c *PullClient) maxBytes() int64 {
	if c.MaxBodyBytes > 0 {
		return c.MaxBodyBytes
	}
	return 32 << 20
}

func (c *PullClient) checkToken() error {
	if strings.TrimSpace(c.Token) == "" {
		return Errorf("PullClient", CodeInvalidEvidence, "token", "bearer token is required")
	}
	return nil
}

func readCapped(res *http.Response, cap int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(res.Body, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > cap {
		return nil, Errorf("PullClient", CodeMalformedRequest, "body", "body exceeds %d bytes", cap)
	}
	return body, nil
}

func (c *PullClient) failForStatus(op string, res *http.Response, body []byte) error {
	var eb ErrorBody
	_ = json.Unmarshal(body, &eb)
	msg := eb.Message
	if msg == "" {
		msg = "http " + strconv.Itoa(res.StatusCode)
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return Errorf(op, CodeUnauthorized, "bearer", "%s", msg)
	case res.StatusCode == http.StatusTooManyRequests:
		return Errorf(op, CodeRateLimited, "server", "%s", msg)
	case res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusRequestEntityTooLarge || res.StatusCode == http.StatusNotFound:
		return Errorf(op, CodeMalformedRequest, "server", "%s", msg)
	default:
		return Errorf(op, CodeStorageFailed, "server", "%s", msg)
	}
}

// List 拉取一页待接管清单（按 sequence 升序）。
// List fetches one page of pending archives.
func (c *PullClient) List(ctx context.Context, after int64, limit int) (*ListArchivesResponse, error) {
	if err := ValidateListParams(after, limit); err != nil {
		return nil, err
	}
	if err := c.checkToken(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ListArchivesURL(c.BaseURL, after, limit), nil)
	if err != nil {
		return nil, Wrap(err, "List", CodeMalformedRequest, "request")
	}
	bearerHeader(req, c.Token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, Wrap(ctx.Err(), "List", CodeCanceled, "context")
		}
		return nil, Wrap(err, "List", CodeStorageFailed, "transport")
	}
	defer res.Body.Close()
	body, err := readCapped(res, 1<<20)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, c.failForStatus("List", res, body)
	}
	var out ListArchivesResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, Wrap(err, "List", CodeStorageFailed, "response")
	}
	for i, a := range out.Archives {
		if err := ValidateArchiveID(a.ArchiveID); err != nil {
			return nil, Wrap(err, "List", CodeStorageFailed, fmt.Sprintf("archives[%d]", i))
		}
	}
	return &out, nil
}

// download 取原始字节（kind 仅 gzip 或 sig），超限报错。
// download fetches raw bytes for one archive artifact.
func (c *PullClient) download(ctx context.Context, op, archiveID, kind string) ([]byte, error) {
	if err := ValidateArchiveID(archiveID); err != nil {
		return nil, err
	}
	if kind != "gzip" && kind != "sig" {
		return nil, Errorf(op, CodeMalformedRequest, "kind", "kind must be gzip or sig")
	}
	if err := c.checkToken(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ArchiveGzipURL(c.BaseURL, archiveID, kind), nil)
	if err != nil {
		return nil, Wrap(err, op, CodeMalformedRequest, "request")
	}
	bearerHeader(req, c.Token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, Wrap(ctx.Err(), op, CodeCanceled, "context")
		}
		return nil, Wrap(err, op, CodeStorageFailed, "transport")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := readCapped(res, 1<<20)
		return nil, c.failForStatus(op, res, body)
	}
	body, err := readCapped(res, c.maxBytes())
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, Errorf(op, CodeStorageFailed, "body", "empty artifact")
	}
	return body, nil
}

// FetchGzip 下载原始 gzip。FetchGzip downloads the raw gzip.
func (c *PullClient) FetchGzip(ctx context.Context, archiveID string) ([]byte, error) {
	return c.download(ctx, "FetchGzip", archiveID, "gzip")
}

// FetchSig 下载签名封装。FetchSig downloads the .sig envelope.
func (c *PullClient) FetchSig(ctx context.Context, archiveID string) ([]byte, error) {
	return c.download(ctx, "FetchSig", archiveID, "sig")
}

// Ack 确认已可靠接管；重复确认成功（Repeated=true）。
// Ack confirms durable takeover; repeats succeed.
func (c *PullClient) Ack(ctx context.Context, archiveID string) (*AckResponse, error) {
	if err := ValidateArchiveID(archiveID); err != nil {
		return nil, err
	}
	if err := c.checkToken(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ArchiveAckURL(c.BaseURL, archiveID), nil)
	if err != nil {
		return nil, Wrap(err, "Ack", CodeMalformedRequest, "request")
	}
	bearerHeader(req, c.Token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, Wrap(ctx.Err(), "Ack", CodeCanceled, "context")
		}
		return nil, Wrap(err, "Ack", CodeStorageFailed, "transport")
	}
	defer res.Body.Close()
	body, err := readCapped(res, 1<<20)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, c.failForStatus("Ack", res, body)
	}
	var out AckResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, Wrap(err, "Ack", CodeStorageFailed, "response")
	}
	if out.ArchiveID != archiveID {
		return nil, Errorf("Ack", CodeStorageFailed, "receipt", "archiveId mismatch")
	}
	return &out, nil
}
