package collector

import "fmt"

// ErrorCode 是稳定错误码，分支只看 Code 不匹配文本。
// ErrorCode is stable; switch on Code, never on messages.
type ErrorCode string

const (
	// CodeMalformedRequest 请求体、记录或请求头非法（HTTP 400/413）。
	CodeMalformedRequest ErrorCode = "invalid_request"
	// CodeUnauthorized 验签失败（HTTP 401），不进入归档。
	CodeUnauthorized ErrorCode = "unauthorized"
	// CodeStorageFailed 服务端落盘失败（HTTP 500），客户端不标记成功。
	CodeStorageFailed ErrorCode = "storage_failed"
	// CodeRateLimited 限流（HTTP 429），可按退避重试。
	CodeRateLimited ErrorCode = "rate_limited"
	// CodeInvalidEvidence 本地证据非法（公钥、签名编码、摘要）。
	CodeInvalidEvidence ErrorCode = "invalid_evidence"
	// CodeSignerUnavailable 宿主签名能力暂不可用，可重试同一输入。
	CodeSignerUnavailable ErrorCode = "signer_unavailable"
	// CodeCanceled 操作被取消。
	CodeCanceled ErrorCode = "canceled"
)

// ErrMalformedRequest 哨兵：请求非法。ErrInvalidEvidence 哨兵：证据非法。
var (
	ErrMalformedRequest = &Error{Op: "collector", Code: CodeMalformedRequest}
	ErrInvalidEvidence  = &Error{Op: "collector", Code: CodeInvalidEvidence}
)

// Error 是统一错误。Error is the SDK error type.
type Error struct {
	Op    string
	Code  ErrorCode
	Field string
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "collector: <nil>"
	}
	msg := "collector." + e.Op + ": " + string(e.Code)
	if e.Field != "" {
		msg += " field=" + e.Field
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Cause }

// Errorf 构造带操作与字段的错误。Errorf builds an error with op and field.
func Errorf(op string, code ErrorCode, field, format string, args ...any) *Error {
	return &Error{Op: op, Code: code, Field: field, Cause: fmt.Errorf(format, args...)}
}

// Wrap 包装外部错误。Wrap wraps an external error.
func Wrap(err error, op string, code ErrorCode, field string) error {
	return &Error{Op: op, Code: code, Field: field, Cause: err}
}

// IsCode 报告错误链是否含指定 Code。IsCode reports whether the chain has code.
func IsCode(err error, code ErrorCode) bool {
	for err != nil {
		if e, ok := err.(*Error); ok {
			if e.Code == code {
				return true
			}
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
