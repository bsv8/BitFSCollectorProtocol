# BitFSCollectorProtocol

采集提交协议的 Go SDK 与 TypeScript SDK。定义提交格式、gzip 封装、签名与验签规则、HTTP 请求及响应。传输使用普通 HTTP／HTTPS，不引入 libp2p 或 BitFS 会话，不改动 BitFS 买卖协议。

BitFSCollectorProtocol is the Go + TypeScript SDK for collector submissions: record encoding, gzip envelope, signing/verification and the HTTP contract. Plain HTTP/HTTPS only.

- Go module：`github.com/bsv8/BitFSCollectorProtocol`，包 `collector`
- npm 包：`bitfs-collector-protocol`（`typescript/`）
- 有效需求与验收在工程仓：`docs/BitFSCollectorProtocol/`、`e2e/BitFSCollector/`、`parity/BitFSCollectorProtocol/`

## Go

```sh
go test ./...
```

`collector.EncodeSubmission` 编码规范 JSON → `collector.GzipJSON` 压缩 → `collector.DigestGzip` 求摘要 → `collector.SignGzip` 经宿主 Signer 签名 → `collector.Submit` 发送。验签只用 `collector.VerifyDigestSignature`，私钥永远由宿主提供，不由 SDK 保管。

## TypeScript

```sh
npm ci
npm run typecheck && npm run build && npm test
```

API 与 Go 对齐：`encodeSubmission`、`gzipJson`、`digestGzip`、`signGzip`、`submit`、`verifyDigestSignature`。摘要已是 32 字节，签名与验签必须关闭预哈希（`prehash: false`）。
