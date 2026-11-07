// Package collector 是采集提交协议的 Go SDK：批量记录的规范编码与 gzip
// 压缩、对实际 gzip 字节的签名与验签、HTTP 提交客户端。
//
// 私钥由宿主以 Signer 能力注入，SDK 只接触 32 字节摘要，不保管私钥，
// 不读时钟、网络或磁盘。有效契约见工程仓 docs/BitFSCollectorProtocol/。
package collector
