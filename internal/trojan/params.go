// 协议参数形状（设计文档 §7.3：协议 Params 结构体只有 struct tag，
// 协议包零 yaml 依赖——严格解码由 config.DecodeParams 完成，协议专属
// 校验在传输 / 服务端构造处）。
package trojan

// Params 是一个 trojan 出口节点的协议参数（client 配置 outbound.nodes[].params
// 块的形状）。地址与口令的合法性在 NewTransport 构造时校验（协议语义归协议）。
type Params struct {
	// Addr 是出口节点地址（host:port）。
	Addr string `yaml:"addr"`
	// Password 是隧道口令；线上以 hex(SHA-224) 摘要出现（不出协议包）。
	Password string `yaml:"password"`
	// SNI 是可选的 TLS SNI / 证书校验名；空 = 取 Addr 的主机名。
	SNI string `yaml:"sni,omitempty"`
	// CAFile 是可选的自定义 CA 证书路径（自签证书场景）。
	CAFile string `yaml:"ca-file,omitempty"`
	// InsecureSkipVerify 跳过证书校验，仅限测试 / 自签调试。
	InsecureSkipVerify bool `yaml:"insecure-skip-verify,omitempty"`
}

// ServerUser 是一条服务端隧道凭据（config params.users 条目的形状）。
// 服务端只保留 SHA-224 摘要（auth.Store 构造时派生），配置携带明文口令。
type ServerUser struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ServerParams 是 trojan 服务端入站的协议参数（server 配置
// inbounds[].params 块的形状）。
type ServerParams struct {
	// CertFile / KeyFile 是隧道 TLS 证书与私钥路径（必填）。
	CertFile string `yaml:"cert-file"`
	KeyFile  string `yaml:"key-file"`
	// DecoyFile 是可选的伪装页面文件；空 = 使用 DefaultDecoyPage。
	DecoyFile string `yaml:"decoy-file,omitempty"`
	// Users 是隧道凭据列表（必填）。
	Users []ServerUser `yaml:"users"`
}
