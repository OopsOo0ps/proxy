// 依赖治理的唯一数据源（设计文档 §6.1「分层是数据，完备性即强制」）。
//
// 本文件宣言式地声明全部依赖规则；internal/arch/arch_test.go 的守护测试只
// 从这里推导规则（go list 枚举真实包集合 + 默认拒绝），不存在第二份例外
// 清单。修改依赖关系 = 修改这里的数据 = 一次显式评审。
//
// 数据的四张表：
//   - Layers：每个包的层号，允许的 import = 层号严格更小的包 + 同层边；
//   - SameLayerEdges：受控同层边，每条有一句话理由；
//   - ExternalDeps：第三方直接依赖的属主（防依赖蔓延）；
//   - ProtocolPkgs：协议词汇的触达 allowlist（防协议泄漏）。
package arch

// Layers 是 module 内每个包的层号（设计文档 §5.1）。键为去掉 module 前缀
// 的导入路径：internal/ 下的包取 internal/ 之后的相对路径，cmd/ 与 test/
// 保留目录前缀。值越小越底层。
//
// 允许的 import = 层号严格小于自己的包 + SameLayerEdges 声明的同层边。
// 未在此登记的包会被 TestDependencyDirection 判为违例——「把新包加进仓库」
// 这个动作本身就让测试失败，归类决策无法被遗忘（完备性即强制）。
var Layers = map[string]int{
	// L0 纯原语
	"relay": 0, "sockswire": 0, "netutil": 0, "logging": 0,
	"shutdown": 0, "connlimit": 0, "auth": 0, "version": 0,
	"defaults": 0, // 纯常量，零依赖
	"throttle": 0, // 认证失败按 IP 指数退避：纯 stdlib，零模块内依赖
	// L1 契约/机械
	"core": 1, "outbound": 1, "session": 1,
	"lifecycle": 1, // 组装根共有生命周期核心：只依赖 stdlib（与 session 同语义）
	// L2 领域引擎
	"routing": 2, "ruleset": 2, "nodes": 2, "connpool": 2, "dialer": 2,
	"accounts": 2, // 账户聚合（动态用户/订阅存储 + 门禁视图）：HTTP-free / core-free 领域包
	"payment":  2, // 订单聚合（状态机 + trade_no 幂等落地 + orders.json 独立持久化）：applied 落地调 accounts 单调延长订阅
	"alipay":   2, // 支付宝线格式方言 owner（RSA2 编解码/签名 + 网关客户端）：stdlib-only，零模块内依赖
	// L3 协议端点
	"httpproxy": 3, "socks5": 3, "dnsgw": 3, "trojan": 3,
	"alipaymock": 3, // 假支付宝网关（收银台页 + 验签 + 发签名 notify）：复用 alipay 编解码的协议端点，与 trojan 同类
	// L4 组装/面/守护
	"config": 4, "clientapp": 4, "serverapp": 4, "metrics": 4,
	"status": 4, "testutil": 4,
	"control": 4, // 控制面 HTTP（用户/订阅管理）：gin 唯一属主，纯向下消费 accounts
	"arch":    4, // 守护包自身：零内部依赖，登记以纳入完备性管理
	// L5 入口
	"cmd/client": 5, "cmd/server": 5, "test/integration": 5,
	"cmd/mockpay": 5, // 假支付宝二进制：宿主 alipaymock + 自有最小配置（旗标，不走 config 主 schema）
}

// SameLayerEdges 是受控同层边：键为源包，值为允许它同层依赖的包。
// 每条边必须能一句话说清理由；新增 = 一次显式评审。同层边的稀缺性
// 本身就是设计质量的信号。
//
// 相对设计文档 §6.1 的「5 源包 / 10 条边」计数有一条勘误：outbound(L1)
// → core(L1) 不可避免——§4.2 出口契约的签名（Transport.DialTunnel /
// Prewarmer.Bind 的入参与返回值）直接引用 core.Target，契约包消费共享
// 词汇不是分层漂移。登记后同层边实为 6 个源包 / 11 条边。
var SameLayerEdges = map[string][]string{
	"dialer":    {"routing", "nodes"},                       // 路由分派与节点选择是 dialer 的组成部件
	"nodes":     {"connpool"},                               // 预热池是节点池的内部机制（§5.3 组合树：每节点 PrewarmPool）
	"ruleset":   {"routing"},                                // 规则源产出路由引擎的规则表
	"clientapp": {"config", "metrics", "status"},            // 组装根唯一可触配置/遥测/管理面
	"serverapp": {"config", "metrics", "status", "control"}, // serverapp 宿主控制面服务（同层，对齐 status）
	"outbound":  {"core"},                                   // 勘误：出口契约签名引用 core.Target（见上注释）
	"payment":   {"accounts"},                               // 支付落地是订单状态机的终态动作（applied 幂等落地 → 订阅单调延长，设计书 §1.1）
}

// ExternalDeps 是第三方直接依赖的属主：键为 go.mod 的 module 路径，值为
// 允许 import 它（含其子包）的包。非属主包 import 它 = FAIL。
// 新增第三方依赖必须先在这里登记属主 = 一次显式决策（防依赖蔓延）。
var ExternalDeps = map[string][]string{
	"gopkg.in/yaml.v3":                    {"config"},
	"github.com/prometheus/client_golang": {"metrics"},
	"github.com/gin-gonic/gin":            {"control"}, // gin 只许控制面触达（组装根保持 gin-free）
}

// ProtocolPkgs 是协议与领域词汇泄漏检查的 allowlist：键为协议/领域包名，值为允许
// import 该协议包的包（含其外部测试的宿主包归属）。协议包只许被自己和
// 组装根/测试地基触达；新增出口/入站协议时在此登记一行，泄漏防线自动
// 覆盖它。
var ProtocolPkgs = map[string][]string{
	"trojan": {"trojan", "clientapp", "serverapp", "testutil", "test/integration"},
	// accounts 是领域词汇（非线格式协议）：触达面 = 自身 + 支付落地（payment
	// 经 SameLayerEdges 的同层边消费 ExtendSubscriptionExpiresAt）+ 两个组装根
	// 与控制面（clientapp 自迭代④起触达：只读消费管理员分发的 entitlement
	// 文件并与入站静态凭据复合，设计书 §2.2 clientapp ──► accounts，不获得
	// →control 边；test/integration 走 HTTP 黑盒零 import）。
	"accounts": {"accounts", "payment", "serverapp", "control", "clientapp"},
	// payment 是订单聚合的领域词汇：触达面 = 自身 + 组装根 + 控制面（下单与
	// notify 回调）+ 黑盒集成；数据面 L0–L3 不得触达。
	"payment": {"payment", "serverapp", "control", "test/integration"},
	// alipay 是线格式方言词汇：触达面 = 自身 + 假网关 alipaymock + 组装根
	//（读取密钥文件并构造 Client，PEM 字节注入控制面）+ 控制面 + mockpay
	// 二进制 + 黑盒集成；数据面 L0–L3 不得触达。
	"alipay": {"alipay", "alipaymock", "serverapp", "control", "cmd/mockpay", "test/integration"},
	// alipaymock 是假网关的 HTTP 面（迭代②）：触达面 = 自身 + 假件宿主
	// cmd/mockpay + 控制面（迭代③）+ 黑盒集成；数据面 L0–L3 不得触达。
	"alipaymock": {"alipay", "alipaymock", "control", "cmd/mockpay", "test/integration"},
}
