// Package arch 以测试强制仓库的依赖治理（设计文档 §6「分层是数据，完备性
// 即强制」）。
//
// 全部依赖规则的唯一数据源是 layering.go：Layers（层号）、SameLayerEdges
// （受控同层边）、ExternalDeps（第三方依赖属主）与 ProtocolPkgs（协议词汇
// 触达 allowlist）四张表，宣言式声明、每条边有理由。arch_test.go 的守护
// 测试只从这份数据推导规则——go list ./... 枚举真实包集合（完备性即强制：
// 未登记的新包让测试失败）、默认拒绝未声明的 import、go.mod 直接依赖按
// 属主收口、协议包按 allowlist 防泄漏。没有第二份例外清单。
//
// 本包零内部依赖（守护测试只用标准库与 go 子进程），自身也登记在 Layers
// 中以纳入完备性管理。
package arch
