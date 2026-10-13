# 安全政策

## 支持的版本

安全修复会合并到 `main` 分支，并以最新发行版本（见
[Releases](https://github.com/OopsOo0ps/proxy/releases)）作为修复载体；
更早的版本不单独维护安全补丁。

## 报告安全漏洞

请**不要**通过公开的 GitHub Issue 报告安全漏洞。请使用 GitHub 私密漏洞报告渠道：

**GitHub 私密漏洞报告**：在仓库
[Security → Advisories → Report a vulnerability](https://github.com/OopsOo0ps/proxy/security/advisories/new)
提交，仅维护者可见。

报告中请尽量包含：

- 受影响版本或提交；
- 复现步骤或最小 PoC；
- 影响评估（可利用性与潜在危害）；
- 你期望的公开披露时间点（如有）。

报告语言英文或中文均可。

## 响应与披露流程

- **首次响应**：我们承诺在 **14 天（自然日）内**确认收到并对报告进行初步评估。
- **修复**：确认后尽快在私有分支修复，并通过新的发行版本或补丁提交发布。
- **披露**：修复发布后与报告者协商公开细节；如报告者同意，我们会在 Release Notes /
  [CHANGELOG.md](CHANGELOG.md) 中致谢。

## 范围

- 在范围内：`proxy-server` / `proxy-client` 的代码与发行产物中的漏洞。
- 不在范围内：依赖项的已知漏洞（请报告给对应上游）；仅影响本地演示证书或示例配置的问题；
  以及需要攻击者已完全控制运行环境才能触发的问题。

## 安全设计参考

项目自身的认证、凭据处理与失败响应设计，见 [README.md](README.md) 的「安全」一节。
