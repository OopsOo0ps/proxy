# 参与贡献

感谢你愿意为 Proxy 出一份力。本项目当前处于早期阶段，欢迎通过 Issue 讨论想法，或直接提交 Pull Request。

## 开发环境

- Go 1.25 及以上
- Make（macOS / Linux 自带；CI 运行在 ubuntu-22.04）
- 无需手动安装 golangci-lint：`make lint` 首次执行会自动下载到 `.bin/`

## 常用命令

```sh
make build    # 构建三个二进制到 bin/
make test     # 运行全部单元测试
make cover    # 运行测试并打印总覆盖率
make lint     # 运行 golangci-lint
make run      # 前台运行 proxy-server
make help     # 查看全部目标
```

单元测试包含本机回环上的端到端用例（会短暂绑定本地端口），无需外部网络。

## 提交规范

- 提交信息使用 Conventional Commits：`feat` / `fix` / `docs` / `build` / `ci` / `refactor` / `chore` 等
- 从 `main` 拉出特性分支，保持 PR 小而聚焦
- 提交 PR 前确保 `make test` 与 `make lint` 全部通过（CI 会重复校验）
- PR 描述请写清：动机、方案、验证方式

## 代码风格

- 统一使用 `gofmt` / `goimports`，由 `make lint` 强制检查
- 面向 Ubuntu 22.04 的生产目标，优先考虑可靠性与资源效率
- 新增行为请附带测试

## 交流

- Bug 与功能建议：GitHub Issues
- 安全问题：请勿公开提交 Issue，先通过仓库主页的联系方式私下沟通
