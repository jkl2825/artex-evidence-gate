# 相对上游 v0.3.19 的差异

## 新增文件
- `agent/predicate.go`（764 行）
- `agent/http_probe.go`（434 行）
- `agent/honeydetect.go`（327 行）
- `agent/honeydetect_signatures.json`（105 行）
- `agent/honeydetect_logic_test.go`（50 行）

## 修改文件
- `agent/tools.go`（+22 / -2 行）
- `agent/tools_insert.go`（+19 / -0 行）
- `db/schema.sql`（+26 / -2 行）
- `Dockerfile`（+99 / -0 行）
- `.dockerignore`（+5 / -0 行）

## 改动说明

### V1/V2/V3 —— `agent/predicate.go`（764 行，新增）

把 R05 五层有效性从**提示词纪律**下沉为**机器判据**。

```
kindValidityAudit      审计记录节点（layers / context / unknown_predicates / baselines_used）
kindValidityGate       门决策节点（decision / reason / audit_id / keyword）
kindBaseline           可复用基线（TTL + 失效条件）
kindObservation        结构化观察（供谓词机器校验）

BuiltinPredicates      5 条内建谓词
semanticCheck()        逐谓词做语义校验，返回 (reason, layer)
checkEvidenceRef()     校验 evidence_ref 是否真实指向存在的观察
checkBaseline()        校验引用的基线是否仍有效
validityGate()         写回门：不够资格则拒绝写入并给出补救指令
saveValidityAudit()    审计落盘（含逐层理由，保证可回溯）
```

### V4 —— `agent/http_probe.go`（434 行，新增）

`http_probe` 工具：把 HTTP 观察**结构化**落盘（obs_ref / actual_url / req_* / resp_* /
elapsed_ms / compare_with / compare_identical / extracted），并提供 `redactHeaders`
与 `runExtract`（header | json | regex）三条提取通道。

存在的理由：谓词要机器校验就需要结构化输入；`curl` 的输出是给人看的。

### V5 —— `agent/honeydetect.go`（327 行，新增，含签名库）

`honeypot_check` 工具：判断目标像不像已知开源蜜罐的默认配置。

★ **签名库 11 条全部 `verified: false`** —— 未能独立核实。
故它**不接入写回门的强制判定**，只产出线索，返回里带 `authority` 说明。
设计上沿用三条硬约束：签名必须带 source · 空条件签名永不命中 · 多条件 AND。

### 修改 —— `agent/tools.go`（+22 / -2）

- `factItem` 增加 `Conclusion` 字段
- `recordOneFact` 在 `AddNode` **之前**调用 `t.validityGate(it, intent)`

### 修改 —— `agent/tools_insert.go`（+19 / -0）

`WorkerTools()` 里接线：`auditValidity()` · `registerBaseline()` · `httpProbe()` · `honeypotCheck()`

### 修改 —— `db/schema.sql`（+26 / -2）

`exploration_nodes.kind` 是 CHECK 白名单，新增四类节点需同步：
CREATE 定义里加白名单 + 末尾幂等 ALTER（兼容已有库）。

### 修改 —— `Dockerfile`（+99 / -0）

1. apt/pip/npm 换国内镜像源（抗网络抖动）
2. **工具链固化层提到应用层之前** ⇒ 改代码重建 40 分钟 → ~60 秒
3. 用 BuildKit `additional_contexts` 把工具链移出主构建上下文 ⇒ context 534MB → 16MB
4. `ARTEX_BUILD_VERSION` 传版本号（否则 `/api/health` 显示 `dev`）

### 修改 —— `.dockerignore`（+5 / -0）

排除工具链目录作双保险（防止有人忘记传 `--build-context` 时白拷 500MB）。

### V6 —— `agent/scope_guard.go`（655 行）+ `agent/scope_tool.go`（118 行）+ `scope_guard_test.go`（197 行，新增）

授权范围闸。`http_probe` 在发请求**之前**与**每一跳重定向**都过闸；
`scope_status` 工具让 worker 能看见边界并显式声明。

三道闸（绝对禁止段无例外 / 私有网段需声明 / 声明外 fail-closed）、
只认 `source ∈ {manual,agent}`、DNS 只用于 deny 防 rebinding、DNS 结果 60 秒缓存。

修改：
- `agent/http_probe.go`（+24）发请求前 + `CheckRedirect` 内各插一道闸
- `agent/predicate.go`（+28）新增第 6 个谓词 `out_of_scope`（`Enforced: true`，进 `required`）
- `agent/tools_insert.go`（+8）接线 `scopeStatus()`

### V7 —— `agent/policy_guard.go`（304 行）+ `policy_guard_test.go`（178 行，新增）

把四条通用测试规则落成硬判据：内网硬禁（白名单例外）· 越权读取 ≤5 组 ·
默认只读方法 · 每分钟 + 单任务总量双闸。

配置全部走环境变量，便于现场收紧而不必重建：
`ARTEX_INTRANET_ALLOW` · `ARTEX_POLICY_MAX_READS` · `ARTEX_POLICY_ALLOW_WRITE` ·
`ARTEX_POLICY_MAX_REQUESTS` · `ARTEX_POLICY_MAX_PER_MINUTE`

修改：
- `agent/scope_guard.go`   私有网段从"需声明"改为"硬禁除非白名单"；
                           判定顺序改为「绝对禁止 → 内网硬禁 → scope 匹配」
- `agent/http_probe.go`    +22 行：插三条策略闸（写方法 / 读取配额 / 速率）
- `agent/scope_tool.go`    返回 `policy_usage` 用量快照

### V8 —— `server/mcp_action_gate.go`（120 行）+ 测试（118 行，新增）

MCP 动作类工具黑名单。V6/V7 只管 `http_probe`，而 agent 手上的
`create_scan_task` 等工具能让 ScopeSentry（scan worker 跑 host 网络）去真扫描 ——
那条路绕过了全部闸。

修改：
- `server/assembly.go`（+9 行）在 MCP 工具展开循环里过滤，不进 extra / 不进 unlock
- 放开方式：`ARTEX_MCP_ALLOW_ACTIONS`（1 / all / `ScopeSentry:create_scan_task`）
