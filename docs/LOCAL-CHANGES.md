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
