# 验证记录

> 本文件记录本仓库相对上游的改动**实测到了什么级别**。
> 分级标准：**L1** 动作执行了（文件写了、命令退出码 0）· **L2** 静态可达/语法自洽/路径存在 ·
> **L3** 端到端跑通，且有**独立信道的可观测副作用**（读回文件、真实请求、独立校验）。
> **只有 L3 能说"验证通过"。**

验证环境：Linux (WSL2) · Docker · ARTEX v0.3.19 单容器 + PostgreSQL 16 · LLM `cn:deepseek-v4.1-flash`

---

## 一、L1 · 代码自洽

| 项 | 结果 |
|---|---|
| `go build ./agent/ ./server/ ./db/ ./cmd/artex/` | **通过**（exit 0） |
| `go vet ./agent/ ./db/` | **无告警** |
| `gofmt -l`（本仓库改动与新增的 6 个文件） | **全部合规** |
| `gofmt -l`（上游原有文件） | 6 个不合规 —— **与上游逐字节相同，属上游自带**，不改（避免给上游合并制造无意义 diff）<br>`db/asset_intercept.go` · `db/assets_test.go` · `db/config.go` · `db/task_scope_test.go` · `server/assembly_test.go` · `server/tools_wire_test.go` |

---

## 二、L2 · 单元测试

```
$ go test ./agent/ -run TestHoneypot -v
=== RUN   TestHoneypotSignatureLogic
--- PASS: TestHoneypotSignatureLogic (0.00s)
=== RUN   TestHoneypotEmptyMatchNeverFires
--- PASS: TestHoneypotEmptyMatchNeverFires (0.00s)
PASS
```

覆盖：11 条签名加载 · 三正例命中（Cowrie 0.99 / OpenCanary 0.85 / Glastopf 0.90）·
三负例不命中（仅端口无 body · 正常 nginx · 空视图）· **空条件签名永不命中**。

---

## 三、L3 · 端到端

### 3.1 部署健康

```
GET /api/health                       → {"ok":true,"service":"artex","version":"0.3.19"}
容器                                   artex + postgres(healthy) 均 Up
数据                                   agents 8 · prompts 26 · tools 56
worker 工具                            16 个
```

### 3.2 四类新节点的 schema 白名单生效

```
ck_node_kind 含 validity_audit / validity_gate / baseline / observation  → ✓
```

### 3.3 四个工具已注册可用

```
audit_validity      ["worker"]
register_baseline   ["worker"]
http_probe          ["worker"]
honeypot_check      ["worker"]
```

### 3.4 ★ V1/V2/V3 —— 写回门闭环（L3）

实测链路（真实 agent 运行，非构造）：

```
audit#1079  insufficient
   ↓ 程序输出：[object.exists] false ——「无对照…请再用另一个对象引用发一次观察并填 compare_with」
   ↓ worker 照做：对 user?id=1 与 user?id=0 各跑一次 http_probe
audit#1081  sufficient ——「与对照 927 可区分（404≠200；长度 25≠36；user:0≠user:1）」
gate  #1082 allow
```

**这是 V2 的核心价值**：没有对照的结论被**拒绝写入**，且给出了可执行的补救指令；
模型照做后才通过。**不是靠提示词自觉，是机器拦住的。**

### 3.5 ★ V4 —— 结构化执行器（L3）

`http_probe` 把观察落盘为结构化节点（`obs_ref` / `actual_url` / `req_*` / `resp_*` /
`elapsed_ms` / `compare_with` / `compare_identical` / `extracted`），
上述 3.4 的语义校验就建立在这些字段上（`404≠200`·`长度 25≠36` 是机器比对出来的）。

### 3.6 ★ V5 —— 蜜罐指纹线索（L2 + L3）

**L2**：见第二节单测。

**L3**（真实 agent 任务，worker 调 `honeypot_check` 4 次）：

| 目标 | 结果 |
|---|---|
| `/cowrie`（种 Cowrie 默认 SSH banner） | `hit_count=1` → `cowrie_default_ssh_banner` ✓ |
| `/opencanary`（种 OpenCanary 默认 Server 头） | `hit_count=1` → `opencanary_default_http_server` ✓ |
| `/glastopf`（种 Glastopf 默认页） | `hit_count=1` → `glastopf_default_page` ✓ |
| `/plain`（正常 nginx，负例） | `hit_count=0` → `no_signature_hit` ✓ |

worker 写回的事实：**「三端点均命中蜜罐签名（verdict=hit_unverified），/plain 正常端点未命中」**
—— 它如实引用了 `hit_unverified`，没有把线索当判定。

**⚠ 这验证的是【机制】，不是【数据】**：签名库 11 条全部 `verified:false`（本仓库未能独立核实）。
机制通 ≠ 签名在真实世界准。两者必须分开算。

### 3.7 上游能力的实测基线（用于对照，非本仓库改动）

| 能力 | 结果 |
|---|---|
| RCE 挖掘（5 条真实原语的自建靶机） | **4/5 找到并证明**（命令注入 / 路径穿越 / SSTI 表达式求值 / pickle 反序列化），2 分 08 秒 / 36 发请求 / **0 误报**；漏掉的上传端点自标「未测」并给出联动假设 |
| 安全靶（8 个"看起来有洞"的端点） | **0 误报**；只报 1 条（一个真实存在的弱口令 Bearer），并主动标注未执行项、否掉第三方工具误报、自纠一次越界 |

---

## 四、★ 已知边界（这些都没验证过，别当成已验证）

```
① 只在小规模靶机上验证过：单机、8 端点以内。
   数百端点 / 内网多层 / 真实企业环境 —— 没测过。
   「没测」不等于「有问题」，但也不等于「没问题」。
② V5 签名库 11 条全部未独立核实（核实当轮 raw.githubusercontent.com 不可达）。
③ V5 不接入写回门的强制判定 —— 阈值未经实测校准。
④ 成本/延迟画像（14,663 次调用）显示无系统性限速问题，
   但该画像来自单实例、单 LLM 端点，不外推。
⑤ 跨服务对象编号映射、凭据 audience/租户条件、异步/概率性结果重复性 —— 未覆盖。
```

---

## 五、复现方法

```bash
# 1. 恢复 norma（见 README）
go mod download github.com/Autumn-27/norma@v0.4.3
NORMA=$(go env GOMODCACHE)/github.com/\!autumn-27/norma@v0.4.3
mkdir -p norma && cp -r "$NORMA"/* norma/ && chmod -R u+w norma/

# 2. L1
go build ./agent/ ./server/ ./db/ ./cmd/artex/
go vet ./agent/ ./db/

# 3. L2
go test ./agent/ -run TestHoneypot -v

# 4. L3
docker compose build && docker compose up -d
curl -s http://127.0.0.1:8787/api/health
```

> L3 的完整链路（写回门闭环 / 蜜罐命中）需要一个可被扫描的目标与一次真实 agent 运行，
> 不适合做成一条命令 —— 上面 3.4 / 3.6 记录的是实测原文。
