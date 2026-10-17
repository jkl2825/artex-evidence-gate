# 关于本仓库

本仓库是 **[mhtsec/ARTEX](https://github.com/mhtsec/ARTEX) `v0.3.19`** 的本地增强版，
主体框架、Web 前端、提示词体系均来自上游，未做重构。

**上游信息**：ARTEX —— AI 自主渗透测试系统 · 上游作者 `Autumn-27` · 上游仓库 `mhtsec/ARTEX`
**许可证**：AGPL-3.0（见 [LICENSE](LICENSE)）—— 本仓库作为衍生作品，同样以 AGPL-3.0 发布，
并保留上游全部版权声明。分发或部署本仓库时请一并遵守 AGPL-3.0 的开源义务。

---

## 这个分支加了什么

一句话：**给上游补了一层「证据资格判定」—— 让"未复现"不是一个随口结论，而是一个可审计的判定。**

上游的 R05 五层有效性（传输 / 身份 / 业务基线 / 观察能力 / 方法适用性）是**提示词层面的纪律**，
模型可以遵守，也可以不遵守。本分支把它**下沉成机器判据**：

| # | 层 | 文件 | 作用 |
|---|---|---|---|
| V1 | 谓词判定 | `agent/predicate.go` | `audit_validity`：逐层判定证据资格，产出 `sufficient/insufficient` 与逐层理由 |
| V2 | 写回门 | `agent/predicate.go` + `agent/tools.go` | `record_fact` 写结论前过门；不够资格**直接拒绝写入**，并告诉 worker 缺什么 |
| V3 | 公共基线 | `agent/predicate.go` | `register_baseline`：把"对照"沉淀成可复用基线，带 TTL 与失效条件 |
| V4 | 结构化执行器 + 语义谓词 | `agent/http_probe.go` | `http_probe`：把 HTTP 观察结构化落盘（状态/长度/头/正文摘要/耗时），供谓词机器校验 |
| V5 | 蜜罐指纹线索 | `agent/honeydetect.go` | `honeypot_check`：目标像不像已知开源蜜罐的默认配置（**线索级，非判定**） |
| V6 | **授权范围闸** | `agent/scope_guard.go`<br>`agent/scope_tool.go` | `http_probe` 发请求**之前**先判目标是否在授权边界内；`scope_status` 看/声明边界。**绝对禁止段（云元数据/回环/链路本地/组播/保留）任何授权都不放行** |
| V7 | **测试规则闸** | `agent/policy_guard.go` | 把四条通用测试规则落成硬判据：**①内网硬禁**（白名单例外）· **②越权读取 ≤5 组** · **⑤禁止写方法**（默认只读）· **⑥防 DDoS**（每分钟 + 单任务总量双闸） |

### 为什么要有 V1–V2

上游可以（也曾经）在**没有任何对照**的情况下把 `object.exists` 写成 `true`。
一旦这个结论进了图，后面所有推理都建立在它上面。

V2 的门会在写回时拦住它，并给出可执行的补救指令 —— 实测里模型**照做了**：
它补跑了一次对照观察，拿到 `404≠200 / 长度 25≠36`，通过后才写回。

### 为什么要有 V4

`predicate` 要机器校验，就需要**结构化**的观察。`curl` 的输出是给人看的，
`http_probe` 的输出是给判据看的 —— 这是 V4 存在的唯一理由。

### 为什么要有 V6（授权范围）

上游的 `task_scope` 是**覆盖度分母**与**查询过滤基准**，不是**执行前的授权边界** ——
代码注释自己写着 "task_scope is the task's range boundary (the **filter basis** for ...)"，
而 `AddAutoScope` 的记录逻辑是「worker 碰到哪个主机就自动加进范围」。
也就是说：**范围记录的是「我碰过什么」，不是「我该碰什么」** —— 拿它当边界是自证。

实测过的事实（改造前）：

```
容器能直接访问互联网        http://example.com → 200
http_probe 不做任何校验      grep scope/allowlist/private → 无命中
没有命令黑名单              grep blockedCmd/denyCmd → 无命中
task_scope                 0 条记录（所有任务都没声明过范围）
```

⇒ 只要模型"自己认为"在范围内，就能对任何地址发请求，**没有任何一层拦**。

V6 补的是最前面那一层，三道闸从硬到软：

```
① 绝对禁止段（无例外）：169.254/16 云元数据 · 127/8 回环 · 0/8 · 224/4 组播 · 240/4 保留
   · ::1 · fe80::/10 · ff00::/8
   —— 打元数据端点等于偷凭据，打回环等于 SSRF 打自己。这类目标在任何授权语境下都不该被测试。
② 私有网段（10/8 · 172.16/12 · 192.168/16 · 100.64/10 · fc00::/7）：默认拒绝，需显式声明。
③ 已声明范围外：本任务有声明则 fail-closed 拒绝；无声明则放行但记警告。
```

两个设计取舍：

```
· 只统计 source ∈ {manual, agent} 的 scope；source=auto（自动累积）不构成授权 —— 否则自证
· DNS 解析只用于 deny 不用于 allow —— 域名解析到 169.254.169.254 仍拒绝（防 rebinding），
  但解析出的 IP 在 scope 里也不代表域名本身被授权
```

**模式由 `ARTEX_SCOPE_MODE` 控制**：`strict`（必须声明）/ `declared`（默认）/ `audit_only`（只判定不拦，绝对禁止段仍拦）。

### V7 把四条通用测试规则落成硬判据

不是自己编的规则，是**通用的众测/SRC 测试纪律**，逐条映射到可机器判定的动作：

| 规则原文 | 机器化判据 | 实现 |
|---|---|---|
| ① 禁止进行内网渗透行为 | 私有网段**硬禁**，只有 `ARTEX_INTRANET_ALLOW` 列出的 CIDR 放行 | `intranet_denied` |
| ② 越权漏洞禁止批量读取，允许读取的数据不超过 5 组 | 按「主机+接口路径」计数，同一接口用**携带身份**的方式读到超过 5 个不同对象即拒 | `read_quota` |
| ⑤ 禁止影响线上业务 / 禁止修改线上数据 | HTTP 方法闸：默认只允许 `GET/HEAD/OPTIONS`；写方法需 `ARTEX_POLICY_ALLOW_WRITE=1` | `write_method` |
| ⑥ 禁止进行 DDOS 攻击 | 滑动一分钟窗口上限 + 单任务总请求数上限 | `rate` / `total` |
| ③ 禁止对外披露漏洞细节 · ④ 禁止保留漏洞与厂商数据 | **不是代码能强制的**（是人的行为），本仓库不假装解决 | —— |

三个刻意的设计取舍：

```
· 「内网硬禁」不看 scope 声明 —— 声明只能证明"我知道我在打内网"，
  不能证明"被授权打内网"。规则说禁止，那就默认禁止；要放开只能由部署方改环境变量。
· 「读取配额」只对【携带身份】的请求计数 —— 规则约束的是【越权读取】。
  匿名遍历不属于越权（它仍受规则⑥的速率闸约束）。
· 「写方法闸」的开关属于授权决策，不由模型自行打开 ——
  错误文案里明确写了这一点，且模型手边没有打开它的工具。
```

### V5 的诚实边界（重要）

`honeydetect` 的签名库**11 条全部标注 `verified: false`** —— 本仓库未能独立核实其中任何一条
（核实当轮 `raw.githubusercontent.com` 不可达）。因此：

- 它只覆盖**用开源蜜罐默认配置**的目标
- 专有蜜罐、改过默认值的蜜罐**没有任何公开指纹** ⇒ **查不出来不代表不是蜜罐**
- 真实服务可能恰好用同一默认值 ⇒ **查出来也不代表一定是**
- **故它不接入写回门的强制判定** —— 阈值未经实测校准就拿来拦结论，属于拍脑袋

工具返回里带 `authority` 字段说明这一点，不给一个光秃秃的分数。

---

## 构建

### 前置：恢复 `norma`（本仓库不包含）

上游依赖 `github.com/Autumn-27/norma`，该模块**已闭源**。上游自己是从 Go module proxy 恢复的，
并把 `replace` 指向本地 `./norma`。**本仓库不分发这份第三方闭源代码**，请自行恢复：

```bash
# 1. 拉取依赖到模块缓存
go mod download github.com/Autumn-27/norma@v0.4.3

# 2. 从缓存拷到 ./norma
NORMA=$(go env GOMODCACHE)/github.com/\!autumn-27/norma@v0.4.3
mkdir -p norma && cp -r "$NORMA"/* norma/
chmod -R u+w norma/

# 3. 校验
ls norma/go.mod && head -1 norma/go.mod
```

> `go.mod` 里已有 `replace github.com/Autumn-27/norma => ./norma`，恢复后即可正常构建。

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env
# 按需改 .env：数据库口令、监听地址、LLM 配置

docker compose build
docker compose up -d
```

默认入口 `http://127.0.0.1:8787`（可用 `.env` 改）。

> **本仓库的 `Dockerfile` 与上游不同**：加了国内可用的 apt/pip/npm 镜像源替换、
> 把工具链固化层提到应用层之前（改代码重建从 40 分钟降到 ~60 秒），
> 并用 BuildKit 的 `additional_contexts` 把工具链移出主构建上下文（534MB → 16MB）。
> 工具链资产不在本仓库内，见下文「工具链」。

### 方式二：本地运行

```bash
go build -tags embedui -o artex ./cmd/artex
./artex
```

（`-tags embedui` 会把 `server/webui/dist/` 内嵌进二进制；不打这个 tag 需要单独提供前端产物。）

### 工具链（不在本仓库内）

渗透工具链（`toolchain/bin` ~406MB、`toolchain-extra` ~113MB）**不上传到本仓库**，
因为体积与许可都不合适。仓库里的 `Dockerfile` 通过以下两个构建上下文引用它们：

```yaml
build:
  additional_contexts:
    toolchain-bin: <你的路径>/toolchain
    toolchain-extra: <你的路径>/toolchain-extra
```

自建方法见上游 `Dockerfile` 的工具安装段，或按需裁剪成自己需要的子集。

---

## 验证

**完整验证记录见 [docs/VERIFICATION.md](docs/VERIFICATION.md)** —— 含环境、分级结论、实测原文、已知边界。

摘要：

```
L1  go build 通过 · go vet 无告警 · 本仓库改动文件 gofmt 全合规
L2  go test ./agent/ -run TestHoneypot 全绿（11 条签名 / 3 正例 / 3 负例 / 空条件不命中）
L3  写回门闭环：insufficient → 模型补跑对照 → sufficient → allow
L3  蜜罐工具端到端：3 命中 / 1 不命中，worker 如实引用 verdict=hit_unverified
── 对照基线（上游能力，非本仓库改动）──
L3  RCE 能力考核：4/5 原语被找到并证明，0 误报，2 分 08 秒
L3  安全靶考核：8 个"看起来有洞"的端点，0 误报，如实标注未执行项
```

★ **已知边界（没验证过的，别当已验证）**：只在小规模靶机（单机 / 8 端点以内）上验证；
百端点级、内网多层、真实企业环境**没测过**。

`agent/honeydetect_logic_test.go` 是可直接跑的：

```bash
go test ./agent/ -run TestHoneypot -v
```

---

## 与上游保持同步

本仓库基于 **v0.3.19**。上游若有新版本，合并原则：

- `agent/predicate.go`、`agent/http_probe.go`、`agent/honeydetect*.go` 是**新增文件**，无冲突
- `agent/tools.go`、`agent/tools_insert.go`、`db/schema.sql`、`Dockerfile` 是**改过**的，需手工合并
- 其余整目录取上游

> 提示：上游 v0.3.17–19 三版 100% 是认证加固（凭证绑定密码哈希、登录限速、失败锁定、
> 认证审计、认证请求体读取超时）。合并时**不要**把这几处覆盖回旧版。

---

## 免责声明

本工具仅用于**获得明确授权的**安全测试。使用者需自行确保测试目标在授权范围内。
作者不对未授权使用造成的任何后果负责。
