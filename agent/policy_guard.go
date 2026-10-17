package agent

// policy_guard.go —— 测试规则的可机器强制部分（本地新增 2026-10-17）
//
// 用户给定的测试规则里，能在代码层强制的有四条：
//
//   规则① 禁止进行内网渗透行为
//          → 私有网段【硬禁】，只放行显式白名单段（ARTEX_INTRANET_ALLOW）
//            与 scope_guard 的"私有网段需声明"不同：声明只能证明"我知道我在打内网"，
//            不能证明"被授权打内网"。规则说禁止，那就默认禁止。
//
//   规则② 越权漏洞禁止批量读取，允许读取的数据不超过 5 组
//          → 按「主机 + 接口路径」计数，同一接口读到的【不同对象值】超过 5 个即拒。
//            只在【携带身份】的请求上计数 —— 匿名遍历不算越权（但受速率闸约束）。
//
//   规则⑤ 禁止影响线上用户和业务正常运行，禁止修改线上数据
//          → HTTP 方法闸：默认只允许 GET / HEAD / OPTIONS。
//            POST / PUT / DELETE / PATCH 需要显式开启 ARTEX_POLICY_ALLOW_WRITE=1。
//            这是硬判据：改数据必然要写方法，堵住写方法就堵住了"改线上数据"；
//            "影响业务"另由速率闸约束。
//
//   规则⑥ 禁止进行 DDOS 攻击
//          → 双闸：滑动一分钟窗口上限 + 单任务总请求数上限。
//
// 规则③（禁止披露）、④（禁止保留）是人的行为，代码只能辅助脱敏与清理，不在此文件。

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ── 上限配置（全部走环境变量，带保守默认值）────────────────────────────────

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envBool(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// policyLimits 读取当前上限。
// 刻意每次现读：调参不必重启，便于现场收紧。
func policyLimits() (maxTotal, maxPerMinute, maxReads int, allowWrite bool) {
	return envInt("ARTEX_POLICY_MAX_REQUESTS", 1000),
		envInt("ARTEX_POLICY_MAX_PER_MINUTE", 60),
		envInt("ARTEX_POLICY_MAX_READS", 5),
		envBool("ARTEX_POLICY_ALLOW_WRITE", false)
}

// allowedWriteMethods 是规则⑤的判据：默认只读。
var allowedWriteMethods = map[string]bool{
	"GET": true, "HEAD": true, "OPTIONS": true,
}

// isReadMethod 判断某方法是否只读。
func isReadMethod(m string) bool { return allowedWriteMethods[strings.ToUpper(strings.TrimSpace(m))] }

// ── per-task 状态 ─────────────────────────────────────────────────────────

type taskPolicy struct {
	mu       sync.Mutex
	reqTotal int
	winStart time.Time
	winCount int
	// reads: key="host|path" → 已读到的不同对象值集合
	reads map[string]map[string]struct{}
}

var (
	policyMu     sync.Mutex
	policyByTask = map[int64]*taskPolicy{}
)

func policyFor(taskID int64) *taskPolicy {
	policyMu.Lock()
	defer policyMu.Unlock()
	p, ok := policyByTask[taskID]
	if !ok {
		p = &taskPolicy{reads: map[string]map[string]struct{}{}}
		policyByTask[taskID] = p
	}
	return p
}

// policyVerdict 一次规则判定。
type policyVerdict struct {
	Allowed bool           `json:"allowed"`
	Rule    string         `json:"rule"` // ok | write_method | rate | total | read_quota
	Reason  string         `json:"reason"`
	Detail  map[string]any `json:"detail,omitempty"`
}

func (v policyVerdict) String() string {
	if v.Allowed {
		return "policy ok"
	}
	return fmt.Sprintf("policy deny (%s): %s", v.Rule, v.Reason)
}

// ── 规则⑤：写方法闸 ──────────────────────────────────────────────────────

// checkMethod 判方法是否被规则⑤放行。
func (t *ToolSet) checkMethod(method string) policyVerdict {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	_, _, _, allowWrite := policyLimits()
	if isReadMethod(m) || allowWrite {
		return policyVerdict{Allowed: true, Rule: "ok"}
	}
	return policyVerdict{
		Allowed: false,
		Rule:    "write_method",
		Reason: fmt.Sprintf("测试规则⑤「禁止修改线上数据」：方法 %s 属于写操作，默认不放行。"+
			"本执行器只允许 GET/HEAD/OPTIONS。若确已获授权做写测试，需由部署方设置 "+
			"ARTEX_POLICY_ALLOW_WRITE=1 —— 这个开关属于授权决策，不由模型自行打开", m),
		Detail: map[string]any{"method": m, "allowed_methods": []string{"GET", "HEAD", "OPTIONS"}},
	}
}

// ── 规则⑥：速率与总量 ────────────────────────────────────────────────────

// denyRequest 构造一条策略拒绝结果。
// 抽出来是为了让 http_probe 的顺序判定只需三行，且拒绝文案只有一处。
func (t *ToolSet) denyRequest(pv policyVerdict) actool.Result {
	body, _ := json.MarshalIndent(map[string]any{
		"error":  "违反测试规则，请求未发出",
		"policy": pv,
		"usage":  t.policySnapshot(),
		"next": "这条是部署方设定的硬约束，不是建议。请调整测试方式（改用只读方法 / " +
			"减少读取组数 / 降低频率），而不是绕过本执行器。" +
			"确需放宽时，由部署方调整对应的 ARTEX_POLICY_* 环境变量。",
	}, "", "  ")
	return actool.Errorf(string(body))
}

// checkBudget 判本次请求是否在上限内。通过时【已计入】。
func (t *ToolSet) checkBudget() policyVerdict {
	maxTotal, maxPerMinute, _, _ := policyLimits()
	p := policyFor(t.taskID)
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if p.winStart.IsZero() || now.Sub(p.winStart) >= time.Minute {
		p.winStart = now
		p.winCount = 0
	}

	if p.reqTotal >= maxTotal {
		return policyVerdict{
			Allowed: false, Rule: "total",
			Reason: fmt.Sprintf("测试规则⑥「禁止 DDOS」：本任务累计请求数已达上限 %d，停止发送。"+
				"如需继续，由部署方调大 ARTEX_POLICY_MAX_REQUESTS", maxTotal),
			Detail: map[string]any{"used": p.reqTotal, "limit": maxTotal},
		}
	}
	if p.winCount >= maxPerMinute {
		return policyVerdict{
			Allowed: false, Rule: "rate",
			Reason: fmt.Sprintf("测试规则⑥「禁止 DDOS」：本任务最近一分钟内已发 %d 个请求，达到上限 %d。"+
				"请降低频率（分批、加间隔）后重试；本窗口在 %s 后重置",
				p.winCount, maxPerMinute, p.winStart.Add(time.Minute).Format("15:04:05")),
			Detail: map[string]any{"used_this_minute": p.winCount, "limit": maxPerMinute},
		}
	}
	p.reqTotal++
	p.winCount++
	return policyVerdict{Allowed: true, Rule: "ok"}
}

// ── 规则②：越权读取配额 ──────────────────────────────────────────────────

// readQuotaKey 从 URL 抽「主机 + 路径」作为接口标识，并返回该请求的"对象值"。
//
// 判据设计：把同一接口上【query 参数值组合】或【路径最后一段】当作一个"数据组"。
// 同一接口读到超过 N 个不同的组合，就认为在批量读取。
//
//	GET /api/user?id=1   → key="h|/api/user"  val="id=1"
//	GET /api/user/2      → key="h|/api/user"  val="#2"     （路径末段当对象）
func readQuotaKey(rawURL string) (key, val string, objectLike bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	host := strings.ToLower(u.Hostname())
	path := u.Path
	if path == "" {
		path = "/"
	}
	// 有 query：按参数值组合算对象
	if q := u.RawQuery; q != "" {
		vals := u.Query()
		names := make([]string, 0, len(vals))
		for k := range vals {
			names = append(names, k)
		}
		sort.Strings(names)
		var b strings.Builder
		// ★★★ 语义（2026-10-17 第三版，前两版都被审计方证伪）：
		//
		//  【按参数分别计数】：只有"像对象标识"的非空值才进 val（= 计入读取配额）。
		//  载荷形状的值忽略 —— 但它【不豁免同一请求里的其它参数】。
		//
		//  ★ 前两版的错，及对应绕过：
		//   v1: if !looksLikeObjectValue(v) { allObjectLike=false }
		//       ?id=6&unused=            ⇒ 空值让整体豁免
		//   v2: hasObject && !hasPayload
		//       ?id=6&unused=%27         ⇒ 非空标点让整体豁免
		//   ⇒ 都被审计方（efc2bd5d）实测证伪。共同错误：把"整请求"当成一个判定单位。
		//
		//  v3 正确语义：判定单位是【参数值】。
		//   ?id=6&unused=%27  ⇒ val="id=6"   ⇒ 计数（unused 被忽略，不影响 id）
		//   ?id=1'            ⇒ val=""       ⇒ 不计数（纯注入载荷）
		//   ?a=1&b=2          ⇒ val="a=1&b=2"⇒ 计数
		hasObject := false
		for _, k := range names {
			v := vals.Get(k)
			if strings.TrimSpace(v) == "" {
				continue // 空值不参与：既不是对象，也不是载荷
			}
			if !looksLikeObjectValue(v) {
				continue // 载荷形状的值本身不计数（但也不豁免其它参数）
			}
			hasObject = true
			b.WriteString(k)
			b.WriteString("=")
			b.WriteString(v)
			b.WriteString("&")
		}
		return host + "|" + path, strings.TrimSuffix(b.String(), "&"), hasObject
	}
	// 无 query：把路径末段当对象标识
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) >= 2 {
		last := segs[len(segs)-1]
		prefix := "/" + strings.Join(segs[:len(segs)-1], "/")
		// 末段像 ID（纯数字 / 短 token、且不含载荷特征）才当对象
		if looksLikeObjectValue(last) {
			return host + "|" + prefix, "#" + last, true
		}
		_ = last
		// 末段是载荷（/api/user/1'/...）⇒ 不是对象遍历
		return host + "|" + path, path, false
	}
	return host + "|" + path, path, true
}

// looksLikeObjectValue 判断一个 query 值像不像"对象标识"（而不是测试 payload）。
//
// ★ 为什么要区分（2026-10-17 修）：原实现把「同一接口的 query 值组合」直接当成
// 「不同的数据组」计数。这会把 SQL 注入 / XSS / 命令注入的**载荷变体**也算成"读了新对象"：
//
//	/api/user?id=1          → id=1         （读了一个对象，应计数）
//	/api/user?id=1' OR '1'='1 → 载荷，不该算"又读了一个对象"
//
// 规则②的原意是「越权漏洞禁止批量读取，允许读取的数据不超过 N 组」——
// 约束的是【批量拉取别人的数据】，不是约束注入测试。误把载荷计进去，会让正常的
// 参数变体测试在第 6 个 payload 就被卡住，直接压缩挖掘空间。
func looksLikeObjectValue(v string) bool {
	if v == "" || len(v) > 40 {
		return false
	}
	// 含这些字符的值视为测试载荷：引号/括号/注释符/编码/路径/空白/模板符号
	const poison = "\"'<>()%;|&=/\\`${}[]+*#@!~^,:? \t\n"
	for _, c := range v {
		if strings.ContainsRune(poison, c) {
			return false
		}
	}
	return true
}

// checkReadQuota 判读取是否超配额。只在【携带身份】的请求上计数。
//
// 为什么只对带身份的请求计数：规则原文是「越权漏洞禁止批量读取，允许读取的数据不超过 5 组」——
// 受约束的是【越权读取】。匿名遍历不属于越权（但它仍受规则⑥的速率闸约束）。
func (t *ToolSet) checkReadQuota(rawURL, actor string) policyVerdict {
	if isAnonymousActor(actor) {
		return policyVerdict{Allowed: true, Rule: "ok"}
	}
	_, _, maxReads, _ := policyLimits()
	key, val, objectLike := readQuotaKey(rawURL)
	if key == "" || val == "" {
		return policyVerdict{Allowed: true, Rule: "ok"}
	}
	// ★ 载荷变体不算"读取新对象"（见 looksLikeObjectValue 注释）。
	// 由 readQuotaKey 逐值判定，避免把 "id=6" 自带的 '=' 当成载荷特征。
	if !objectLike {
		return policyVerdict{Allowed: true, Rule: "ok"}
	}

	p := policyFor(t.taskID)
	p.mu.Lock()
	defer p.mu.Unlock()

	set, ok := p.reads[key]
	if !ok {
		set = map[string]struct{}{}
		p.reads[key] = set
	}
	if _, seen := set[val]; seen {
		// 同一对象重复读，不增加配额消耗
		return policyVerdict{Allowed: true, Rule: "ok"}
	}
	if len(set) >= maxReads {
		// 给出去重后的已读对象样本，便于审计
		seenVals := make([]string, 0, len(set))
		for v := range set {
			seenVals = append(seenVals, v)
		}
		sort.Strings(seenVals)
		return policyVerdict{
			Allowed: false, Rule: "read_quota",
			Reason: fmt.Sprintf("测试规则②「越权漏洞禁止批量读取，允许读取的数据不超过 %d 组」："+
				"接口 %s 上已用【携带身份】的方式读到 %d 个不同对象（%s）。"+
				"继续批量读取会被拒。若需继续，请先由部署方调大 ARTEX_POLICY_MAX_READS，"+
				"并在报告中说明每组数据的必要性",
				maxReads, key, len(set), strings.Join(seenVals, ", ")),
			Detail: map[string]any{
				"endpoint": key, "used": len(set), "limit": maxReads, "seen": seenVals,
			},
		}
	}
	set[val] = struct{}{}
	return policyVerdict{Allowed: true, Rule: "ok"}
}

// policySnapshot 供工具/审计输出当前用量。
func (t *ToolSet) policySnapshot() map[string]any {
	maxTotal, maxPerMinute, maxReads, allowWrite := policyLimits()
	p := policyFor(t.taskID)
	p.mu.Lock()
	defer p.mu.Unlock()
	endpoints := make([]map[string]any, 0, len(p.reads))
	keys := make([]string, 0, len(p.reads))
	for k := range p.reads {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		endpoints = append(endpoints, map[string]any{"endpoint": k, "distinct_objects_read": len(p.reads[k])})
	}
	return map[string]any{
		"task_id":                t.taskID,
		"requests_used":          p.reqTotal,
		"requests_limit":         maxTotal,
		"this_minute_used":       p.winCount,
		"per_minute_limit":       maxPerMinute,
		"max_reads_per_endpoint": maxReads,
		"allow_write_methods":    allowWrite,
		"read_usage":             endpoints,
	}
}
