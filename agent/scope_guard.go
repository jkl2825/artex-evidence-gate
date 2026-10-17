package agent

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ════════════════════════════════════════════════════════════════════════════
// 授权范围守卫（scope guard）—— 本地新增 2026-10-17
//
// 解决什么：上游的 task_scope 是【覆盖度分母 + 查询过滤基准】，不是【执行前的授权边界】。
// 实测过的事实：
//   · 容器能直接访问互联网（http://example.com → 200）
//   · http_probe 此前不做任何范围校验
//   · 没有任何命令黑名单
//   · task_scope 记录的是「worker 碰到过什么」（source='auto'），不是「该碰什么」
// ⇒ 也就是说：只要模型"自己认为"在范围内，就能对任何地址发请求，没有任何一层拦。
//
// 本文件补的是【最前面那一层】：请求发出前，先问一句「这个 host 在授权边界内吗」。
//
// ★★ 设计要点（每条都是有意的取舍，不是随手写的）：
//
//  ① 【用 source 区分"授权声明"与"自动累积"】
//     source ∈ {manual, agent} → 视为授权声明（人填的，或 agent 主动声明的）
//     source = auto             → 视为自动累积（worker 碰到就记），**不作为边界**
//     否则会自证：碰到谁就把谁写进范围，然后"在范围内"。这是上游这套字段的固有陷阱。
//
//  ② 【三道闸，从硬到软】
//     第一道 绝对禁止（无例外，任何 scope 都覆盖不了）：云元数据 / 回环 / 链路本地 /
//             组播 / 保留段 / 未指定地址。理由：这些目标【在任何授权语境下都不该被测试】，
//             打元数据端点等于偷凭据，打回环等于 SSRF 打自己。
//     第二道 私有网段（10/8 · 172.16/12 · 192.168/16 · 100.64/10 · IPv6 ULA/链路本地）：
//             默认拒绝，必须【显式写进 scope】才允许。
//     第三道 授权声明匹配：root_domain / subdomain / ip / cidr。
//
//  ③ 【fail-closed，但区分"没声明"与"声明了没匹配"】
//     有声明的任务（declared=true）→ 不匹配就拒（真 fail-closed）
//     无声明的任务（declared=false）→ 只走到第一道（绝对禁止），
//                                     并返回 no_scope_declared 警告，由上层决定怎么记
//     理由：直接全量 fail-closed 会把存量任务一次性锁死（实测我们 9 个任务的
//     task_scope 全是 0 条），护栏装上等于系统停摆。见 ScopeEnforceMode 的说明。
//
//  ④ 【DNS 解析只用于 deny，不用来 allow】
//     域名能匹配 scope 就允许；但同时把域名解析一次，若解析出的 IP 落在第一道禁止段，
//     **仍然拒绝** —— 这是防 DNS rebinding（`http://evil.com` → 169.254.169.254）。
//     反向不成立：解析出的 IP 在 scope 里，也不代表域名本身被授权。
//
//  ⑤ 【规则可拒绝，也可解释】
//     每次判定都返回命中的具体规则或拒绝的具体理由，便于审计与给模型可执行的补救指令。
// ════════════════════════════════════════════════════════════════════════════

// ScopeEnforceMode 控制守卫的严格程度。
type ScopeEnforceMode string

const (
	// ScopeEnforceStrict：绝对禁止段 + 有无声明都一律要求匹配。
	// 适合"范围已明确声明"的生产任务。
	ScopeEnforceStrict ScopeEnforceMode = "strict"

	// ScopeEnforceDeclared（默认）：绝对禁止段永远生效；
	// 有声明的任务 fail-closed；无声明的任务放行但打警告。
	// 这是"护栏能装上、又不锁死存量任务"的折中。
	ScopeEnforceDeclared ScopeEnforceMode = "declared"

	// ScopeEnforceAuditOnly：只判定不拦截，把结论写进 observation 供审计。
	ScopeEnforceAuditOnly ScopeEnforceMode = "audit_only"
)

// scopeVerdict 是一次判定的结果。
type scopeVerdict struct {
	Allowed    bool   `json:"allowed"`
	Layer      string `json:"layer"` // absolutely_denied | private_requires_scope | scope_matched | scope_miss | no_scope_declared | unparsable
	Rule       string `json:"rule"`  // 命中的规则（或拒绝依据的摘要）
	Host       string `json:"host"`  // 归一化后的 host
	ResolvedIP string `json:"resolved_ip,omitempty"`
	Note       string `json:"note,omitempty"`
}

func (v scopeVerdict) String() string {
	if v.Allowed {
		return fmt.Sprintf("scope allow (%s) host=%s rule=%s", v.Layer, v.Host, v.Rule)
	}
	return fmt.Sprintf("scope deny (%s) host=%s rule=%s", v.Layer, v.Host, v.Rule)
}

// scopeRule 一条可判定的授权规则。
type scopeRule struct {
	kind   string // root_domain | subdomain | ip | cidr
	domain string // 小写、去尾点
	ipnet  *net.IPNet
	raw    string // 原始值，报告用
	source string
}

// scopeGuard 某个任务的授权边界快照。
type scopeGuard struct {
	taskID   int64
	rules    []scopeRule
	declared bool // 是否存在 source ∈ {manual, agent} 的声明
	loaded   time.Time
	mode     ScopeEnforceMode
	// ignoreICPKW 为 true 时，icp/keyword 类 scope 不参与 host 判定（它们无法从 host 反推）。
	// 现在恒为 true —— 保留字段是为了将来若要按 ICP 反查域名时不必改结构。
	ignoreICPKW bool
}

// ── 绝对禁止段：任何 scope 都覆盖不了 ──────────────────────────────────────

var absolutelyDeniedNets = mustParseNets(
	// 云元数据 / 链路本地（AWS/GCP/Azure/阿里云/腾讯云 的 169.254.169.254 都在这里）
	"169.254.0.0/16",
	// 回环：访问 127.0.0.1 等于打容器自己（SSRF 最常见的目标）
	"127.0.0.0/8",
	// "本网络"
	"0.0.0.0/8",
	// 组播
	"224.0.0.0/4",
	// 保留（含 255.255.255.255 广播）
	"240.0.0.0/4",
	// IPv6：回环 / 链路本地 / 组播
	"::1/128",
	"fe80::/10",
	"ff00::/8",
)

// ── 私有网段：默认拒绝，需显式声明 ────────────────────────────────────────

var privateNets = mustParseNets(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // CGNAT
	"fc00::/7",      // IPv6 ULA
)

func mustParseNets(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func ipInAny(ip net.IP, nets []*net.IPNet) (*net.IPNet, bool) {
	if ip == nil {
		return nil, false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return n, true
		}
	}
	return nil, false
}

// ── 内网白名单（测试规则①：禁止内网渗透）────────────────────────────────
//
// 语义变化（2026-10-17 按用户给定规则调整）：
//   旧：私有网段"需在 scope 中显式声明"才允许 —— 但"声明"只能证明"我知道我在打内网"，
//       不能证明"被授权打内网"。规则明确禁止内网渗透，所以改成【默认硬禁】。
//   新：私有网段一律拒绝，只有落在 ARTEX_INTRANET_ALLOW 列出的 CIDR 里才放行。
//       该白名单由部署方设置（例如本地靶机所在的 Docker 网段），模型无法自行打开。

var (
	intranetAllowOnce sync.Once
	intranetAllowList []*net.IPNet
)

// intranetAllowlist 解析 ARTEX_INTRANET_ALLOW（逗号分隔 CIDR 或裸 IP）。
func intranetAllowlist() []*net.IPNet {
	intranetAllowOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("ARTEX_INTRANET_ALLOW"))
		if raw == "" {
			return
		}
		for _, item := range strings.Split(raw, ",") {
			c := strings.TrimSpace(item)
			if c == "" {
				continue
			}
			if !strings.Contains(c, "/") {
				if ip := net.ParseIP(c); ip != nil {
					bits := 32
					if ip.To4() == nil {
						bits = 128
					}
					c = fmt.Sprintf("%s/%d", ip.String(), bits)
				}
			}
			if _, n, err := net.ParseCIDR(c); err == nil {
				intranetAllowList = append(intranetAllowList, n)
			}
		}
	})
	return intranetAllowList
}

// resetIntranetAllowlistForTest 清空已解析的白名单缓存，供测试隔离用。
//
// 为什么需要：intranetAllowOnce / intranetAllowList 是包级全局，而 t.Setenv 只恢复
// 环境变量、不会重置已解析的切片。不重置就会出现"前面的测试设了白名单，
// 后面的测试莫名被放行"的串扰（实测踩过）。
func resetIntranetAllowlistForTest() {
	intranetAllowOnce = sync.Once{}
	intranetAllowList = nil
}

// intranetAllowed 判某私有地址是否落在白名单里。
func intranetAllowed(ip net.IP) (*net.IPNet, bool) {
	if ip == nil {
		return nil, false
	}
	for _, n := range intranetAllowlist() {
		if n.Contains(ip) {
			return n, true
		}
	}
	return nil, false
}

// ── host 归一化 ───────────────────────────────────────────────────────────

// scopeNormHost 把 host / host:port / [v6]:port 归一化为小写去尾点的裸 host。
func scopeNormHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	// 去掉可能的 scheme（容错）
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	// 去掉 path / query / fragment
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(h, sep); i >= 0 {
			h = h[:i]
		}
	}
	// 去掉 userinfo
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	// 去端口
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	h = strings.Trim(h, "[]")
	return h
}

// scopeHostFromURL 从完整 URL 取 host；解析失败时退回字符串处理。
func scopeHostFromURL(raw string) (host string, port string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return scopeNormHost(u.Host), u.Port()
	}
	// 容错：没有 scheme 的 "example.com:8080/path"
	h := scopeNormHost(raw)
	if host, p, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(raw, "//"), "http://")); err == nil {
		host = scopeNormHost(host)
		return host, p
	}
	return h, ""
}

// ── 加载与缓存 ────────────────────────────────────────────────────────────

var (
	scopeGuardMu    sync.Mutex
	scopeGuardCache = map[int64]*scopeGuard{}
	scopeGuardTTL   = 30 * time.Second
)

// loadScopeGuard 读取并缓存某任务的授权边界。
// declared 只统计 source ∈ {manual, agent}；source='auto' 是自动累积，不算声明。
func (t *ToolSet) loadScopeGuard() *scopeGuard {
	// 模式由环境变量 ARTEX_SCOPE_MODE 控制（declared 为默认）：
	//   strict      —— 必须显式声明范围，未声明一律拒绝
	//   declared    —— 绝对禁止段永远生效；有声明的任务 fail-closed；未声明的放行但打警告
	//   audit_only  —— 只判定不拦截（绝对禁止段仍拦）
	mode := ScopeEnforceDeclared
	switch ScopeEnforceMode(strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_SCOPE_MODE")))) {
	case ScopeEnforceStrict:
		mode = ScopeEnforceStrict
	case ScopeEnforceAuditOnly:
		mode = ScopeEnforceAuditOnly
	}
	g := &scopeGuard{taskID: t.taskID, mode: mode, ignoreICPKW: true}

	if t.as == nil || t.taskID <= 0 {
		// 没有任务上下文（测试 / 编排器跨任务读）：只保留绝对禁止段
		g.declared = false
		g.loaded = time.Now()
		return g
	}

	scopeGuardMu.Lock()
	if c, ok := scopeGuardCache[t.taskID]; ok && time.Since(c.loaded) < scopeGuardTTL && c.mode == mode {
		scopeGuardMu.Unlock()
		return c
	}
	scopeGuardMu.Unlock()

	rows, err := t.as.ListTaskScope(t.taskID)
	if err == nil {
		for _, r := range rows {
			src := strings.ToLower(strings.TrimSpace(r.Source))
			isDecl := src == "manual" || src == "agent"
			if isDecl {
				g.declared = true
			}
			if !isDecl {
				// 自动累积的行不参与边界判定（否则自证）
				continue
			}
			switch r.Kind {
			case "root_domain", "subdomain":
				d := scopeNormHost(r.Domain)
				if d == "" {
					continue
				}
				g.rules = append(g.rules, scopeRule{kind: r.Kind, domain: d, raw: r.Domain, source: src})
			case "ip", "cidr":
				netStr := strings.TrimSpace(r.Net)
				if netStr == "" {
					continue
				}
				if !strings.Contains(netStr, "/") {
					// 单 IP 转 /32 或 /128
					if ip := net.ParseIP(netStr); ip != nil {
						bits := 32
						if ip.To4() == nil {
							bits = 128
						}
						netStr = fmt.Sprintf("%s/%d", ip.String(), bits)
					}
				}
				if _, n, err := net.ParseCIDR(netStr); err == nil {
					g.rules = append(g.rules, scopeRule{kind: r.Kind, ipnet: n, raw: netStr, source: src})
				}
			}
		}
	}
	// 稳定排序，便于报告可复现
	sort.Slice(g.rules, func(i, j int) bool {
		if g.rules[i].kind != g.rules[j].kind {
			return g.rules[i].kind < g.rules[j].kind
		}
		return g.rules[i].raw < g.rules[j].raw
	})

	g.loaded = time.Now()
	scopeGuardMu.Lock()
	scopeGuardCache[t.taskID] = g
	scopeGuardMu.Unlock()
	return g
}

// invalidateScopeGuard 在 scope 变更后清缓存（add_task_scope 调用时用）。
func invalidateScopeGuard(taskID int64) {
	scopeGuardMu.Lock()
	delete(scopeGuardCache, taskID)
	scopeGuardMu.Unlock()
}

// ── 判定 ──────────────────────────────────────────────────────────────────

var ipLiteralLike = regexp.MustCompile(`^[0-9a-fA-F:.]+$`)

// ── DNS 解析缓存 ──────────────────────────────────────────────────────────
//
// checkHost 对域名要解析一次（用于"是否落到绝对禁止段"的检查）。
// 不做缓存的话每个 http_probe 都会查一次，实测会让单测从 0.02s 涨到 1.7s。
// 缓存 60 秒：够挡重复请求，又不至于让 DNS 变更长时间失效。

type dnsCacheEntry struct {
	ips []net.IP
	at  time.Time
}

var (
	dnsCacheMu  sync.Mutex
	dnsCache    = map[string]dnsCacheEntry{}
	dnsCacheTTL = 60 * time.Second
)

// scopeDNSLookup 带缓存的解析；失败返回 nil（调用方按"解析不到"处理）。
func scopeDNSLookup(host string) []net.IP {
	dnsCacheMu.Lock()
	if e, ok := dnsCache[host]; ok && time.Since(e.at) < dnsCacheTTL {
		dnsCacheMu.Unlock()
		return e.ips
	}
	dnsCacheMu.Unlock()

	ips, err := net.LookupIP(host)
	if err != nil {
		ips = nil
	}
	// 只缓存成功结果：失败可能是临时抖动，缓存住会让后续请求一直被拒
	if len(ips) > 0 {
		dnsCacheMu.Lock()
		dnsCache[host] = dnsCacheEntry{ips: ips, at: time.Now()}
		// 简单的容量上限，避免长时间运行后无限增长
		if len(dnsCache) > 4096 {
			for k := range dnsCache {
				delete(dnsCache, k)
				if len(dnsCache) <= 2048 {
					break
				}
			}
		}
		dnsCacheMu.Unlock()
	}
	return ips
}

// invalidateDNSCache 在 scope 变更时清掉（同 host 的判定可能因 scope 变化而变，
// 但 DNS 结果本身不变；保留此函数是为了测试与手工干预）。
func invalidateDNSCache() {
	dnsCacheMu.Lock()
	dnsCache = map[string]dnsCacheEntry{}
	dnsCacheMu.Unlock()
}

// checkHost 判定一个 host 是否在授权边界内。
func (g *scopeGuard) checkHost(host string) scopeVerdict {
	host = scopeNormHost(host)
	v := scopeVerdict{Host: host}
	if host == "" {
		v.Layer = "unparsable"
		v.Rule = "空 host，无法判定"
		return v
	}

	// 是否为 IP 字面量
	var ip net.IP
	if ipLiteralLike.MatchString(host) {
		ip = net.ParseIP(host)
	}

	// ── 第一道：绝对禁止（无论 scope 怎么写、无论有无声明）──
	if ip != nil {
		if n, hit := ipInAny(ip, absolutelyDeniedNets); hit {
			v.Layer = "absolutely_denied"
			v.Rule = fmt.Sprintf("%s 命中绝对禁止段 %s（云元数据/回环/链路本地/组播/保留）", host, n.String())
			return v
		}
	} else {
		// 域名：解析一次，只用于"若落到绝对禁止段则拒绝"（防 DNS rebinding）
		if addrs := scopeDNSLookup(host); len(addrs) > 0 {
			for _, a := range addrs {
				if n, hit := ipInAny(a, absolutelyDeniedNets); hit {
					v.Layer = "absolutely_denied"
					v.ResolvedIP = a.String()
					v.Rule = fmt.Sprintf("%s 解析到 %s，命中绝对禁止段 %s（疑似 DNS rebinding）",
						host, a.String(), n.String())
					return v
				}
			}
			if len(addrs) > 0 {
				v.ResolvedIP = addrs[0].String()
			}
		}
	}

	// ── 第二道 + 第三道 ──
	if ip == nil {
		// 域名匹配：root_domain（含子域）/ subdomain（精确）
		for _, r := range g.rules {
			switch r.kind {
			case "subdomain":
				if host == r.domain {
					v.Allowed = true
					v.Layer = "scope_matched"
					v.Rule = fmt.Sprintf("subdomain=%s（source=%s）", r.raw, r.source)
					return v
				}
			case "root_domain":
				if host == r.domain || strings.HasSuffix(host, "."+r.domain) {
					v.Allowed = true
					v.Layer = "scope_matched"
					v.Rule = fmt.Sprintf("root_domain=%s（含子域，source=%s）", r.raw, r.source)
					return v
				}
			}
		}
		// 域名没匹配上：如果解析到了私有 IP，按私有网段规则再判一次
		if v.ResolvedIP != "" {
			if rip := net.ParseIP(v.ResolvedIP); rip != nil {
				if _, hit := ipInAny(rip, privateNets); hit {
					// 尝试用 IP 类规则匹配
					for _, r := range g.rules {
						if r.ipnet != nil && r.ipnet.Contains(rip) {
							v.Allowed = true
							v.Layer = "scope_matched"
							v.Rule = fmt.Sprintf("%s 解析到 %s，命中 %s=%s",
								host, v.ResolvedIP, r.kind, r.raw)
							return v
						}
					}
					// ★ 规则①：解析到私有地址 → 内网硬禁（白名单例外）
					if allowNet, ok := intranetAllowed(rip); ok {
						v.Allowed = true
						v.Layer = "intranet_allowlisted"
						v.Rule = fmt.Sprintf("%s 解析到 %s，属内网白名单 %s",
							host, v.ResolvedIP, allowNet.String())
						return v
					}
					v.Layer = "intranet_denied"
					v.Rule = fmt.Sprintf("测试规则①「禁止进行内网渗透行为」：%s 解析到私有地址 %s。"+
						"内网目标默认禁止；需由部署方把该网段加入 ARTEX_INTRANET_ALLOW", host, v.ResolvedIP)
					return v
				}
				// 公网 IP 但域名没在 scope 里
				if !g.declared {
					v.Allowed = true
					v.Layer = "no_scope_declared"
					v.Rule = fmt.Sprintf("%s（%s）不在 scope 中，但本任务【未声明范围】，仅绝对禁止段生效", host, v.ResolvedIP)
					return v
				}
			}
		}
		if g.declared {
			v.Layer = "scope_miss"
			v.Rule = fmt.Sprintf("%s 不匹配任何已声明规则；如需测试请用 add_task_scope 加入"+
				"（kind=root_domain/subdomain/ip/cidr）", host)
			return v
		}
		v.Allowed = true
		v.Layer = "no_scope_declared"
		v.Rule = fmt.Sprintf("%s 不在 scope 中，但本任务【未声明范围】，仅绝对禁止段生效", host)
		return v
	}

	// ★★★ 顺序说明（2026-10-17 修正）：
	//   绝对禁止段 → 【内网硬禁】 → scope 匹配。
	//   内网检查必须排在 scope 匹配【之前】：否则只要把 10.0.0.0/8 声明进 scope，
	//   就会先命中 scope 分支而放行 —— "规则①禁止内网渗透" 就形同虚设。
	//   这条是单测 TestPolicyIntranetDenied 抓出来的真实顺序 bug。

	// ★ 规则①：内网硬禁。私有网段一律拒绝，只有 ARTEX_INTRANET_ALLOW 白名单里的段放行。
	if n, hit := ipInAny(ip, privateNets); hit {
		if allowNet, ok := intranetAllowed(ip); ok {
			v.Allowed = true
			v.Layer = "intranet_allowlisted"
			v.Rule = fmt.Sprintf("%s 属私有网段 %s，但落在内网白名单 %s 内（ARTEX_INTRANET_ALLOW）",
				host, n.String(), allowNet.String())
			return v
		}
		v.Layer = "intranet_denied"
		v.Rule = fmt.Sprintf("测试规则①「禁止进行内网渗透行为」：%s 属私有网段 %s。"+
			"内网目标默认禁止；若这是获授权的内网测试环境，需由部署方把该网段加入 "+
			"ARTEX_INTRANET_ALLOW（模型无法自行打开）", host, n.String())
		return v
	}

	// 内网白名单放行后，再看是否命中其它 scope 规则（公网目标走这里）
	for _, r := range g.rules {
		if r.ipnet != nil && r.ipnet.Contains(ip) {
			v.Allowed = true
			v.Layer = "scope_matched"
			v.Rule = fmt.Sprintf("%s=%s（source=%s）", r.kind, r.raw, r.source)
			return v
		}
	}
	// 公网 IP 未匹配
	if g.declared {
		v.Layer = "scope_miss"
		v.Rule = fmt.Sprintf("%s 不匹配任何已声明规则；如需测试请用 add_task_scope 加入（kind=ip/cidr）", host)
		return v
	}
	v.Allowed = true
	v.Layer = "no_scope_declared"
	v.Rule = fmt.Sprintf("%s 不在 scope 中，但本任务【未声明范围】，仅绝对禁止段生效", host)
	return v
}

// checkURL 判定一个完整 URL 的目标是否在授权边界内。
func (g *scopeGuard) checkURL(raw string) scopeVerdict {
	host, _ := scopeHostFromURL(raw)
	return g.checkHost(host)
}

// enforce 把 verdict 与模式合成为"是否真的拦"。
// audit_only 模式下永不拦，但 verdict 仍带真实判定，供审计记录。
func (g *scopeGuard) enforce(v scopeVerdict) (block bool, out scopeVerdict) {
	// 绝对禁止段：任何模式都拦 —— 打元数据端点不属于"策略选择"范畴
	if v.Layer == "absolutely_denied" {
		return true, v
	}
	if g.mode == ScopeEnforceAuditOnly {
		return false, v
	}
	if g.mode == ScopeEnforceStrict && v.Layer == "no_scope_declared" {
		v.Allowed = false
		v.Layer = "scope_miss"
		v.Rule = "strict 模式下要求先声明范围（add_task_scope），当前任务未声明任何范围"
		return true, v
	}
	return !v.Allowed, v
}

// scopeRulesSummary 供工具/审计输出：当前生效的规则清单。
func (g *scopeGuard) summary() map[string]any {
	rules := make([]map[string]any, 0, len(g.rules))
	for _, r := range g.rules {
		m := map[string]any{"kind": r.kind, "source": r.source}
		if r.domain != "" {
			m["domain"] = r.domain
		}
		if r.ipnet != nil {
			m["net"] = r.ipnet.String()
		}
		rules = append(rules, m)
	}
	return map[string]any{
		"task_id":                g.taskID,
		"mode":                   string(g.mode),
		"declared":               g.declared,
		"rule_count":             len(rules),
		"rules":                  rules,
		"absolutely_denied_nets": netStrings(absolutelyDeniedNets),
		"private_nets":           netStrings(privateNets),
		"note":                   "只有 source ∈ {manual, agent} 的 scope 参与边界判定；source=auto 是自动累积，不构成授权",
	}
}

func netStrings(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// ── 自动声明范围 ──────────────────────────────────────────────────────────

// scopeCandidateRe 从自由文本里抓「像目标」的 token。
// 覆盖：带 scheme 的 URL、host:port、裸域名、IPv4。
var scopeCandidateRe = regexp.MustCompile(`(?i)(?:https?://[^\s<>"'）)\]，,；;]+` +
	`|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b` +
	`|\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?\b` +
	`|\b[a-z][a-z0-9-]{1,62}(?::\d{2,5})\b)`)

// declareScopeFromText 从任务的目标/描述文本里提取目标并写入 scope（source='agent'）。
//
// 为什么需要它：实测存量 9 个任务的 task_scope 全是 0 条。护栏一装，
// 「已声明才 fail-closed」这条就永远不会生效。所以任务开始时要能把目标写进去。
//
// 只做【显式提取】，不做任何猜测性扩大：
//
//	· 提取到带点的域名 → kind=subdomain（精确），不自动扩成 root_domain
//	· 提取到 IP        → kind=ip
//	· 单标签主机名（如容器名 vulnlab）→ 解析成 IP 后 kind=ip；解析失败则跳过
//	· 绝不写入 root_domain（那等于把整个域纳入，是权限扩大，必须由人或 agent 显式声明）
func (t *ToolSet) declareScopeFromText(text, reason string) (added []string, skipped []string) {
	if t.as == nil || t.taskID <= 0 || strings.TrimSpace(text) == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, raw := range scopeCandidateRe.FindAllString(text, -1) {
		host := scopeNormHost(raw)
		if host == "" || len(host) > 253 {
			continue
		}
		if seen[host] {
			continue
		}
		seen[host] = true

		// IP 字面量 → kind=ip
		if ip := net.ParseIP(host); ip != nil {
			// 绝对禁止段不写进 scope（写了也没用，反而误导）
			if _, hit := ipInAny(ip, absolutelyDeniedNets); hit {
				skipped = append(skipped, host+"（绝对禁止段，不入 scope）")
				continue
			}
			if _, err := t.as.AddAgentScope(t.taskID, "ip", host, reason, "agent"); err == nil {
				added = append(added, "ip:"+host)
			} else {
				skipped = append(skipped, host+"（"+err.Error()+"）")
			}
			continue
		}

		// 含点的域名 → kind=subdomain（精确，不扩根域）
		if strings.Contains(host, ".") {
			if _, err := t.as.AddAgentScope(t.taskID, "subdomain", host, reason, "agent"); err == nil {
				added = append(added, "subdomain:"+host)
			} else {
				skipped = append(skipped, host+"（"+err.Error()+"）")
			}
			continue
		}

		// 单标签主机名（容器名 / 内网短名）→ 解析成 IP 再入 scope
		if addrs, err := net.LookupIP(host); err == nil && len(addrs) > 0 {
			ip := addrs[0]
			if _, hit := ipInAny(ip, absolutelyDeniedNets); hit {
				skipped = append(skipped, host+"（解析到绝对禁止段）")
				continue
			}
			if _, err := t.as.AddAgentScope(t.taskID, "ip", ip.String(), reason+"（由主机名 "+host+" 解析）", "agent"); err == nil {
				added = append(added, "ip:"+ip.String()+"←"+host)
			} else {
				skipped = append(skipped, host+"（"+err.Error()+"）")
			}
		} else {
			skipped = append(skipped, host+"（单标签主机名且解析失败）")
		}
	}
	if len(added) > 0 {
		invalidateScopeGuard(t.taskID)
	}
	return added, skipped
}
