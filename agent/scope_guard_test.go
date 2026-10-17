package agent

import (
	"net"
	"testing"
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// 构造一个已声明范围的 guard（绕过 DB），用于纯逻辑测试。
func guardWith(declared bool, rules ...scopeRule) *scopeGuard {
	return &scopeGuard{
		taskID:   1,
		rules:    rules,
		declared: declared,
		mode:     ScopeEnforceDeclared,
	}
}

// ── 第一道闸：绝对禁止段，任何 scope、任何模式都不放行 ──────────────────

func TestScopeAbsolutelyDenied(t *testing.T) {
	cases := []string{
		"169.254.169.254", // 云元数据（AWS/GCP/Azure/阿里云/腾讯云）
		"169.254.1.1",     // 链路本地
		"127.0.0.1",       // 回环
		"127.1.2.3",
		"0.0.0.0",
		"224.0.0.1",       // 组播
		"255.255.255.255", // 广播（在 240/4）
		"::1",             // IPv6 回环
		"fe80::1",         // IPv6 链路本地
	}
	for _, h := range cases {
		// 即使把该地址显式写进 scope，也必须拒绝
		g := guardWith(true, scopeRule{kind: "ip", ipnet: mustCIDR(h + "/32"), raw: h})
		if h == "::1" || h == "fe80::1" {
			g = guardWith(true, scopeRule{kind: "ip", ipnet: mustCIDR(h + "/128"), raw: h})
		}
		v := g.checkHost(h)
		if v.Allowed {
			t.Errorf("%s 应被绝对禁止段拦下，但被判为允许（layer=%s rule=%s）", h, v.Layer, v.Rule)
			continue
		}
		if v.Layer != "absolutely_denied" {
			t.Errorf("%s 拒绝层级应为 absolutely_denied，实际 %s", h, v.Layer)
		}
		if !g.enforceMustBlock(v) {
			t.Errorf("%s 在 enforce 后应被拦，但没有", h)
		}
	}
	t.Logf("✓ %d 个绝对禁止目标全部被拦（含显式声明进 scope 的情况）", len(cases))
}

// enforceMustBlock 便于测试：返回是否被拦。
func (g *scopeGuard) enforceMustBlock(v scopeVerdict) bool {
	block, _ := g.enforce(v)
	return block
}

// ── 未声明范围：只走第一道闸 ────────────────────────────────────────────

func TestScopeUndeclaredAllowsPublicButWarns(t *testing.T) {
	// 清空白名单缓存，避免被其它测试的 t.Setenv 串扰（见 resetIntranetAllowlistForTest 注释）
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	resetIntranetAllowlistForTest()
	g := guardWith(false)
	v := g.checkHost("example.com")
	if !v.Allowed {
		t.Fatalf("未声明范围时公网域名应放行（仅第一道闸生效），实际被拒：%s / %s", v.Layer, v.Rule)
	}
	if v.Layer != "no_scope_declared" {
		t.Errorf("层级应为 no_scope_declared，实际 %s", v.Layer)
	}
	// ★ 2026-10-17「纵向可以、横向不行」：
	//   内网目标是否放行，看【有没有在 task_scope 里窄声明】，不是看"声明过没有"。
	//   这里 g 没有任何内网规则 ⇒ 172.18.0.5 属可疑横向 ⇒ lateral_denied。
	v2 := g.checkHost("172.18.0.5")
	if v2.Allowed {
		t.Errorf("未声明内网目标应判疑似横向，实际放行")
	} else if v2.Layer != "lateral_denied" {
		t.Errorf("层级应为 lateral_denied，实际 %s", v2.Layer)
	}
	t.Logf("✓ 未声明范围：公网放行并标 no_scope_declared；未声明的内网目标判疑似横向")
}

// ── 已声明范围：fail-closed ─────────────────────────────────────────────

func TestScopeDeclaredFailClosed(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	resetIntranetAllowlistForTest()
	g := guardWith(true,
		scopeRule{kind: "root_domain", domain: "example.com", raw: "example.com", source: "agent"},
		scopeRule{kind: "cidr", ipnet: mustCIDR("172.18.0.0/16"), raw: "172.18.0.0/16", source: "agent"},
	)

	allow := []string{"example.com", "api.example.com", "a.b.example.com"}
	for _, h := range allow {
		if v := g.checkHost(h); !v.Allowed {
			t.Errorf("%s 应命中 root_domain，实际被拒：%s / %s", h, v.Layer, v.Rule)
		}
	}

	deny := []string{
		"evil.com",             // 完全不在范围
		"notexample.com",       // 后缀相似但不是子域
		"example.com.evil.com", // 前缀伪装
	}
	for _, h := range deny {
		if v := g.checkHost(h); v.Allowed {
			t.Errorf("%s 不在声明范围内，应被拒，实际允许（layer=%s）", h, v.Layer)
		}
	}

	// ★ 2026-10-17「纵向可以、横向不行」：
	//   内网目标在 task_scope 里【窄声明】（IPv4 ≥/24）⇒ 放行（纵向）；
	//   未声明，或只声明了过宽的网段 ⇒ 拒绝（视为横向扩散）。
	//
	//   这里声明的 172.18.0.0/16 是【宽】的（/16 < /24）⇒ 按新规则仍被拒。
	//   ⇒ 这正是「不能靠一句 10.0.0.0/8 就横扫内网」的闸。
	if v := g.checkHost("172.18.0.5"); v.Allowed {
		t.Errorf("172.18.0.5 只被 /16 宽声明覆盖，应判疑似横向，实际放行")
	} else if v.Layer != "lateral_denied" {
		t.Errorf("层级应为 lateral_denied，实际 %s", v.Layer)
	}
	if v := g.checkHost("10.1.2.3"); v.Allowed {
		t.Errorf("10.1.2.3 无任何声明，应判疑似横向，实际允许")
	} else if v.Layer != "lateral_denied" {
		t.Errorf("层级应为 lateral_denied，实际 %s", v.Layer)
	}
	t.Logf("✓ 已声明范围：子域放行、伪子域拒绝、私有网段硬禁（规则①）")
}

// ── strict 模式：未声明一律拒 ───────────────────────────────────────────

func TestScopeStrictMode(t *testing.T) {
	// ★ 分工：checkHost 只做【事实判定】（这个 host 在不在已声明的边界内），
	//   enforce 才做【策略合成】（当前模式要不要因此拦截）。
	//   strict 模式的"拒绝"发生在 enforce 层，所以断言必须查 enforce 的返回值。
	g := guardWith(false)
	g.mode = ScopeEnforceStrict

	v := g.checkHost("example.com")
	if v.Layer != "no_scope_declared" {
		t.Errorf("checkHost 应如实报告 no_scope_declared，实际 %s", v.Layer)
	}
	block, out := g.enforce(v)
	if !block {
		t.Errorf("strict 模式下 enforce 应拦，实际未拦（layer=%s）", out.Layer)
	}
	if out.Layer != "scope_miss" {
		t.Errorf("strict 模式拦截层级应为 scope_miss，实际 %s", out.Layer)
	}

	// 对照：同样的 host，在 declared 模式下不该被拦
	g2 := guardWith(false)
	g2.mode = ScopeEnforceDeclared
	if b, _ := g2.enforce(g2.checkHost("example.com")); b {
		t.Errorf("declared 模式下未声明范围不应拦截（那是 strict 的行为）")
	}
	t.Logf("✓ strict 模式：未声明范围的目标被 enforce 拦下（%s）；declared 模式下不拦", out.Layer)
}

// ── audit_only 模式：只判定不拦，但绝对禁止段仍拦 ──────────────────────

func TestScopeAuditOnly(t *testing.T) {
	g := guardWith(true, scopeRule{kind: "root_domain", domain: "example.com", raw: "example.com", source: "agent"})
	g.mode = ScopeEnforceAuditOnly

	// 范围外但非绝对禁止：不拦，只标记
	v := g.checkHost("evil.com")
	block, _ := g.enforce(v)
	if block {
		t.Errorf("audit_only 模式下范围外目标不应被拦")
	}
	if v.Allowed {
		t.Errorf("audit_only 模式仍应给出真实判定（Allowed=false），实际 true")
	}

	// 绝对禁止段：任何模式都拦
	v2 := g.checkHost("169.254.169.254")
	block2, _ := g.enforce(v2)
	if !block2 {
		t.Errorf("audit_only 模式下绝对禁止段仍必须被拦，实际未拦")
	}
	t.Logf("✓ audit_only：范围外只标记不拦，绝对禁止段仍拦")
}

// ── host 归一化 ────────────────────────────────────────────────────────

func TestScopeHostNormalization(t *testing.T) {
	cases := map[string]string{
		"example.com:8080":        "example.com",
		"HTTP://Example.COM/path": "example.com",
		"example.com./":           "example.com",
		"user:pass@Example.com":   "example.com",
		"172.18.0.5:9000":         "172.18.0.5",
		"[::1]:8080":              "::1",
	}
	for in, want := range cases {
		if got := scopeNormHost(in); got != want {
			t.Errorf("scopeNormHost(%q) = %q，期望 %q", in, got, want)
		}
	}
	t.Logf("✓ host 归一化 %d 例通过", len(cases))
}

// ── 2026-10-17「纵向可以、横向不行」─────────────────────────────────────
//
// 判据：内网目标在 task_scope 里【窄声明】(IPv4 ≥/24) ⇒ 放行（纵向测试）；
//       未声明或只被宽网段覆盖 ⇒ 拒绝（疑似横向扩散）。

func TestIntranetVerticalAllowedByNarrowDeclare(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	resetIntranetAllowlistForTest()

	g := guardWith(true,
		// 单机声明（/32）
		scopeRule{kind: "ip", ipnet: mustCIDR("10.1.2.3/32"), raw: "10.1.2.3", source: "agent"},
		// /24 小网段（合规边界值）
		scopeRule{kind: "cidr", ipnet: mustCIDR("192.168.5.0/24"), raw: "192.168.5.0/24", source: "agent"},
	)

	allow := []string{"10.1.2.3", "192.168.5.10", "192.168.5.255"}
	for _, h := range allow {
		v := g.checkHost(h)
		if !v.Allowed {
			t.Errorf("%s 已被窄声明覆盖，应放行（纵向），实际被拒：%s / %s", h, v.Layer, v.Rule)
			continue
		}
		if v.Layer != "intranet_scope_declared" {
			t.Errorf("%s 放行层级应为 intranet_scope_declared，实际 %s", h, v.Layer)
		}
	}
	t.Logf("✓ 窄声明（/32、/24）的内网目标放行 —— 纵向测试")

	// 同一网段里没声明的邻居，仍要拒
	if v := g.checkHost("10.1.2.4"); v.Allowed {
		t.Errorf("10.1.2.4 与 10.1.2.3 同段但未声明，应判疑似横向，实际放行")
	} else if v.Layer != "lateral_denied" {
		t.Errorf("10.1.2.4 层级应为 lateral_denied，实际 %s", v.Layer)
	}
	t.Logf("✓ 同网段未声明的邻居仍被拒 —— 横向测试")
}

func TestIntranetWideDeclareStillDenied(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	resetIntranetAllowlistForTest()

	// 全是宽网段声明
	g := guardWith(true,
		scopeRule{kind: "cidr", ipnet: mustCIDR("10.0.0.0/8"), raw: "10.0.0.0/8", source: "agent"},
		scopeRule{kind: "cidr", ipnet: mustCIDR("172.16.0.0/12"), raw: "172.16.0.0/12", source: "agent"},
		scopeRule{kind: "cidr", ipnet: mustCIDR("192.168.0.0/16"), raw: "192.168.0.0/16", source: "agent"},
	)
	for _, h := range []string{"10.1.2.3", "172.20.0.5", "192.168.1.1"} {
		v := g.checkHost(h)
		if v.Allowed {
			t.Errorf("%s 只被宽网段（</24）覆盖，应判疑似横向，实际放行", h)
			continue
		}
		if v.Layer != "lateral_denied" {
			t.Errorf("%s 层级应为 lateral_denied，实际 %s", h, v.Layer)
		}
	}
	t.Logf("✓ /8 /12 /16 宽声明不放行 —— 防「一句声明横扫内网」")
}

func TestIntranetAllowlistStillWorks(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "172.18.0.0/16")
	resetIntranetAllowlistForTest()

	// 没有 task_scope 声明，但部署方白名单覆盖
	g := guardWith(true)
	if v := g.checkHost("172.18.0.5"); !v.Allowed {
		t.Errorf("172.18.0.5 在 ARTEX_INTRANET_ALLOW 内，应放行，实际被拒：%s / %s", v.Layer, v.Rule)
	} else if v.Layer != "intranet_allowlisted" {
		t.Errorf("层级应为 intranet_allowlisted，实际 %s", v.Layer)
	}
	// 白名单外的内网仍拒
	if v := g.checkHost("10.9.9.9"); v.Allowed {
		t.Errorf("10.9.9.9 既无声明也不在白名单，应拒，实际放行")
	}
	t.Logf("✓ 部署方白名单通道仍然有效")
}

func TestAbsolutlyDeniedBeatsNarrowDeclare(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	resetIntranetAllowlistForTest()

	// 即使窄声明了云元数据地址，也必须被第一道闸拦
	g := guardWith(true,
		scopeRule{kind: "ip", ipnet: mustCIDR("169.254.169.254/32"), raw: "169.254.169.254", source: "agent"},
	)
	if v := g.checkHost("169.254.169.254"); v.Allowed {
		t.Errorf("云元数据地址即使被窄声明也必须拦，实际放行")
	} else if v.Layer != "absolutely_denied" {
		t.Errorf("层级应为 absolutely_denied，实际 %s", v.Layer)
	}
	t.Logf("✓ 绝对禁止段不受声明影响")
}

func TestNarrowEnough(t *testing.T) {
	cases := []struct {
		cidr string
		want bool
	}{
		{"10.1.2.3/32", true},
		{"192.168.5.0/24", true},
		{"192.168.5.0/25", true},
		{"10.0.0.0/16", false},
		{"10.0.0.0/8", false},
		{"172.16.0.0/12", false},
	}
	for _, c := range cases {
		if got := narrowEnough(mustCIDR(c.cidr)); got != c.want {
			t.Errorf("narrowEnough(%s) = %v, want %v", c.cidr, got, c.want)
		}
	}
	t.Logf("✓ 宽窄判定 %d 例通过", len(cases))
}
