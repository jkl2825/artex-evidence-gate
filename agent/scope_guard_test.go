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
	g := guardWith(false)
	v := g.checkHost("example.com")
	if !v.Allowed {
		t.Fatalf("未声明范围时公网域名应放行（仅第一道闸生效），实际被拒：%s / %s", v.Layer, v.Rule)
	}
	if v.Layer != "no_scope_declared" {
		t.Errorf("层级应为 no_scope_declared，实际 %s", v.Layer)
	}
	// 但私有网段也应放行（因为无声明，只有绝对禁止段生效）
	v2 := g.checkHost("172.18.0.5")
	if !v2.Allowed || v2.Layer != "no_scope_declared" {
		t.Errorf("未声明范围时私有网段应放行并记警告，实际 allowed=%v layer=%s", v2.Allowed, v2.Layer)
	}
	t.Logf("✓ 未声明范围：公网与私有均放行，层级标 no_scope_declared（由上层决定是否记警告）")
}

// ── 已声明范围：fail-closed ─────────────────────────────────────────────

func TestScopeDeclaredFailClosed(t *testing.T) {
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

	// 私有网段：在 scope 里 → 放行
	if v := g.checkHost("172.18.0.5"); !v.Allowed {
		t.Errorf("172.18.0.5 在 172.18.0.0/16 内，应放行，实际 %s / %s", v.Layer, v.Rule)
	}
	// 私有网段：不在 scope 里 → 拒（private_requires_scope）
	if v := g.checkHost("10.1.2.3"); v.Allowed {
		t.Errorf("10.1.2.3 属私有网段且未声明，应被拒，实际允许")
	} else if v.Layer != "private_requires_scope" {
		t.Errorf("层级应为 private_requires_scope，实际 %s", v.Layer)
	}
	t.Logf("✓ 已声明范围：子域放行、伪子域拒绝、私有网段需显式声明")
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
