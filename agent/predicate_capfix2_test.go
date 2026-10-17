package agent

// predicate_capfix2_test.go —— 2026-10-17 第三轮：E1 语义收口的纯函数回归
//
// E1（evidence-audit）指出：原实现只要「两条响应不同」就判 session.valid / object.exists
// ⇒ 两个不同的 200 错误页（nonce/时间戳不同）就能互相"证明"会话有效。
//
// 收口后加的三条可判定前提：
//   session.valid  → 对照必须【匿名主体】+【同端点】
//   object.exists  → 对照必须【不同对象】+【同端点】
//
// 本文件只测 sameEndpoint（纯函数，不需要 DB）。完整谓词行为需要 PG，
// 由 predicate_capfix_test.go 在库可用时跑，不可用则 Skip（不假报通过）。

import "testing"

func TestSameEndpoint(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want bool
	}{
		// 同端点（query 不同，不影响）—— 这是最常用的对照形态
		{"同 path 不同 query", "http://x/api/user?id=1", "http://x/api/user?id=2", true},
		{"同 path 无 query", "http://x/api/user", "http://x/api/user", true},
		{"大小写 host", "http://X.example/api/u", "http://x.example/api/u", true},
		{"空 path 视为 /", "http://x", "http://x/", true},

		// 不同端点 —— 必须判 false，否则任意两条响应可互相当对照
		{"不同 path", "http://x/api/user", "http://x/api/other", false},
		{"不同 host", "http://x/a", "http://y/a", false},
		{"不同 scheme", "http://x/a", "https://x/a", false},
		{"子路径不同", "http://x/api/user/1", "http://x/api/user/2", false},
		{"空串", "", "http://x/a", false},
		{"不可解析", "://bad", "http://x/a", false},
	}

	for _, c := range cases {
		got := sameEndpoint(c.a, c.b)
		if got != c.want {
			t.Errorf("%s: sameEndpoint(%q, %q) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
	t.Logf("✓ %d 组端点判定全部符合预期", len(cases))
}

// 反向校验：确保这个函数不会把所有 URL 都判成同一个端点
func TestSameEndpointNotAlwaysTrue(t *testing.T) {
	pairs := [][2]string{
		{"http://a/x", "http://b/x"},
		{"http://a/x", "http://a/y"},
		{"https://a/x", "http://a/x"},
	}
	for _, p := range pairs {
		if sameEndpoint(p[0], p[1]) {
			t.Errorf("%q 与 %q 不该被判为同端点", p[0], p[1])
		}
	}
	t.Log("✓ 没有退化成恒真")
}
