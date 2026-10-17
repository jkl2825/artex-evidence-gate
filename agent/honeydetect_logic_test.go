package agent

import "testing"

func TestHoneypotSignatureLogic(t *testing.T) {
	e := newHoneypotEngine("/nonexistent/signatures.json") // 强制走内嵌库
	sigs := e.signatures()
	if len(sigs) == 0 {
		t.Fatal("内嵌签名库为空")
	}
	t.Logf("内嵌签名 %d 条", len(sigs))

	cases := []struct {
		name    string
		view    serviceView
		wantMin float64 // 期望命中的最低置信度；0 = 期望不命中
	}{
		{"cowrie banner", serviceView{Banner: "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"}, 0.99},
		{"opencanary server", serviceView{Banner: "Apache/2.2.22 (Ubuntu)"}, 0.85},
		{"glastopf body", serviceView{Body: "<h1>My Resource/</h1>"}, 0.9},
		{"仅端口 8080 无 body（不应命中 hfish）", serviceView{Port: 8080, Body: "hello"}, 0},
		{"正常 nginx", serviceView{Banner: "nginx/1.25.3", Title: "Dashboard", Body: "Welcome"}, 0},
		{"空视图（不应命中任何签名）", serviceView{}, 0},
	}
	for _, c := range cases {
		score, hits := e.evaluate(c.view)
		if c.wantMin == 0 {
			if score != 0 || len(hits) != 0 {
				t.Errorf("%s: 期望不命中，实际 score=%.2f hits=%v", c.name, score, hits)
			} else {
				t.Logf("%s: ✓ 不命中", c.name)
			}
		} else {
			if score < c.wantMin {
				t.Errorf("%s: 期望 score>=%.2f，实际 %.2f（hits=%v）", c.name, c.wantMin, score, hits)
			} else {
				t.Logf("%s: ✓ score=%.2f hits=%d", c.name, score, len(hits))
			}
		}
	}
}

// 空签名永不命中（防「无条件签名匹配一切」）
func TestHoneypotEmptyMatchNeverFires(t *testing.T) {
	var m honeypotMatch
	if m.matches(serviceView{Banner: "x", Body: "y", Title: "z", Port: 80}) {
		t.Fatal("空条件签名居然命中了 —— 防误报的硬约束失效")
	}
	t.Log("✓ 空条件签名不命中")
}
