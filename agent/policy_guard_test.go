package agent

import (
	"strconv"
	"testing"
)

// 每测一轮用不同的 taskID，避免共享全局状态互相污染。
func freshPolicyTask(id int64) *ToolSet {
	policyMu.Lock()
	delete(policyByTask, id)
	policyMu.Unlock()
	return &ToolSet{taskID: id}
}

// ── 规则⑤：写方法闸 ─────────────────────────────────────────────────────

func TestPolicyWriteMethodGate(t *testing.T) {
	t.Setenv("ARTEX_POLICY_ALLOW_WRITE", "")
	ts := freshPolicyTask(9001)

	for _, m := range []string{"GET", "get", "HEAD", "OPTIONS"} {
		if v := ts.checkMethod(m); !v.Allowed {
			t.Errorf("只读方法 %s 应放行，实际被拒：%s", m, v.Reason)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		v := ts.checkMethod(m)
		if v.Allowed {
			t.Errorf("写方法 %s 应被拒（规则⑤），实际放行", m)
			continue
		}
		if v.Rule != "write_method" {
			t.Errorf("%s 拒绝规则应为 write_method，实际 %s", m, v.Rule)
		}
	}

	// 显式开启后放行
	t.Setenv("ARTEX_POLICY_ALLOW_WRITE", "1")
	if v := ts.checkMethod("POST"); !v.Allowed {
		t.Errorf("ARTEX_POLICY_ALLOW_WRITE=1 时 POST 应放行，实际被拒")
	}
	t.Logf("✓ 规则⑤：默认只读；GET/HEAD/OPTIONS 放行，写方法拒；显式开启后放行")
}

// ── 规则②：越权读取配额（≤5 组）────────────────────────────────────────

func TestPolicyReadQuota(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")
	ts := freshPolicyTask(9002)

	const actor = "session:alice" // 非匿名 ⇒ 计入越权读取配额

	// 前 5 个不同对象应全部放行
	for i := 1; i <= 5; i++ {
		u := "http://api.example.com/api/user?id=" + strconv.Itoa(i)
		if v := ts.checkReadQuota(u, actor); !v.Allowed {
			t.Fatalf("第 %d 组应放行，实际被拒：%s", i, v.Reason)
		}
	}
	// 第 6 个不同对象应被拒
	v := ts.checkReadQuota("http://api.example.com/api/user?id=6", actor)
	if v.Allowed {
		t.Errorf("第 6 组应被规则②拒绝，实际放行")
	} else if v.Rule != "read_quota" {
		t.Errorf("拒绝规则应为 read_quota，实际 %s", v.Rule)
	} else {
		t.Logf("  第 6 组被拒：%s", v.Reason)
	}

	// 重复读已读过的对象：不占新配额，应放行
	if v := ts.checkReadQuota("http://api.example.com/api/user?id=3", actor); !v.Allowed {
		t.Errorf("重复读取已读对象不应消耗配额，实际被拒")
	}

	// 不同接口各自独立计数
	if v := ts.checkReadQuota("http://api.example.com/api/order?id=1", actor); !v.Allowed {
		t.Errorf("不同接口应独立计数，实际被拒")
	}

	// ★ 匿名请求不计入越权配额（受速率闸约束即可）
	for i := 1; i <= 20; i++ {
		u := "http://api.example.com/api/public?id=" + strconv.Itoa(i)
		if v := ts.checkReadQuota(u, "anonymous"); !v.Allowed {
			t.Fatalf("匿名读取不应受越权配额约束，第 %d 组被拒：%s", i, v.Reason)
		}
	}
	t.Logf("✓ 规则②：同接口前 5 组放行、第 6 组拒；重复读不扣；不同接口独立；匿名不计")
}

// ── 规则⑥：速率与总量 ──────────────────────────────────────────────────

func TestPolicyRateAndTotal(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_PER_MINUTE", "3")
	t.Setenv("ARTEX_POLICY_MAX_REQUESTS", "5")
	ts := freshPolicyTask(9003)

	for i := 1; i <= 3; i++ {
		if v := ts.checkBudget(); !v.Allowed {
			t.Fatalf("第 %d 发应放行（分钟上限 3），实际被拒：%s", i, v.Reason)
		}
	}
	v := ts.checkBudget()
	if v.Allowed {
		t.Errorf("第 4 发应被速率闸拒绝，实际放行")
	} else if v.Rule != "rate" {
		t.Errorf("拒绝规则应为 rate，实际 %s", v.Rule)
	} else {
		t.Logf("  第 4 发被速率闸拒：%s", v.Reason)
	}
	t.Logf("✓ 规则⑥：分钟窗口 3 发后拒（rate）")
}

func TestPolicyTotalCap(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_PER_MINUTE", "100")
	t.Setenv("ARTEX_POLICY_MAX_REQUESTS", "3")
	ts := freshPolicyTask(9004)

	for i := 1; i <= 3; i++ {
		if v := ts.checkBudget(); !v.Allowed {
			t.Fatalf("第 %d 发应放行（总量上限 3），实际被拒", i)
		}
	}
	v := ts.checkBudget()
	if v.Allowed {
		t.Errorf("第 4 发应被总量闸拒绝，实际放行")
	} else if v.Rule != "total" {
		t.Errorf("拒绝规则应为 total，实际 %s", v.Rule)
	}
	t.Logf("✓ 规则⑥：总量 3 发后拒（total）")
}

// ── 规则①：内网硬禁 + 白名单 ───────────────────────────────────────────

func TestPolicyIntranetDenied(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "")
	// 重新解析白名单（sync.Once 需要重置后才能读到新环境变量）
	resetIntranetAllowlistForTest()

	g := guardWith(true,
		scopeRule{kind: "cidr", ipnet: mustCIDR("10.0.0.0/8"), raw: "10.0.0.0/8", source: "agent"},
		scopeRule{kind: "cidr", ipnet: mustCIDR("172.18.0.0/16"), raw: "172.18.0.0/16", source: "agent"},
	)

	// ★ 2026-10-17「纵向可以、横向不行」：
	//   这里声明的是 10.0.0.0/8 与 172.18.0.0/16 —— 都【过宽】（< /24）。
	//   ⇒ 按新规则不放行：靠一句大网段声明去横扫内网，判为疑似横向。
	for _, h := range []string{"10.1.2.3", "172.18.0.5", "192.168.1.1"} {
		v := g.checkHost(h)
		if v.Allowed {
			t.Errorf("%s 只被宽网段覆盖或无声明，应判疑似横向，实际放行", h)
			continue
		}
		if v.Layer != "lateral_denied" {
			t.Errorf("%s 拒绝层级应为 lateral_denied，实际 %s", h, v.Layer)
		}
	}
	t.Logf("✓ 宽网段声明（/8、/16）不放行：判疑似横向，防止一句声明横扫内网")
}

func TestPolicyIntranetAllowlist(t *testing.T) {
	t.Setenv("ARTEX_INTRANET_ALLOW", "172.18.0.0/16")
	resetIntranetAllowlistForTest()

	g := guardWith(false)
	// 白名单内的私有网段放行
	if v := g.checkHost("172.18.0.5"); !v.Allowed {
		t.Errorf("172.18.0.5 在内网白名单内应放行，实际被拒：%s / %s", v.Layer, v.Rule)
	} else if v.Layer != "intranet_allowlisted" {
		t.Errorf("层级应为 intranet_allowlisted，实际 %s", v.Layer)
	}
	// 白名单外的私有网段仍拒
	if v := g.checkHost("10.1.2.3"); v.Allowed {
		t.Errorf("10.1.2.3 不在白名单内应被拒，实际放行")
	}
	t.Logf("✓ 规则①：白名单内放行（intranet_allowlisted），名单外仍拒")
}
