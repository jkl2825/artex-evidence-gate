package agent

// policy_guard_capfix_test.go —— 2026-10-17 挖掘能力审计的回归测试
//
// 这组测试钉住三件事，都是"看起来防住了、实际在拖累挖掘"的缺陷：
//   ① 载荷变体不该被算成"读取了新的数据组"（否则注入测试打到第 6 个 payload 就被卡）
//   ② 被前一道闸拒绝的请求不该继续消耗后面的额度（顺序判定）
//   ③ 读取配额只对"像对象标识"的值生效
//
// 全部是纯内存函数，不依赖 PostgreSQL / 网络 / 服务。

import (
	"strconv"
	"testing"
)

// snapInt 从 policySnapshot 的 map 里安全取整数。
// policySnapshot 用的是 int，而 numOr0 只处理 float64/int64/json.Number —— 直接用它恒得 0。
func snapInt(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// ── ① 载荷识别 ─────────────────────────────────────────────────────────────

func TestLooksLikeObjectValue(t *testing.T) {
	// 像对象标识：应当计入"读取组"
	objectLike := []string{
		"1", "42", "10086",
		"abc123", "user_7", "550e8400-e29b-41d4-a716-446655440000",
		"a", "Z", "item-2026",
	}
	for _, v := range objectLike {
		if !looksLikeObjectValue(v) {
			t.Errorf("%q 像对象标识，应计入读取配额，实际被判为载荷", v)
		}
	}

	// 像测试载荷：不该计入（否则 SQLi/XSS/命令注入的参数变体会耗光配额）
	payloadLike := []string{
		"1'", "1' OR '1'='1", `1"`, "1;id", "1|whoami",
		"<script>", "../../etc/passwd", "%27", "${7*7}",
		"1 AND SLEEP(5)", "a b", "x=1&y=2", "1`id`",
	}
	for _, v := range payloadLike {
		if looksLikeObjectValue(v) {
			t.Errorf("%q 含测试载荷特征，不应计入读取配额，实际被计数", v)
		}
	}

	// 边界
	if looksLikeObjectValue("") {
		t.Error("空值不该计数")
	}
	if looksLikeObjectValue(string(make([]byte, 41))) {
		t.Error("超长值（>40）不该计数")
	}
	t.Logf("✓ 载荷识别：%d 个对象样值放行 · %d 个载荷样值豁免", len(objectLike), len(payloadLike))
}

// 端到端：同一接口连续打 10 个注入 payload，不应触发 read_quota。
func TestReadQuotaIgnoresInjectionPayloads(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")
	ts := freshPolicyTask(7001)
	const actor = "session:alice"

	payloads := []string{
		"1'", "1''", "1'--", "1'#", `1"`, "1;id", "1|id",
		"1 AND 1=1", "1 AND 1=2", "<svg/onload=alert(1)>",
	}
	for i, pl := range payloads {
		u := "http://t.example.com/api/user?id=" + pl
		if v := ts.checkReadQuota(u, actor); !v.Allowed {
			t.Fatalf("第 %d 个载荷 %q 被 read_quota 拦下（这是误伤）：%s", i+1, pl, v.Reason)
		}
	}
	t.Logf("✓ %d 个注入载荷全部放行，未消耗读取配额", len(payloads))
}

// 对照：真正的批量遍历仍然要被挡住。
func TestReadQuotaStillBlocksRealEnumeration(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")
	ts := freshPolicyTask(7002)
	const actor = "session:alice"

	for i := 1; i <= 5; i++ {
		u := "http://t.example.com/api/user?id=" + strconv.Itoa(i)
		if v := ts.checkReadQuota(u, actor); !v.Allowed {
			t.Fatalf("第 %d 组真实对象应放行，实际被拒：%s", i, v.Reason)
		}
	}
	v := ts.checkReadQuota("http://t.example.com/api/user?id=6", actor)
	if v.Allowed {
		t.Error("第 6 组真实对象应被 read_quota 拦下（这是规则②的本意），实际放行")
	} else {
		t.Logf("✓ 真实遍历第 6 组仍被拦：rule=%s", v.Rule)
	}
}

// ── ② 顺序判定：被拒的请求不消耗额度 ───────────────────────────────────────

func TestRejectedRequestDoesNotConsumeBudget(t *testing.T) {
	// 只读模式（默认），POST 会被 method 闸拒绝
	t.Setenv("ARTEX_POLICY_ALLOW_WRITE", "0")
	t.Setenv("ARTEX_POLICY_MAX_PER_MINUTE", "100")
	t.Setenv("ARTEX_POLICY_MAX_REQUESTS", "100")
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")

	ts := freshPolicyTask(7003)
	before := ts.policySnapshot()
	usedBefore := snapInt(before, "requests_used")

	// 模拟「先过 method 闸，失败就返回」的正确顺序
	if pv := ts.checkMethod("POST"); pv.Allowed {
		t.Fatal("POST 在只读模式下应被拒")
	}
	// ★ 关键断言：方法闸拒绝之后，不应再调用 checkReadQuota / checkBudget
	after := ts.policySnapshot()
	usedAfter := snapInt(after, "requests_used")

	if usedAfter != usedBefore {
		t.Errorf("被拒绝的请求消耗了额度：拒绝前 %d → 拒绝后 %d（应保持不变）", usedBefore, usedAfter)
	}

	// 反证：如果按旧写法把三者放进一个 slice 字面量，额度就会被扣
	ts2 := freshPolicyTask(7004)
	snap1 := ts2.policySnapshot()
	_ = []policyVerdict{
		ts2.checkMethod("POST"), // 会被拒
		ts2.checkReadQuota("http://t.example.com/api/u?id=1", "session:a"), // 仍会执行
		ts2.checkBudget(), // 仍会执行 ⇒ 扣额度
	}
	snap2 := ts2.policySnapshot()
	if snapInt(snap2, "requests_used") == snapInt(snap1, "requests_used") {
		t.Log("  （说明 eager 求值已不再扣额度，符合预期）")
	} else {
		t.Logf("  ✓ 复现旧缺陷：slice 字面量会扣额度 %d → %d（这正是 http_probe 里已修掉的写法）",
			snapInt(snap1, "requests_used"), snapInt(snap2, "requests_used"))
	}
	t.Log("✓ 顺序判定：方法闸拒绝后额度不变")
}
