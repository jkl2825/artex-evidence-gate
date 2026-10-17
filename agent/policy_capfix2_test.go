package agent

// policy_capfix2_test.go —— 2026-10-17 第二轮：修掉我自己引入的配额绕过
//
// 背景：第一轮修"注入载荷不该占读取配额"时，判定写成
//   if !looksLikeObjectValue(v) { allObjectLike = false }
// 对【空值】也判 false ⇒ `?id=6&unused=` 会让整个请求跳过配额。
// 审计方（efc2bd5d）指出：模型只要在 URL 尾巴挂一个空参数就能无限遍历。
//
// 本文件钉住修复后的语义：
//   空值参数忽略（既不算载荷也不算对象）
//   有任一非空值带载荷特征 ⇒ 注入测试，不计配额
//   否则至少一个对象值 ⇒ 计配额

import (
	"strconv"
	"testing"
)

// 空参数不得让整个请求豁免
func TestReadQuotaNotBypassedByEmptyParam(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")
	ts := freshPolicyTask(7101)
	const actor = "session:alice"

	// 前 5 组正常放行
	for i := 1; i <= 5; i++ {
		u := "http://t.example.com/api/user?id=" + strconv.Itoa(i) + "&unused="
		if v := ts.checkReadQuota(u, actor); !v.Allowed {
			t.Fatalf("前 %d 组应放行（空参数不该拦正常请求），实际被拒：%s", i, v.Reason)
		}
	}
	// 第 6 组必须被拦 —— 空参数不能豁免
	v := ts.checkReadQuota("http://t.example.com/api/user?id=6&unused=", actor)
	if v.Allowed {
		t.Error("★ 绕过仍存在：?id=6&unused= 让第 6 组逃过 read_quota")
	} else {
		t.Logf("✓ 空参数不再豁免：第 6 组被拦（rule=%s）", v.Rule)
	}
}

// 多种空/噪声参数的组合都不得豁免
func TestReadQuotaBypassVariants(t *testing.T) {
	variants := []string{
		"http://t.example.com/api/user?id=%d&unused=",
		"http://t.example.com/api/user?id=%d&",
		"http://t.example.com/api/user?id=%d&_=",
		"http://t.example.com/api/user?id=%d&t=",
	}
	for _, tpl := range variants {
		t.Setenv("ARTEX_POLICY_MAX_READS", "5")
		// 每次用不同的 taskID，避免状态串味
		ts := freshPolicyTask(7200 + int64(len(tpl))*10 + int64(tpl[0]%7))
		const actor = "session:bob"
		for i := 1; i <= 5; i++ {
			_ = ts.checkReadQuota(sprintfURL(tpl, i), actor)
		}
		if v := ts.checkReadQuota(sprintfURL(tpl, 6), actor); v.Allowed {
			t.Errorf("★ 变体绕过：%s 让第 6 组逃过配额", tpl)
		} else {
			t.Logf("✓ %s 未绕过", tpl)
		}
	}
}

// 真正的载荷仍然不占配额（不能因为修绕过又把功能修坏）
func TestInjectionStillExemptAfterFix(t *testing.T) {
	t.Setenv("ARTEX_POLICY_MAX_READS", "5")
	ts := freshPolicyTask(7301)
	const actor = "session:carol"

	payloads := []string{
		"http://t.example.com/api/health?id=1'",
		"http://t.example.com/api/health?id=1' OR '1'='1",
		"http://t.example.com/api/health?id=<script>",
		"http://t.example.com/api/health?id=1;id&x=1",
	}
	for i, u := range payloads {
		if v := ts.checkReadQuota(u, actor); !v.Allowed {
			t.Errorf("第 %d 个载荷 %q 被误拦：%s", i+1, u, v.Reason)
		}
	}
	t.Logf("✓ %d 个真载荷仍豁免", len(payloads))
}

// sprintfURL 内部小工具（避免引入 fmt 依赖歧义）
func sprintfURL(tpl string, n int) string {
	out := make([]byte, 0, len(tpl)+2)
	for i := 0; i < len(tpl); i++ {
		if i+1 < len(tpl) && tpl[i] == '%' && tpl[i+1] == 'd' {
			out = append(out, []byte(strconv.Itoa(n))...)
			i++
			continue
		}
		out = append(out, tpl[i])
	}
	return string(out)
}

// 第三版：非空载荷形状的"诱饵参数"不得豁免真实遍历
func TestReadQuotaBypassByNonEmptyDummy(t *testing.T) {
	cases := []struct {
		name string
		tpl  string
	}{
		{"空值诱饵", "http://t.example.com/api/u?id=%d&unused="},
		{"单引号诱饵", "http://t.example.com/api/u?id=%d&unused=%27"},
		{"超长诱饵", "http://t.example.com/api/u?id=%d&unused=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"尖括号诱饵", "http://t.example.com/api/u?id=%d&junk=%3Cscript%3E"},
		{"分号诱饵", "http://t.example.com/api/u?id=%d&junk=%3Bid"},
	}
	for _, c := range cases {
		t.Setenv("ARTEX_POLICY_MAX_READS", "5")
		ts := freshPolicyTask(7400 + int64(len(c.name)))
		const actor = "session:zed"
		for i := 1; i <= 5; i++ {
			_ = ts.checkReadQuota(sprintfURL(c.tpl, i), actor)
		}
		if v := ts.checkReadQuota(sprintfURL(c.tpl, 6), actor); v.Allowed {
			t.Errorf("★ %s 仍能豁免：第 6 组逃过 read_quota", c.name)
		} else {
			t.Logf("✓ %s 不豁免（rule=%s）", c.name, v.Rule)
		}
	}
}
