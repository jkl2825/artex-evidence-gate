package agent

// predicate_capfix_test.go —— 2026-10-17 能力审计：伪证据修复的集成测试
//
// 钉住两件事：
//   ① 观察里声明的对照【实际不存在】时，session.valid / object.exists 必须判 false
//      （否则"对照不存在"会被零值 CompareSame=false 误读成"两条响应可区分" ⇒ 假 true）
//   ② 该判定不依赖 CompareInvalid 字段 —— 历史 observation 没有这个字段，
//      只信字段的话旧数据仍会被误判。必须实际查一次。
//
// 需要 PostgreSQL；不可用时 Skip（不 Pretend 通过）。

import (
	"testing"
)

// newCapfixStore 建一个临时 exploration，返回 store 与清理函数。
func newCapfixStore(t *testing.T) (*ToolSet, func()) {
	t.Helper()
	d := testDB(t)

	expID, err := d.CreateExploration("capfix-test", "验证无效对照被拒")
	if err != nil {
		t.Skipf("CreateExploration unavailable: %v", err)
	}
	ts := NewToolSet(d.Exploration(expID), "capfix")
	ts.SetTaskID(0) // 不绑任务：避免 semanticCheck 的 source_task_id 校验干扰

	cleanup := func() {
		// 注意：exploration_nodes 对 explorations 没有外键级联，必须手动按序删
		_, _ = d.Exec(`DELETE FROM exploration_nodes WHERE exploration_id=$1`, expID)
		_, _ = d.Exec(`DELETE FROM activity WHERE exploration_id=$1`, expID)
		_, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
		d.Close()
	}
	return ts, cleanup
}

// addObs 直接往探索图里写一条 observation，返回节点 id。
func addObs(t *testing.T, ts *ToolSet, pl observationPayload) int64 {
	t.Helper()
	id, err := ts.ts.AddNode(kindObservation, mustMap(pl), 0, "confirmed", "capfix", nil)
	if err != nil {
		t.Fatalf("AddNode observation: %v", err)
	}
	return id
}

// ── ① 对照不存在 → session.valid 必须判 false ─────────────────────────────

func TestSemanticCheckSessionValidRejectsMissingCompare(t *testing.T) {
	ts, cleanup := newCapfixStore(t)
	defer cleanup()

	// 故意不写 CompareInvalid（模拟历史数据：该字段当时还不存在）
	obsID := addObs(t, ts, observationPayload{
		Channel: "http", ActualURL: "http://t.example.com/me",
		Actor:       "session:alice", // 非匿名，骗过第一道检查
		CompareWith: 999999999,       // ★ 指向不存在的 observation
		RespStatus:  200, RespLen: 10, RespSHA256: "deadbeef",
	})

	res, why := ts.semanticCheck(obsID, "session.valid", expContext{})
	if res != "false" {
		t.Errorf("对照不存在时必须判 false，实际 result=%s\nreason=%s", res, why)
	} else {
		t.Logf("✓ 无效对照被判 false：%s", why)
	}
}

// ── ② 对照不存在 → object.exists 必须判 false ────────────────────────────

func TestSemanticCheckObjectExistsRejectsMissingCompare(t *testing.T) {
	ts, cleanup := newCapfixStore(t)
	defer cleanup()

	obsID := addObs(t, ts, observationPayload{
		Channel: "http", ActualURL: "http://t.example.com/api/item?id=1",
		Actor:       "session:alice",
		Object:      "item:1",  // 声明了对象，骗过第一道检查
		CompareWith: 888888888, // ★ 不存在
		RespStatus:  404, RespLen: 25, RespSHA256: "cafebabe",
	})

	res, why := ts.semanticCheck(obsID, "object.exists", expContext{})
	if res != "false" {
		t.Errorf("对照不存在时必须判 false，实际 result=%s\nreason=%s", res, why)
	} else {
		t.Logf("✓ 无效对照被判 false：%s", why)
	}
}

// ── ③ 对照真实存在且可区分 → 仍然要通过（不能把功能修坏）──────────────────

func TestSemanticCheckSessionValidAcceptsRealCompare(t *testing.T) {
	ts, cleanup := newCapfixStore(t)
	defer cleanup()

	// 先造一条匿名基线
	anonID := addObs(t, ts, observationPayload{
		Channel: "http", ActualURL: "http://t.example.com/me",
		Actor:      "anonymous",
		RespStatus: 302, RespLen: 0, RespSHA256: "anon-hash",
	})
	// 再造一条带身份的、且与基线可区分
	authID := addObs(t, ts, observationPayload{
		Channel: "http", ActualURL: "http://t.example.com/me",
		Actor:       "session:alice",
		CompareWith: anonID, // ★ 真实存在
		CompareSame: false,  // 状态码/哈希不同 ⇒ 可区分
		RespStatus:  200, RespLen: 42, RespSHA256: "auth-hash",
	})

	res, why := ts.semanticCheck(authID, "session.valid", expContext{})
	if res != "true" {
		t.Errorf("真实且可区分的对照应判 true，实际 result=%s\nreason=%s", res, why)
	} else {
		t.Logf("✓ 有效对照仍判 true：%s", why)
	}
}
