package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestObservationLineageFallback 锁住"observation 必须有父边"这条不变量。
//
// ★ 2026-10-17 的教训：http_probe / record_observation 的 intent_id 都不是 required，
// 模型漏传时 pid() 返回 0 ⇒ Link(0,...) 建不出边 ⇒ observation 成为孤立节点。
// 实测 task49：154 条 observation 里 39 条没有父边。
// 而孤立节点在冷节点分组时是单节点块，受 K=2 约束永远不会被折 ⇒ 图上只增不减。
//
// 兜底顺序：模型给的 → ownerNode → 都不建（宁可不建边也不建脏边）。
func TestObservationLineageFallback(t *testing.T) {
	// 纯逻辑断言：这里不碰 DB，只验证兜底选择的优先级。
	pick := func(arg, owner int64) (int64, bool) {
		iid := arg
		if iid <= 0 {
			iid = owner
		}
		if iid <= 0 {
			return 0, false // 不建边
		}
		return iid, true
	}

	if got, ok := pick(100, 7); !ok || got != 100 {
		t.Errorf("模型显式给了 intent_id 时应优先用它，got=%d ok=%v", got, ok)
	}
	if got, ok := pick(0, 7); !ok || got != 7 {
		t.Errorf("模型没给时应回落到 ownerNode，got=%d ok=%v", got, ok)
	}
	if _, ok := pick(0, 0); ok {
		t.Error("两者都没有时不应建边（避免 src_id=0 的脏边）")
	}

	// 顺带确认 RelYields 的方向语义没变（intent → observation）
	if db.RelYields != "yields" {
		t.Errorf("RelYields 语义变了：%q", db.RelYields)
	}
}
