package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestFoldableKind 锁住"哪些节点可以进冷折叠"这条边界。
//
// ★ 2026-10-17 的教训：本 fork 加了 http_probe，每次探测写一条 observation。
// 而原版 foldableKind 只认 intent/fact ⇒ observation 只增不减，
// 60 分钟堆到 373 条，探索链路图被淹没（466 节点里 80% 是它，digest 从未触发）。
// 修完必须保证：
//
//	① 记录型节点（observation/validity_audit/validity_gate/baseline）可折
//	② 结论型节点（intent/fact）保持可折
//	③ 绝不能折：finding/goal/hint/begin/digest（以及本 fork 的 thread）
func TestFoldableKind(t *testing.T) {
	yes := []string{
		db.KindIntent, db.KindFact,
		kindObservation, kindValidityAudit, kindValidityGate, kindBaseline,
	}
	for _, k := range yes {
		if !foldableKind(k) {
			t.Errorf("foldableKind(%q) = false，应为 true（否则这类节点只增不减，会淹没探索链路图）", k)
		}
	}

	no := []string{
		db.KindFinding, // 真漏洞，必须一直在图上
		db.KindGoal,    // 目标
		db.KindHint,    // 战略提示
		db.KindBegin,   // 图根
		db.KindDigest,  // 已折叠块自身，不能二次折
		db.KindThread,  // ★ 本 fork 的战线：当前主线必须一直可见
	}
	for _, k := range no {
		if foldableKind(k) {
			t.Errorf("foldableKind(%q) = true，绝不能折（折了会在图上消失）", k)
		}
	}
}

// TestHotSetKeepsLiveIntentChildren 验证：活意图的直接子节点必须保持热。
//
// 这是 observation 折叠的正确性前提 —— 活意图的观察不能被折走，
// 否则正在干活时 planner/worker 会看不到刚拿到的证据。
func TestHotSetKeepsLiveIntentChildren(t *testing.T) {
	g := &coldGraph{
		nodes: map[int64]cgNode{
			1: {ID: 1, Kind: db.KindIntent, State: "running"}, // 活意图
			2: {ID: 2, Kind: kindObservation, State: "confirmed"},
			3: {ID: 3, Kind: db.KindIntent, State: "done"}, // 已收意图
			4: {ID: 4, Kind: kindObservation, State: "confirmed"},
		},
		parents:  map[int64][]int64{2: {1}, 4: {3}},
		children: map[int64][]int64{1: {2}, 3: {4}},
	}
	hot := g.hotSet()

	if !hot[1] {
		t.Error("活意图 #1 应为热")
	}
	if !hot[2] {
		t.Error("活意图 #1 的直接子节点（observation #2）应为热 —— 否则干活时看不到刚拿到的证据")
	}
	if hot[3] {
		t.Error("已收意图 #3 不应为热")
	}
	if hot[4] {
		t.Error("已收意图 #3 的子节点（observation #4）不应为热 —— 这正是要被折叠的")
	}
}
