package db

import (
	"encoding/json"
	"fmt"
)

// ---------------------------------------------------------------------------
// thread（战线）：一条主攻方向
//
// ★ 2026-10-17 引入。动机：planner 原本每次唤醒都从全局问"还有什么新方向"，
// 没有任何结构约束"当前主攻哪条线、挖完没有" ⇒ 必然铺开而不深入
// （实测 21 分钟派 22 条意图，每条都浅）。
//
// 约束（由代码保证，不靠提示词自觉）：
//   · 同一时刻只允许一条 state='active' 的 thread
//   · 有 active thread 时，add_intent 必须带 thread_id
//   · active thread close 后，才允许 open 下一条
//
// 关系：
//
//	thread --spawns--> intent --yields--> observation / fact / finding
// ---------------------------------------------------------------------------

// ThreadStats 是一条战线的自动度量。
//
// ★ 为什么要自动算：让 planner 有客观依据判断"在推进还是空转"，
// 而不是凭感觉。StatsHash 变化即视为有实质进展。
type ThreadStats struct {
	ThreadID     int64 `json:"thread_id"`
	Intents      int   `json:"intents"`          // 该线下派了多少意图
	Terminal     int   `json:"intents_terminal"` // 其中已终态（done/blocked/exhausted/stopped/deleted）
	Open         int   `json:"intents_open"`     // 其中 open/running/paused
	Observations int   `json:"observations"`     // 这些意图产出的结构化观察
	Facts        int   `json:"facts"`
	Findings     int   `json:"findings"`
	// Hash 是 (Intents,Observations,Facts,Findings) 的指纹。
	// 连续多次唤醒 Hash 不变 ⇒ 空转（在重复劳动，没有新信息）。
	Hash string `json:"hash"`
}

// ThreadView 是带状态和统计的战线视图（给 planner/UI 用）。
type ThreadView struct {
	ID      int64         `json:"id"`
	State   string        `json:"state"`
	Payload ThreadPayload `json:"payload"`
	Stats   ThreadStats   `json:"stats"`
}

// CreateThread 建一条战线。payload 里必须有 summary + done_when。
//
// 不在这里校验"是否已有 active"——那是上层（工具层）的职责，因为它要给出
// 更具体的错误信息（现在 active 是哪条）。
func (s *ExplorationStore) CreateThread(payload map[string]any) (int64, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	if _, ok := payload["summary"]; !ok {
		return 0, fmt.Errorf("thread 必须有 summary")
	}
	if _, ok := payload["done_when"]; !ok {
		return 0, fmt.Errorf("thread 必须有 done_when（什么算这条线挖透），否则无法判定收线")
	}
	return s.AddNode(KindThread, payload, 0, StateThreadActive, "planner", nil)
}

// ActiveThread 返回当前 active 的那条战线；没有则 (nil, nil)。
//
// 如果因为历史数据出现多条 active，取最新的一条并返回 warning——
// 不静默挑一条就算了，上层要能把这个异常暴露出来。
func (s *ExplorationStore) ActiveThread() (*Node, error) {
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2 AND state=$3 ORDER BY id DESC LIMIT 2`,
		s.expID, KindThread, StateThreadActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	return nodes[0], nil
}

// ListThreads 列本任务的战线（最新在前），可选按状态过滤（state 为空 = 全部）。
func (s *ExplorationStore) ListThreads(state string, limit int) ([]*Node, error) {
	if limit <= 0 {
		limit = 50
	}
	if state == "" {
		return s.ListByKind(KindThread, limit)
	}
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes
WHERE exploration_id=$1 AND kind=$2 AND state=$3 ORDER BY id DESC LIMIT $4`,
		s.expID, KindThread, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// ThreadStatsOf 算一条战线的自动度量。
//
// 只统计**挂在这条线下**的意图及其产出——thread 之外的意图（历史遗留、
// 或旧数据没有 thread 归属的）不计入，否则统计会失真。
func (s *ExplorationStore) ThreadStatsOf(threadID int64) (*ThreadStats, error) {
	st := &ThreadStats{ThreadID: threadID}

	// 意图：thread --spawns--> intent
	if err := s.db.QueryRow(`
SELECT count(*),
       count(*) FILTER (WHERE n.state IN ('done','blocked','exhausted','stopped','deleted')),
       count(*) FILTER (WHERE n.state IN ('open','running','paused'))
FROM exploration_edges e
JOIN exploration_nodes n ON n.id = e.dst_id
WHERE e.exploration_id=$1 AND e.src_id=$2 AND e.rel=$3 AND n.kind=$4`,
		s.expID, threadID, RelSpawns, KindIntent).Scan(&st.Intents, &st.Terminal, &st.Open); err != nil {
		return nil, err
	}

	// 产出：intent --yields--> observation / fact / finding
	// 一次扫完，按 kind 分组
	rows, err := s.db.Query(`
SELECT out.kind, count(*)
FROM exploration_edges e1
JOIN exploration_edges e2 ON e2.exploration_id = e1.exploration_id AND e2.src_id = e1.dst_id AND e2.rel = $4
JOIN exploration_nodes out ON out.id = e2.dst_id
WHERE e1.exploration_id=$1 AND e1.src_id=$2 AND e1.rel=$3
GROUP BY out.kind`, s.expID, threadID, RelSpawns, RelYields)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		switch kind {
		case "observation":
			st.Observations = n
		case KindFact:
			st.Facts = n
		case KindFinding:
			st.Findings = n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	st.Hash = fmt.Sprintf("i%d-t%d-o%d-f%d-v%d", st.Intents, st.Terminal, st.Observations, st.Facts, st.Findings)
	return st, nil
}

// ThreadViewOf 取一条战线的完整视图（状态 + payload + 统计）。
func (s *ExplorationStore) ThreadViewOf(id int64) (*ThreadView, error) {
	n, err := s.GetNode(id)
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != KindThread {
		return nil, fmt.Errorf("节点 %d 不是 thread", id)
	}
	var p ThreadPayload
	_ = json.Unmarshal(n.Payload, &p)
	st, err := s.ThreadStatsOf(id)
	if err != nil {
		return nil, err
	}
	return &ThreadView{ID: n.ID, State: n.State, Payload: p, Stats: *st}, nil
}

// SetThreadState 切一条战线的状态；收线原因写进 payload。
//
// state 只能是 thread 的四个合法值（DB 有 CHECK 兜底，这里先给出可读错误）。
func (s *ExplorationStore) SetThreadState(id int64, state, reason string) error {
	switch state {
	case StateThreadActive, StateThreadDone, StateThreadParked, StateThreadAbandoned:
	default:
		return fmt.Errorf("非法的 thread 状态 %q（只允许 active/done/parked/abandoned）", state)
	}
	// 原因写进 payload（保留原有字段）
	n, err := s.GetNode(id)
	if err != nil {
		return err
	}
	if n == nil || n.Kind != KindThread {
		return fmt.Errorf("节点 %d 不是 thread", id)
	}
	var p map[string]any
	if err := json.Unmarshal(n.Payload, &p); err != nil || p == nil {
		p = map[string]any{}
	}
	if reason != "" {
		switch state {
		case StateThreadParked:
			p["parked_reason"] = reason
		case StateThreadAbandoned:
			p["abandon_reason"] = reason
		}
	}
	raw, _ := json.Marshal(p)
	if _, err := s.db.Exec(`UPDATE exploration_nodes SET payload=$1, updated_at=now() WHERE id=$2`, string(raw), id); err != nil {
		return err
	}
	return s.SetNodeState(id, state)
}

// ThreadIntents 列一条战线下的意图（最新在前）。
func (s *ExplorationStore) ThreadIntents(threadID int64, limit int) ([]*Node, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM exploration_nodes n
JOIN exploration_edges e ON e.dst_id = n.id
WHERE e.exploration_id=$1 AND e.src_id=$2 AND e.rel=$3 AND n.kind=$4
ORDER BY n.id DESC LIMIT $5`, s.expID, threadID, RelSpawns, KindIntent, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}
