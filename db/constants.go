package db

// Exploration node kinds (exploration_nodes.kind).
const (
	KindBegin   = "begin"   // DEPRECATED: legacy task root; new tasks seed an origin fact (KindFact + StateOrigin) instead
	KindGoal    = "goal"    // a task objective
	KindIntent  = "intent"  // an exploration direction (planner-generated)
	KindFact    = "fact"    // a worker's exploration result/conclusion (incl. negative results), tied to its intent
	KindFinding = "finding" // a confirmed vulnerability (report_finding), distinct from a fact
	KindHint    = "hint"
	KindDigest  = "digest" // a compressed fold of cold intents/facts (cold-digest-spec §1); lossless — members kept, restorable by id
	KindThread  = "thread" // 战线：一条主攻方向。★ 同一时刻只允许一条 active；意图必须挂在它下面
)

// Thread states (kind='thread').
//
// ★ 设计动机（2026-10-17）：planner 原本每次唤醒都从全局问"还有什么新方向"，
// 没有任何结构约束"当前主攻哪条线、挖完没有" ⇒ 必然铺开而不深入
// （实测 21 分钟派 22 条意图，每条都浅）。
// 引入 thread 后，"挖完才换"由代码保证：
//
//	· 有 active thread 时，add_intent 必须带 thread_id，否则拒绝
//	· active thread 被 close 后，才允许 open 下一条
const (
	StateThreadActive    = "active"    // 当前主攻
	StateThreadDone      = "done"      // 已达 done_when，挖透
	StateThreadParked    = "parked"    // 暂时挂起（等外部依赖，如等某个前置产出）
	StateThreadAbandoned = "abandoned" // 放弃（必须写 abandon_reason）
)

// ThreadPayload 是 kind='thread' 节点的 payload 结构。
// 用 map 写库、用这个结构读回，字段名保持一致。
type ThreadPayload struct {
	Summary        string `json:"summary"`         // 这条战线是什么（一句话）
	Entry          string `json:"entry,omitempty"` // 入口：资产/接口/主机（尽量具体，便于 worker 落地）
	DoneWhen       string `json:"done_when"`       // ★ 什么算这条线挖透 —— 必须是可判定的条件
	ParkedReason   string `json:"parked_reason,omitempty"`
	AbandonReason  string `json:"abandon_reason,omitempty"`
	OpenedRound    int64  `json:"opened_round,omitempty"` // 开线时的 planner 轮次
	ClosedRound    int64  `json:"closed_round,omitempty"` // 收线时的轮次
	LastStatsRound int64  `json:"last_stats_round,omitempty"`
	LastStatsHash  string `json:"last_stats_hash,omitempty"` // 上次快照的指纹，用于判定"空转"
	StaleStrikes   int    `json:"stale_strikes,omitempty"`   // 连续多少次唤醒 stats 没变化
}

// Digest node states (kind='digest'). A digest is 'active' while it renders in
// graph_overview; major compaction retires a merged-away segment to 'superseded'
// (its covers edges repointed to the new digest) — cold-digest-spec §5.1.
const (
	StateDigestActive     = "active"
	StateDigestSuperseded = "superseded"
)

// StateOrigin marks the task root fact (KindFact) seeded at task creation — the
// exploration graph's origin. Every intent traces back to it, so "an intent must
// connect to a fact" holds uniformly from the very first intent. Worker-produced
// facts use state 'confirmed', so this never collides.
const StateOrigin = "origin"

// StateIntentDeleted marks an intent the user假删除(soft delete): it drops out of
// the frontier and graph_overview like other terminal states, but keeps its node
// and full lineage. The delete reason lives in exploration_nodes.delete_reason.
const StateIntentDeleted = "deleted"

// Exploration edge relations (exploration_edges.rel).
const (
	RelSpawns      = "spawns"
	RelDerivedFrom = "derived_from"
	RelYields      = "yields"
	RelProves      = "proves"
	RelCovers      = "covers" // digest --covers--> member (cold-digest-spec §1); source of truth for "which digest folds node X"
)
