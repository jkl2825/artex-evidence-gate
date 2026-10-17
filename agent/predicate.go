package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ════════════════════════════════════════════════════════════════════════════
// 机器谓词（validity predicates）—— 上游 docs/创新路线/R05「测试有效性与鉴别实验」的落地
//
// 版本：V3（2026-10-16）—— 在 V2 的写回门之上，接入【公共基线】：
//   ① register_baseline：把「已验过的对照」登记为带有效期与上下文绑定的基线记录
//   ② audit_validity 的 checks 可以用 baseline_id 代替 evidence_ref —— 复用而不必重复诊断
//   ③ 程序在采纳基线前检查【存在 / 未过期 / 上下文相容】；过期或不相容 ⇒ 该层判 false
//   ⇒ 对应上游：「R02 的 owner 对照、R03 的正常业务流程和 R05 的会话健康共用基线存储、
//      引用、复查和失效机制，各自保留用途及判定器」「同一上下文编号不能无限延长有效性」
//
// 【版本能力边界，照实写，不夸大】
//   校验：谓词已注册 / 证据引用真实存在且含观察内容 / 必需层齐备 /
//         基线存在且未过期且上下文相容
//   不校验：那条观察【是否真的支撑】该断言 —— 需要结构化执行器产出的观察明细，属后续版本
//   ⇒ 给的是【准入资格】，不是【结论正确性】
// ════════════════════════════════════════════════════════════════════════════

const (
	kindValidityAudit = "validity_audit" // audit_validity 的一次判定
	kindValidityGate  = "validity_gate"  // 写回门的决策日志（上游要求的「门决策日志」）
	kindBaseline      = "baseline"       // ★ V3：公共基线记录（带有效期与上下文绑定）
)

// PredicateSpec 是一个已注册机器谓词的契约。
type PredicateSpec struct {
	Name        string
	Version     int
	Layer       string
	AppliesWhen string
	Requires    string
	Enforced    bool
}

// BuiltinPredicates 是注册表。五层对应上游共用协议的「有效性检查的分层」表。
var BuiltinPredicates = []PredicateSpec{
	{Name: "transport.reachable", Version: 1, Layer: "传输",
		AppliesWhen: "任何实验（总是适用）", Requires: "一条真实到达目标的请求/响应观察引用", Enforced: true},
	{Name: "session.valid", Version: 1, Layer: "身份",
		AppliesWhen: "实验声明需要登录态时（need_auth=true）",
		Requires: "一条用【已知需要该身份、语义明确的最小操作】取得的成功观察引用。" +
			"公共健康页返回 200 不算（登录页伪装成 200 也不能证明身份有效）", Enforced: true},
	{Name: "object.exists", Version: 1, Layer: "业务基线",
		AppliesWhen: "结论针对某个具体对象（记录/文件/订单…）时（about_object=true）",
		Requires: "一条用【对象拥有者或另一独立身份】取得的对象存在性对照观察引用。" +
			"对象不存在与无权访问可能同为 404，只凭单一 404 不能归因", Enforced: true},
	{Name: "observation.available", Version: 1, Layer: "观察能力",
		AppliesWhen: "任何要判「没发现」的实验",
		Requires: "一条证明本实验要验证的效果【可被当前上下文观察到】的对照观察引用。" +
			"没有可见回显 ≠ 没有效果", Enforced: true},
	{Name: "out_of_scope", Version: 1, Layer: "授权范围",
		AppliesWhen: "任何实验（总是适用，且是前置条件）",
		Requires: "一条指向【授权范围内目标】的结构化观察引用。" +
			"目标落在绝对禁止段（云元数据 169.254/16、回环 127/8、链路本地、组播、保留段）时" +
			"无论 scope 怎么写都不放行；私有网段需在 task_scope 中显式声明。" +
			"★ 这一层判的是「你引用的证据，其目标在不在授权边界内」—— 超范围目标的观察不能支撑任何结论",
		Enforced: true},
	{Name: "method.applicable", Version: 1, Layer: "方法适用性",
		AppliesWhen: "想让判定更完整时（可选）",
		Requires: "方法与本目标条件相容的依据。" +
			"注意：黑盒响应不能普遍证明到达了特定代码分支，故本层【只报不拦】", Enforced: false},
}

func predicateByName(name string) *PredicateSpec {
	for i := range BuiltinPredicates {
		if BuiltinPredicates[i].Name == name {
			return &BuiltinPredicates[i]
		}
	}
	return nil
}

// negativeKeywords 是否定性结论的中文关键词兜底。worker 未显式声明 conclusion 时，
// 程序仍能识别出「这条在断言某物不存在」，从而要求显式分类。
var negativeKeywords = []string{
	"未发现", "未找到", "未命中", "未暴露", "未复现", "未能",
	"不存在", "不可注入", "无法注入", "不可利用", "无法利用",
	"无漏洞", "不是漏洞", "并非漏洞", "没有漏洞",
	"无回显", "无法区分", "无法判定", "不可达", "关闭", "收敛",
}

func looksNegative(text string) (bool, string) {
	for _, k := range negativeKeywords {
		if strings.Contains(text, k) {
			return true, k
		}
	}
	return false, ""
}

// validityClaim 是模型声明的一条「本层我验过了」。
// V3：evidence_ref 与 baseline_id 二选一 —— 前者是本次观察，后者是复用的公共基线。
type validityClaim struct {
	Predicate   string `json:"predicate"`
	EvidenceRef int64  `json:"evidence_ref"`
	BaselineID  int64  `json:"baseline_id"` // ★ V3：复用已登记的基线（程序会查有效期与上下文相容）
	Note        string `json:"note"`
}

// expContext 是本次实验的上下文，用于判定基线能否复用。
// 上游：「缓存不能跨主体、租户和不相容状态复用，也不能因为短时间内请求相似就认定同样有效。」
type expContext struct {
	Target  string `json:"target"`
	Actor   string `json:"actor"`
	Object  string `json:"object"`
	Purpose string `json:"purpose"`
}

type layerResult struct {
	Layer       string `json:"layer"`
	Predicate   string `json:"predicate"`
	Version     int    `json:"predicate_version"`
	Result      string `json:"result"`
	Reason      string `json:"reason"`
	EvidenceRef int64  `json:"evidence_ref,omitempty"`
	BaselineRef int64  `json:"baseline_ref,omitempty"`
	ViaBaseline bool   `json:"via_baseline,omitempty"`
	Enforced    bool   `json:"enforced"`
}

// ════════════════════════════════════════════════════════════════════════════
// V4：语义谓词 —— 对【结构化观察】做可判检查
//
// V1–V3 只能校验「引用是否存在 / 证据节点是否存在」。V4 起改为：
// 必需层必须由【执行器记录的 observation 节点】支撑，并且程序按谓词语义检查
// 「这条观察本身能不能支撑该断言」——而不是只看引用非空。
//
// 依据（上游共用实验协议）：
//   「观察明细由受支持执行器先保存……模型随后生成摘要，不能成为这些字段的唯一来源。」
//   「模型填写的 observed、角色标签或评分不构成程序背书。」
//
// 各谓词的语义判据（全部由程序从 observation 的结构化字段判定）：
//   transport.reachable ← 有一条拿到响应的观察（resp_status>0）
//   session.valid       ← 主体非匿名 且 有对照 且 与对照【可区分】
//                          （带凭据与不带凭据响应一致 ⇒ 凭据没改变判定 ⇒ 不成立）
//   object.exists       ← 声明了对象 且 有对照（不同对象引用）且 可区分
//                          （上游：「对象不存在与无权访问可能同为 404，只凭单一响应不能归因」）
//   observation.available ← 响应有可观察内容（body 或 header 非空）
//   method.applicable   ← 不可由单条观察判定 ⇒ 恒为 unknown（只报不拦）
// ════════════════════════════════════════════════════════════════════════════

func isAnonymousActor(a string) bool {
	s := strings.ToLower(strings.TrimSpace(a))
	return s == "" || s == "anonymous" || s == "anon" || s == "guest" || s == "none" ||
		strings.HasPrefix(s, "anonymous") || strings.HasPrefix(s, "anon:")
}

// semanticCheck 是 V4 的语义检查：证据必须是结构化观察，且满足该谓词的判据。
// 返回 result(true/false/unknown) 与 reason。
func (t *ToolSet) semanticCheck(evID int64, predicate string, cx expContext) (string, string) {
	if evID <= 0 {
		return "false", "未提供 evidence_ref"
	}
	n, err := t.ts.GetNodeWithSources(evID)
	if err != nil {
		return "false", fmt.Sprintf("查询节点 %d 失败：%v", evID, err)
	}
	if n == nil {
		return "false", fmt.Sprintf("引用节点 %d 不存在于本任务探索图 —— 证据引用必须是真实写回过的节点 id，"+
			"不能凭空写一个编号（这就是「模型自称已验证」被拦下的地方）", evID)
	}
	if n.SourceTaskID != 0 && t.taskID != 0 && n.SourceTaskID != t.taskID {
		return "false", fmt.Sprintf("节点 %d 属于其它任务（source_task_id=%d），不能作为本任务实验的证据", evID, n.SourceTaskID)
	}
	if n.Kind != kindObservation {
		return "false", fmt.Sprintf("证据 %d 是 %q 节点，不是【结构化观察】。按 R05 的要求，必需层必须由"+
			"执行器记录的结构化观察（http_probe）支撑 —— 模型自己写的 fact 只能作为摘要，"+
			"不能成为「会话有效 / 对象存在」这类断言的依据。请用 http_probe 重做该对照，"+
			"它会把请求、响应、上下文、时间、渠道一并落盘。", evID, n.Kind)
	}
	var o observationPayload
	if err := json.Unmarshal(n.Payload, &o); err != nil {
		return "false", fmt.Sprintf("观察 %d 的 payload 无法解析：%v", evID, err)
	}

	switch predicate {
	case "transport.reachable":
		if o.RespStatus == 0 {
			return "false", fmt.Sprintf("观察 %d 没有拿到任何响应（传输层失败）—— 传输不可达", evID)
		}
		return "true", fmt.Sprintf("观察 %d：%s %s → HTTP %d（%dms）—— 传输层确实可达",
			evID, o.ReqMethod, o.ActualURL, o.RespStatus, o.ElapsedMS)

	case "session.valid":
		if isAnonymousActor(o.Actor) {
			return "false", fmt.Sprintf("观察 %d 的主体是 %q（匿名）—— 匿名观察无法证明会话有效。"+
				"上游：「健康检查返回 200 不证明登录有效；登录页伪装成 200 也不能证明身份有效」", evID, o.Actor)
		}
		if o.CompareWith <= 0 {
			return "false", fmt.Sprintf("观察 %d 声明主体 %q，但没有对照（compare_with 为空）。"+
				"证明会话有效必须有匿名基线对照：先用 http_probe 发一次 actor=anonymous，再对同一 URL "+
				"带凭据发一次，并在后者填 compare_with=<匿名观察 id>", evID, o.Actor)
		}
		// ★ 对照本身无效时不能算"可区分"。
		// CompareSame 的零值是 false，若不在这里拦住，一个不存在的 compare_with
		// 会被误读成"两条响应不同" ⇒ 给出假的 session.valid。
		if o.CompareInvalid {
			return "false", fmt.Sprintf("观察 %d 指定的对照 %d 不可用（不存在或不是 observation）—— "+
				"本次不构成有效对照，会话有效性无法判定。请确认 compare_with 是真实的 observation 节点 id 后重发",
				evID, o.CompareWith)
		}
		if o.CompareSame {
			return "false", fmt.Sprintf("观察 %d 与对照 %d 【逐字节相同】—— 带凭据与不带凭据的响应完全一致，"+
				"说明该凭据没有改变服务判定，会话有效性不成立", evID, o.CompareWith)
		}
		return "true", fmt.Sprintf("观察 %d：主体 %q 与对照 %d 可区分（%s）—— 凭据确实改变了服务判定，"+
			"会话有效性成立", evID, o.Actor, o.CompareWith, o.CompareNote)

	case "object.exists":
		if strings.TrimSpace(o.Object) == "" {
			return "false", fmt.Sprintf("观察 %d 没有声明对象引用（object 为空）—— 无法判定对象存在性。"+
				"请在 http_probe 的 object 参数里写明你针对的对象（如 item:1）", evID)
		}
		if o.CompareWith <= 0 {
			return "false", fmt.Sprintf("观察 %d 针对对象 %q 但无对照。上游明确："+
				"「对象不存在与无权访问可能同为 404，只凭单一响应不能归因」——"+
				"请再用另一个对象引用（含不存在的）发一次观察并填 compare_with", evID, o.Object)
		}
		// ★ 同 session.valid：对照失效不能被当作"可区分"。
		if o.CompareInvalid {
			return "false", fmt.Sprintf("观察 %d 指定的对照 %d 不可用（不存在或不是 observation）—— "+
				"本次不构成有效对照，对象存在性无法判定。请确认 compare_with 是真实的 observation 节点 id 后重发",
				evID, o.CompareWith)
		}
		if o.CompareSame {
			return "false", fmt.Sprintf("观察 %d 与对照 %d 【逐字节相同】—— 两个不同对象引用得到完全相同的响应，"+
				"无法区分「对象存在」与「对象不存在」，本层不成立", evID, o.CompareWith)
		}
		return "true", fmt.Sprintf("观察 %d：对象 %q 与对照 %d 可区分（%s）—— 对象存在性获得对照支持",
			evID, o.Object, o.CompareWith, o.CompareNote)

	case "observation.available":
		if o.RespLen == 0 && len(o.RespHeaders) == 0 {
			return "false", fmt.Sprintf("观察 %d 的响应既无 body 也无 header —— 无可见内容，"+
				"不能作为「本实验要验证的效果可被观察到」的依据。上游：没有可见回显 ≠ 没有效果", evID)
		}
		return "true", fmt.Sprintf("观察 %d：响应有可观察内容（%d bytes，HTTP %d）—— 观察渠道成立",
			evID, o.RespLen, o.RespStatus)

	case "out_of_scope":
		if strings.TrimSpace(o.ActualURL) == "" && strings.TrimSpace(o.Target) == "" {
			return "false", fmt.Sprintf("观察 %d 没有记录实际目标（actual_url / target 均空）—— "+
				"无法判定授权范围。请用 http_probe 记录该观察，它会落盘实际目标", evID)
		}
		raw := strings.TrimSpace(o.ActualURL)
		if raw == "" {
			raw = strings.TrimSpace(o.Target)
		}
		g := t.loadScopeGuard()
		v := g.checkURL(raw)
		if v.Allowed {
			return "true", fmt.Sprintf("观察 %d：目标 %s 在授权范围内（%s；%s）",
				evID, v.Host, v.Layer, v.Rule)
		}
		return "false", fmt.Sprintf("观察 %d：目标 %s 【超出授权范围】—— %s。%s",
			evID, v.Host, v.Layer, v.Rule)

	case "method.applicable":
		return "unknown", "方法适用性无法由单条观察判定 —— 上游明确「黑盒响应不能普遍证明到达了特定代码分支」，本层只报不拦"
	}
	return "unknown", "未实现的谓词：" + predicate
}

// checkEvidenceRef：程序侧的引用校验（节点真实存在、属于本任务、含观察内容）。
func (t *ToolSet) checkEvidenceRef(id int64) (string, string) {
	if id <= 0 {
		return "false", "未提供 evidence_ref（必填：指向一条真实写回本任务图的观察/事实节点 id）"
	}
	n, err := t.ts.GetNodeWithSources(id)
	if err != nil {
		return "false", fmt.Sprintf("查询节点 %d 失败：%v", id, err)
	}
	if n == nil {
		return "false", fmt.Sprintf("引用节点 %d 不存在于本任务探索图 —— 证据引用必须是真实写回过的节点 id，"+
			"不能凭空写一个编号（这就是「模型自称已验证」被拦下的地方）", id)
	}
	if n.SourceTaskID != 0 && t.taskID != 0 && n.SourceTaskID != t.taskID {
		return "false", fmt.Sprintf("节点 %d 属于其它任务（source_task_id=%d），不能作为本任务实验的证据", id, n.SourceTaskID)
	}
	var pl map[string]any
	_ = json.Unmarshal(n.Payload, &pl)
	ev, _ := pl["evidence"].(string)
	dt, _ := pl["detail"].(string)
	if strings.TrimSpace(ev) == "" && strings.TrimSpace(dt) == "" {
		return "false", fmt.Sprintf("节点 %d（kind=%s）存在，但 payload 里既无 evidence 也无 detail，不能作为观察证据", id, n.Kind)
	}
	return "true", fmt.Sprintf("引用节点 %d（kind=%s）真实存在于本任务图且含观察内容", id, n.Kind)
}

// ── V3：公共基线 ────────────────────────────────────────────────────────────

// baselinePayload 是基线节点的内容。绑定「目标 / 主体 / 对象 / 用途」四元组 + 有效期。
func baselinePayload(kind, target, actor, object, purpose string, evidenceRef int64, ttls int, invalidIf string) map[string]any {
	if ttls <= 0 {
		ttls = 900 // 默认 15 分钟：会话健康这类状态会漂移，不能无限复用
	}
	until := time.Now().Add(time.Duration(ttls) * time.Second).UTC()
	pl := map[string]any{
		"kind": kind, "target": target, "actor": actor, "object": object, "purpose": purpose,
		"evidence_ref":  evidenceRef,
		"ttl_seconds":   ttls,
		"valid_until":   until.Format(time.RFC3339),
		"invalid_if":    invalidIf,
		"predicate_ver": 1,
		"summary": fmt.Sprintf("公共基线[%s] target=%s actor=%s object=%s purpose=%s（有效期至 %s）",
			kind, target, actor, object, purpose, until.Format("15:04:05")),
	}
	return pl
}

// checkBaseline：采纳基线前的三项程序检查 —— 存在 / 未过期 / 上下文相容。
// 上游：「复用前先判上下文是否相容」「同一上下文编号不能无限延长有效性」。
func (t *ToolSet) checkBaseline(id int64, cx expContext) (string, string, int64) {
	if id <= 0 {
		return "false", "未提供 baseline_id", 0
	}
	n, err := t.ts.GetNodeWithSources(id)
	if err != nil || n == nil || n.Kind != kindBaseline {
		return "false", fmt.Sprintf("基线节点 %d 不存在或不是 baseline（kind=%s）", id, func() string {
			if n == nil {
				return "nil"
			}
			return n.Kind
		}()), 0
	}
	var pl map[string]any
	if err := json.Unmarshal(n.Payload, &pl); err != nil {
		return "false", fmt.Sprintf("基线 %d 的 payload 无法解析", id), 0
	}
	// ① 有效期
	if vs, _ := pl["valid_until"].(string); vs != "" {
		if until, e := time.Parse(time.RFC3339, vs); e == nil && time.Now().After(until) {
			return "false", fmt.Sprintf("基线 %d 已过期（valid_until=%s）—— 上游要求「同一上下文编号不能无限延长有效期」，"+
				"请重新做一次对照并更新基线", id, until.Format("15:04:05")), 0
		}
	}
	// ② 上下文相容（目标 / 主体 / 对象 / 用途 四元组）
	got := expContext{
		Target:  strings.TrimSpace(fmt.Sprint(pl["target"])),
		Actor:   strings.TrimSpace(fmt.Sprint(pl["actor"])),
		Object:  strings.TrimSpace(fmt.Sprint(pl["object"])),
		Purpose: strings.TrimSpace(fmt.Sprint(pl["purpose"])),
	}
	mism := []string{}
	if got.Target != cx.Target {
		mism = append(mism, fmt.Sprintf("目标(%s≠%s)", got.Target, cx.Target))
	}
	if got.Actor != cx.Actor {
		mism = append(mism, fmt.Sprintf("主体(%s≠%s)", got.Actor, cx.Actor))
	}
	if got.Object != cx.Object {
		mism = append(mism, fmt.Sprintf("对象(%s≠%s)", got.Object, cx.Object))
	}
	if got.Purpose != cx.Purpose {
		mism = append(mism, fmt.Sprintf("用途(%s≠%s)", got.Purpose, cx.Purpose))
	}
	if len(mism) > 0 {
		return "false", fmt.Sprintf("基线 %d 与本实验上下文不相容：%s —— 上游明确「缓存不能跨主体、租户和不相容状态复用」",
			id, strings.Join(mism, "、")), 0
	}
	evRef := int64(numOr0(pl["evidence_ref"]))
	return "true", fmt.Sprintf("基线 %d 可用（未过期且上下文相容，源自观察 %d）", id, evRef), evRef
}

func numOr0(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	}
	return 0
}

// registerBaseline 把一条已验证的对照登记为公共基线，供同一上下文内的其它实验复用。
func (t *ToolSet) registerBaseline() actool.CoreTool {
	return t.writeExpTool("register_baseline",
		"把一条【已验证的对照】登记为公共基线，让同一上下文内的其它实验复用，避免重复诊断。\n"+
			"对应上游 R05-V3：「多 Worker 复用健康状态，按上下文变化失效」。\n"+
			"典型用途：会话健康（证明当前身份有效）、对象存在性对照（用拥有者证明对象存在）、正常业务流程对照。\n"+
			"★ 基线不是永久的：它绑定【目标/主体/对象/用途】四元组 + 有效期（ttl_seconds，默认 900 秒）。\n"+
			"  过期，或四元组与本实验不符 → 采纳时该层会被判 false，必须重做对照。\n"+
			"★ evidence_ref 必须是真实写回本任务图的观察节点 id（程序会校验）。",
		obj(map[string]any{
			"kind":         str("基线类型：session（会话健康）| object（对象存在性）| normal_flow（正常业务流程）"),
			"target":       str("精确目标引用（与采纳时的 context.target 必须一致）"),
			"actor":        str("主体/身份（与采纳时的 context.actor 必须一致）"),
			"object":       str("对象（object 类基线填；不需要时留空字符串，需与 context.object 一致）"),
			"purpose":      str("用途（与采纳时的 context.purpose 必须一致）"),
			"evidence_ref": idp("支撑本基线的观察节点 id（必填，需真实存在于本任务图）"),
			"ttl_seconds":  intp("有效期秒数；0/省略 = 默认 900（15 分钟）。会话健康这类会漂移的状态不要设太长"),
			"invalid_if":   str("异常失效条件（人读，例如「服务端撤销会话」「目标重启」）；留空则只按有效期失效"),
		}, "kind", "target", "actor", "purpose", "evidence_ref"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Kind        string `json:"kind"`
				Target      string `json:"target"`
				Actor       string `json:"actor"`
				Object      string `json:"object"`
				Purpose     string `json:"purpose"`
				EvidenceRef int64  `json:"evidence_ref"`
				TTLSeconds  int    `json:"ttl_seconds"`
				InvalidIf   string `json:"invalid_if"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Kind) == "" || strings.TrimSpace(a.Target) == "" ||
				strings.TrimSpace(a.Actor) == "" || strings.TrimSpace(a.Purpose) == "" {
				return actool.Errorf("kind / target / actor / purpose 均必填（基线靠这四项判定能否复用）"), nil
			}
			// 基线是「已验证的对照」，因此它的证据必须是结构化观察（执行器记录的），
			// 不能是模型自己写的 fact —— 否则基线本身就不可复核。
			// ★ 按 kind 选对应谓词：原实现一律只查 observation.available（最弱的一层），
			// 于是一条普通响应就能登记成 session/object 基线，再被当作"已验证的对照"复用。
			basePred := "observation.available"
			switch strings.ToLower(strings.TrimSpace(a.Kind)) {
			case "session":
				basePred = "session.valid"
			case "object":
				basePred = "object.exists"
			}
			res, why := t.semanticCheck(a.EvidenceRef, basePred, expContext{})
			if res != "true" {
				return actool.Errorf(fmt.Sprintf("基线登记失败（%s 这一层未通过，证据必须是结构化观察）：%s", basePred, why)), nil
			}
			pl := baselinePayload(a.Kind, a.Target, a.Actor, a.Object, a.Purpose,
				a.EvidenceRef, a.TTLSeconds, a.InvalidIf)
			id, err := t.ts.AddNode(kindBaseline, pl, 0, "confirmed", t.worker, nil)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("基线登记失败（写库）：%v", err)), nil
			}
			return jsonResult(map[string]any{
				"baseline_id":   id,
				"valid_until":   pl["valid_until"],
				"ttl_seconds":   pl["ttl_seconds"],
				"context":       map[string]any{"target": a.Target, "actor": a.Actor, "object": a.Object, "purpose": a.Purpose},
				"how_to_use":    "在 audit_validity 的 checks 里用 baseline_id 代替 evidence_ref，并在 context 里填同样的 target/actor/object/purpose。",
				"predicate_ver": 1,
			})
		})
}

// saveValidityAudit 把一次判定写成 exploration 节点，供写回门按 intent 反查。
func (t *ToolSet) saveValidityAudit(intentID int64, out map[string]any) int64 {
	payload := map[string]any{
		"intent_id":       intentID,
		"verdict":         out["verdict"],
		"permitted":       out["permitted_conclusion"],
		"negative_claim":  out["negative_claim"],
		"unsatisfied":     out["unsatisfied"],
		"required_layers": out["required_layers"],
		"predicate_set":   out["predicate_set"],
		"predicate_ver":   out["predicate_set_ver"],
		// ★ 补（2026-10-16）：逐层判定明细与实验上下文必须落盘。
		// 上游要求门日志记录「输入引用、上下文版本、谓词版本、原因」——
		// 只存 verdict/unsatisfied 会丢掉每层判 false 的具体原因（过期？不相容？引用无效？），
		// 事后无法复核，也无法做 R05 要求的「谓词逐项验证」。
		"layers":             out["layers"],
		"context":            out["context"],
		"unknown_predicates": out["unknown_predicates"],
		"baselines_used":     out["baselines_used"],
		"scope":              out["scope"],
		"summary": "有效性门审计：negative_claim=「" + fmt.Sprint(out["negative_claim"]) +
			"」⇒ verdict=" + fmt.Sprint(out["verdict"]) +
			"，允许记录 " + fmt.Sprint(out["permitted_conclusion"]),
	}
	id, err := t.ts.AddNode(kindValidityAudit, payload, 0, "confirmed", t.worker, nil)
	if err != nil {
		return 0
	}
	if intentID > 0 {
		_ = t.ts.Link(intentID, "audited", id)
	}
	return id
}

// latestValidityAudit 取本意图最近一次有效性审计的判定结果。
func (t *ToolSet) latestValidityAudit(intentID int64) (map[string]any, int64, error) {
	nodes, err := t.ts.ListByKind(kindValidityAudit, 300)
	if err != nil {
		return nil, 0, err
	}
	var bestP map[string]any
	var bestID int64
	for _, n := range nodes {
		var pl map[string]any
		if json.Unmarshal(n.Payload, &pl) != nil {
			continue
		}
		if int64(numOr0(pl["intent_id"])) != intentID {
			continue
		}
		if n.ID > bestID {
			bestP, bestID = pl, n.ID
		}
	}
	if bestP == nil {
		return nil, 0, nil
	}
	return bestP, bestID, nil
}

// logGateDecision 写一条门决策日志。
func (t *ToolSet) logGateDecision(intentID int64, decision, reason string, auditID int64, keyword string) {
	payload := map[string]any{
		"intent_id":     intentID,
		"decision":      decision,
		"reason":        reason,
		"audit_ref":     auditID,
		"predicate_ver": 1,
		"task_id":       t.taskID,
		"summary":       fmt.Sprintf("写回门 %s（intent %d）：%s", decision, intentID, reason),
	}
	if keyword != "" {
		payload["keyword_hit"] = keyword
	}
	id, err := t.ts.AddNode(kindValidityGate, payload, 0, "confirmed", "system", nil)
	if err == nil && intentID > 0 {
		_ = t.ts.Link(intentID, "gated", id)
	}
}

// validityGate 是【写回门】。在 record_fact 落库前调用。
func (t *ToolSet) validityGate(it factItem, intent int64) error {
	text := it.Summary + " " + it.Detail
	if strings.TrimSpace(it.Conclusion) == "observation" {
		return nil // 显式声明为观察记录：中间观察不能被卡死，否则无法先取证再下结论
	}
	kw, hit := "", false
	explicitNegative := strings.TrimSpace(it.Conclusion) == "negative"
	if !explicitNegative {
		hit, kw = looksNegative(text)
		if !hit {
			return nil
		}
	}

	audit, auditID, err := t.latestValidityAudit(intent)
	if err != nil {
		return fmt.Errorf("有效性门查询失败：%v", err)
	}

	if strings.TrimSpace(it.Confidence) == "inconclusive" &&
		(strings.Contains(it.Summary, "无法判定") || strings.Contains(it.Detail, "无法判定")) {
		t.logGateDecision(intent, "allow", "已自标 inconclusive 且写明无法判定，属诚实负结论", auditID, kw)
		return nil
	}

	if audit == nil {
		t.logGateDecision(intent, "deny",
			"未找到本意图的有效性审计（validity_audit），拒绝把否定性结论写入", auditID, kw)
		cause := "你显式声明了 conclusion=negative"
		if !explicitNegative {
			cause = fmt.Sprintf("本条文本命中否定关键词「%s」", kw)
		}
		return fmt.Errorf("★ 有效性门拒绝写回（%s）。\n"+
			"下【否定结论】之前必须先调 audit_validity：把你打算下的结论 + 你实际做过的对照"+
			"（每层一条 predicate + evidence_ref，或复用已登记的 baseline_id）提交给它，"+
			"拿到 permitted_conclusion 之后再写回。\n"+
			"若本条其实只是【观察记录】（只陈述你看到了什么，不是在断言某物不存在），"+
			"请显式传 conclusion=\"observation\" 重新提交——平台要求把【观察】与【否定结论】分开，"+
			"这是上游共用实验协议「区分观察、解释与断言结果」的落点。", cause)
	}

	verdict := strings.TrimSpace(fmt.Sprint(audit["verdict"]))
	if verdict == "sufficient" {
		t.logGateDecision(intent, "allow", "持有本意图的 sufficient 有效性审计", auditID, kw)
		return nil
	}

	unsat := ""
	if u, ok := audit["unsatisfied"].([]any); ok && len(u) > 0 {
		parts := make([]string, 0, len(u))
		for _, x := range u {
			parts = append(parts, fmt.Sprint(x))
		}
		unsat = strings.Join(parts, "、")
	}
	t.logGateDecision(intent, "deny",
		"有效性审计判定 insufficient（缺："+unsat+"），拒绝把否定性结论写入", auditID, kw)
	return fmt.Errorf("★ 有效性门拒绝写回：audit_validity 判定 verdict=insufficient，缺少必需层 [%s]。\n"+
		"请先补齐这些层的对照观察（按 audit_validity 返回的 required_action），再重新提交；\n"+
		"或者如实把本结论标为无法判定：confidence=\"inconclusive\"、summary 里写明「无法判定」——"+
		"平台接受诚实的「无法判定」，但不接受证据不足却写成确定结论。", unsat)
}

// auditValidity 是工人侧的有效性前提校验工具。
// V3：checks 可用 baseline_id 复用公共基线；程序检查 存在/未过期/上下文相容。
func (t *ToolSet) auditValidity() actool.CoreTool {
	return t.readExpTool("audit_validity",
		"【下否定结论前必调】用已注册的机器谓词校验本实验的有效性前提，给出【允许你记什么结论】。"+
			"★ 平台已接入【写回门】：否定性结论若没有本意图的 sufficient 审计，record_fact 会被【拒绝】。\n"+
			"为什么：判『没找到漏洞』比判『找到漏洞』更容易出错 —— 请求可能用了过期会话、错误对象、"+
			"无效业务状态，或者结果根本无法通过当前上下文观察。\n"+
			"★ 权威划分：模型自己填 observed 不构成背书；只有程序校验过的引用才算数。\n"+
			"★ 复用：每层可以给 evidence_ref（本次观察的节点 id），也可以用 baseline_id 复用已登记的公共基线——"+
			"但基线必须【未过期】且与 context 里的 目标/主体/对象/用途 完全一致，否则该层判 false。\n"+
			"用法：提交「否定结论 + 意图 id + 本实验 context + 各层对照」。\n"+
			"返回：sufficient=可以记 not_reproduced；insufficient=只能记 inconclusive，按 unsatisfied 补齐再判。\n"+
			"⚠️ 本工具只校验【形式与引用】（谓词已注册 / 证据真实存在 / 必需层齐备 / 基线有效且上下文相容），"+
			"【不校验语义】（那条观察是否真的支撑你的断言，仍需结构化执行器的观察明细或人工复核）。",
		obj(map[string]any{
			"intent_id":      idp("产生本结论的意图 id（必填：写回门按意图核对审计）"),
			"negative_claim": str("你打算下的否定结论（一句话）。例如「该接口不存在越权访问」"),
			"context": obj(map[string]any{
				"target":  str("本实验的目标（与复用基线时的 target 必须一致）"),
				"actor":   str("本实验的主体/身份（与复用基线时的 actor 必须一致；匿名填 anonymous）"),
				"object":  str("本实验针对的对象；不涉及具体对象时填空字符串"),
				"purpose": str("本实验的用途（与复用基线时的 purpose 必须一致）"),
			}, "target", "actor", "purpose"),
			"need_auth": map[string]any{"type": "boolean",
				"description": "本实验是否需要登录态才能成立？匿名公开接口填 false（此时不要求 session.valid 层）"},
			"about_object": map[string]any{"type": "boolean",
				"description": "结论是否针对某个【具体对象】（记录/文件/订单…）？是则要求 object.exists 层"},
			"checks": map[string]any{"type": "array",
				"description": "你实际做过的有效性对照。每层一条：{predicate, evidence_ref | baseline_id, note}。" +
					"predicate 取已注册名（transport.reachable / session.valid / object.exists / " +
					"observation.available / method.applicable）；evidence_ref = 本次观察的节点 id；" +
					"baseline_id = 复用已登记的公共基线（须未过期且与 context 相容）。二者至少给一个。",
				"items": obj(map[string]any{
					"predicate":    str("已注册的机器谓词名"),
					"evidence_ref": idp("本次对照观察的节点 id（与 baseline_id 二选一）"),
					"baseline_id":  idp("★V3：复用的公共基线 id（程序会查有效期与上下文相容性）"),
					"note":         str("一句话说明你是怎么验的（供人工复核）"),
				})},
		}, "negative_claim", "intent_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				NegativeClaim string          `json:"negative_claim"`
				IntentID      json.RawMessage `json:"intent_id"`
				Context       expContext      `json:"context"`
				NeedAuth      *bool           `json:"need_auth"`
				AboutObject   *bool           `json:"about_object"`
				Checks        []validityClaim `json:"checks"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.NegativeClaim) == "" {
				return actool.Errorf("negative_claim 必填：请先写清你要下的否定结论"), nil
			}
			intent := pid(a.IntentID)
			cx := expContext{
				Target:  strings.TrimSpace(a.Context.Target),
				Actor:   strings.TrimSpace(a.Context.Actor),
				Object:  strings.TrimSpace(a.Context.Object),
				Purpose: strings.TrimSpace(a.Context.Purpose),
			}

			required := map[string]bool{
				"transport.reachable":   true,
				"observation.available": true,
				// ★ 授权范围是前置条件：超范围目标的观察不能支撑任何结论。
				//   见 scope_guard.go。装在 required 里意味着"每份审计都要过这一层"。
				"out_of_scope": true,
			}
			if a.NeedAuth != nil && *a.NeedAuth {
				required["session.valid"] = true
			}
			if a.AboutObject != nil && *a.AboutObject {
				required["object.exists"] = true
			}

			var unknown []string
			declared := map[string]validityClaim{}
			for _, c := range a.Checks {
				name := strings.TrimSpace(c.Predicate)
				if predicateByName(name) == nil {
					unknown = append(unknown, name)
					continue
				}
				declared[name] = c
			}

			var layers []layerResult
			var unsatisfied []string
			baselineUsed := []map[string]any{}
			for _, spec := range BuiltinPredicates {
				c, ok := declared[spec.Name]
				if !ok {
					if required[spec.Name] {
						unsatisfied = append(unsatisfied, spec.Name)
						layers = append(layers, layerResult{
							Layer: spec.Layer, Predicate: spec.Name, Version: spec.Version,
							Result: "false", Enforced: spec.Enforced,
							Reason: "必需层但未声明 —— 你没有提供这一层的对照观察。适用条件：" + spec.AppliesWhen +
								"；观察要求：" + spec.Requires,
						})
					} else {
						layers = append(layers, layerResult{
							Layer: spec.Layer, Predicate: spec.Name, Version: spec.Version,
							Result: "unknown", Enforced: spec.Enforced,
							Reason: "非必需层，未声明 ⇒ 保持未知（不猜）。前提不足时结论不得升级为肯定或否定。",
						})
					}
					continue
				}

				lr := layerResult{Layer: spec.Layer, Predicate: spec.Name, Version: spec.Version, Enforced: spec.Enforced}
				// ★ V3：优先看基线复用；基线不成立再看本次观察
				if c.BaselineID > 0 {
					res, why, srcRef := t.checkBaseline(c.BaselineID, cx)
					lr.BaselineRef = c.BaselineID
					lr.EvidenceRef = srcRef
					if res == "true" {
						// ★★★ 基线只是"把已验过的对照记下来复用"，它本身不是证据。
						// 原实现只查 存在/未过期/上下文相容 就判 true，从不看源观察是否
						// 真的满足本谓词的语义 —— 于是一条普通 HTTP 响应登记成基线后，
						// 可以被 session.valid / object.exists / out_of_scope 随意复用。
						// 修：采纳基线时，对它的源观察跑同一个 semanticCheck。
						if srcRef <= 0 {
							res = "false"
							why = why + "；但基线未记录源观察引用，无法复核语义"
						} else if sres, swhy := t.semanticCheck(srcRef, spec.Name, cx); sres != "true" {
							res = "false"
							why = why + "；且源观察未通过本谓词语义检查：" + swhy
						}
					}
					if res == "true" {
						lr.Result, lr.ViaBaseline = "true", true
						lr.Reason = why + "；以基线复用代替重复诊断（上游 R05-V3）"
						baselineUsed = append(baselineUsed, map[string]any{"predicate": spec.Name, "baseline_id": c.BaselineID})
						if n := strings.TrimSpace(c.Note); n != "" {
							lr.Reason += "；自述：" + n
						}
						layers = append(layers, lr)
						continue
					}
					if c.EvidenceRef <= 0 {
						// 只给了基线且基线不成立 → 本层直接判 false
						lr.Result = "false"
						lr.Reason = why
						if required[spec.Name] {
							unsatisfied = append(unsatisfied, spec.Name)
							lr.Reason += "；本层为必需层，故判未满足"
						}
						layers = append(layers, lr)
						continue
					}
					lr.Reason = why + "；已回退到本次观察 evidence_ref 判定"
				}
				if c.EvidenceRef <= 0 {
					lr.Result = "false"
					lr.Reason = "既未提供 evidence_ref 也未提供可用 baseline_id（至少给一个）"
					if required[spec.Name] {
						unsatisfied = append(unsatisfied, spec.Name)
						lr.Reason += "；本层为必需层，故判未满足"
					}
					layers = append(layers, lr)
					continue
				}
				// ★ V4：走语义检查（证据必须是结构化观察，且满足该谓词的判据）
				res, why := t.semanticCheck(c.EvidenceRef, spec.Name, cx)
				lr.Result, lr.EvidenceRef = res, c.EvidenceRef
				lr.Reason = why
				if res != "true" && required[spec.Name] {
					unsatisfied = append(unsatisfied, spec.Name)
					lr.Reason = why + "；本层为必需层，故判未满足"
				} else if res == "true" && strings.TrimSpace(c.Note) != "" {
					lr.Reason = why + "；自述验法：" + strings.TrimSpace(c.Note)
				}
				layers = append(layers, lr)
			}

			verdict := "sufficient"
			permitted := "not_reproduced"
			action := "必需层已齐备：可以记 `not_reproduced`（本次与当前条件下未复现）。" +
				"但仍须在事实里写明所用方法、有效对照与适用条件 —— 不得写成「整体安全」或「已修复」。"
			if len(unsatisfied) > 0 || len(unknown) > 0 {
				verdict = "insufficient"
				permitted = "inconclusive"
				action = "前提不足，只能记 `inconclusive`（无法判定）。请先补齐下列对照，再下否定结论："
				if len(unsatisfied) > 0 {
					action += " " + strings.Join(unsatisfied, "、")
				}
				if len(unknown) > 0 {
					action += "；另有未注册谓词名被拒绝：" + strings.Join(unknown, "、")
				}
				action += "。★ 不要为了给个结论而硬判肯定或否定。"
			}

			out := map[string]any{
				"verdict":              verdict,
				"permitted_conclusion": permitted,
				"negative_claim":       a.NegativeClaim,
				"intent_id":            intent,
				"context":              map[string]any{"target": cx.Target, "actor": cx.Actor, "object": cx.Object, "purpose": cx.Purpose},
				"required_layers":      required,
				"required_by": map[string]any{
					"need_auth":    a.NeedAuth,
					"about_object": a.AboutObject,
				},
				"layers":             layers,
				"unsatisfied":        unsatisfied,
				"unknown_predicates": unknown,
				"baselines_used":     baselineUsed,
				"required_action":    action,
				"predicate_set":      "artex.validity",
				"predicate_set_ver":  4,
				"model_authority":    "模型自述（observed 标签、角色标签、评分）不构成程序背书",
				"scope": "V4：本工具对【结构化观察】做语义检查 —— 证据必须是执行器（http_probe）记录的 observation 节点，" +
					"且满足该谓词的判据（如 session.valid 要求主体非匿名 + 有对照 + 与对照可区分）；" +
					"同时校验谓词已注册、必需层齐备、基线存在且未过期且上下文相容。" +
					"★ 仍未覆盖的：跨服务对象映射、凭据 audience/租户条件这类需要多源核对的判断，" +
					"以及非 HTTP 通道的观察 —— 这些仍保留为候选或人工复核。",
			}
			if aid := t.saveValidityAudit(intent, out); aid > 0 {
				out["audit_id"] = aid
				out["gate_note"] = "本判定已登记（validity_audit #" + fmt.Sprint(aid) +
					"）。写回门会按 intent_id 核对：verdict=sufficient 才放行否定性结论。"
			} else {
				out["gate_note"] = "⚠ 判定未能登记（保存失败），写回门可能拒绝后续否定性结论。"
			}
			return jsonResult(out)
		})
}
