package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ---------------------------------------------------------------------------
// thread（战线）工具：planner 用它显式开线 / 收线。
//
// ★ 为什么必须是显式工具而不是让模型在 summary 里自己写方向名：
// 靠模型自由命名的「方向」没法强制约束——它可以每轮换一个措辞。
// 做成节点后，「同一时刻只有一条 active」是可查、可判、可拒的。
// ---------------------------------------------------------------------------

// openThread 开一条新战线。
//
// 硬约束：已有 active 战线时拒绝——那是「同时打两条线」，正是要避免的铺开。
func (t *ToolSet) openThread() actool.CoreTool {
	return t.writeExpTool("open_thread",
		"开一条【战线】：本轮主攻的一条方向。\n"+
			"★ 机制：同一时刻只允许一条 active 战线。所有 add_intent 必须挂在它下面。\n"+
			"★ 收线：用 close_thread 把当前战线标成 done/parked/abandoned 后，才能开下一条。\n"+
			"★ 为什么这么设计：不允许想到什么就派什么，否则会铺开一堆浅尝辄止的方向。"+
			"正确做法是选一条最有希望打穿的路，把它挖透，再换下一条。",
		obj(map[string]any{
			"summary": str("★ 这条战线是什么（一句话）：打哪个目标/入口、走什么打法。"),
			"done_when": str("★ 什么算这条战线【挖透】——必须是可判定的条件。" +
				"例：「已用 3 种身份对 /x/space/acc/info 做过越权对照，均返回同构数据 ⇒ 确认无越权」" +
				"「已测完该上传接口的 5 类绕过（后缀/MIME/魔数/竞争/路径），任一成立即算挖到」。" +
				"含糊的「尽量挖」无效。"),
			"entry": str("入口（可选但建议填）：具体的资产/接口/主机，便于 worker 落地。"),
		}, "summary", "done_when"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Summary  string `json:"summary"`
				DoneWhen string `json:"done_when"`
				Entry    string `json:"entry"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Summary) == "" {
				return actool.Errorf("summary 必填：这条战线打什么"), nil
			}
			if strings.TrimSpace(a.DoneWhen) == "" {
				return actool.Errorf("done_when 必填：什么算这条线挖透（可判定）。" +
					"没有完成条件就没法判定收线，会一直挂着"), nil
			}
			if active, err := t.ts.ActiveThread(); err != nil {
				return actool.Errorf(fmt.Sprintf("查询当前战线失败：%v", err)), nil
			} else if active != nil {
				var p db.ThreadPayload
				_ = json.Unmarshal(active.Payload, &p)
				return actool.Errorf(fmt.Sprintf("已有 active 战线 #%d「%s」（done_when: %s）。\n"+
					"同时只能有一条主攻方向——请先用 close_thread 收掉它（done/parked/abandoned 并说明原因），再开新的。",
					active.ID, p.Summary, p.DoneWhen)), nil
			}

			payload := map[string]any{
				"summary":   a.Summary,
				"done_when": a.DoneWhen,
			}
			if a.Entry != "" {
				payload["entry"] = a.Entry
			}
			id, err := t.ts.CreateThread(payload)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("开线失败：%v", err)), nil
			}
			return actool.Text(fmt.Sprintf("战线已开：#%d「%s」\n完成条件：%s\n"+
				"接下来所有 add_intent 都会自动挂到这条线上。挖透了就 close_thread 收线。",
				id, a.Summary, a.DoneWhen)), nil
		})
}

// closeThread 收掉当前战线。
//
// 收线时必须给出状态和原因；服务端会把当前统计一并返回，便于 planner 判断
// 「这条线是不是真的挖透了」（例如 intents 都终态、但 observations=0 ⇒ 其实没真打）。
func (t *ToolSet) closeThread() actool.CoreTool {
	return t.writeExpTool("close_thread",
		"收掉当前战线（标成 done/parked/abandoned）。收起后才可以 open_thread 开下一条。\n"+
			"★ done 的含义是【done_when 已满足】，不是不想打了。真的打不动请用 abandoned 并写明原因。\n"+
			"★ 返回会带上这条线的统计（意图数/观察数/事实数/发现数），请据此自查是否真的挖透。",
		obj(map[string]any{
			"thread_id": idp("要收的战线 id（就是 open_thread 返回的那个）"),
			"state": str("★ 收线状态：done（done_when 已满足）/ parked（等外部依赖，将来还会回来）" +
				"/ abandoned（放弃）"),
			"reason": str("★ 原因：done 时写「哪条证据满足了 done_when」；" +
				"parked 写「在等什么」；abandoned 写「为什么打不动」。空话无效。"),
		}, "thread_id", "state", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ThreadID json.RawMessage `json:"thread_id"`
				State    string          `json:"state"`
				Reason   string          `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)
			id := pid(a.ThreadID)
			if id == 0 {
				return actool.Errorf("thread_id 必填"), nil
			}
			state := strings.TrimSpace(a.State)
			switch state {
			case db.StateThreadDone, db.StateThreadParked, db.StateThreadAbandoned:
			default:
				return actool.Errorf(fmt.Sprintf("state 必须是 done / parked / abandoned 之一（收到 %q）", state)), nil
			}
			if strings.TrimSpace(a.Reason) == "" {
				return actool.Errorf(fmt.Sprintf("reason 必填：%s 时要写清依据（空话无效）", state)), nil
			}
			n, err := t.ts.GetNode(id)
			if err != nil || n == nil || n.Kind != db.KindThread {
				return actool.Errorf("thread_id 必须是本任务的战线节点"), nil
			}
			if n.State != db.StateThreadActive {
				return actool.Errorf(fmt.Sprintf("战线 #%d 当前状态是 %q，不是 active —— 只能收 active 的线", id, n.State)), nil
			}
			stats, _ := t.ts.ThreadStatsOf(id)
			if err := t.ts.SetThreadState(id, state, a.Reason); err != nil {
				return actool.Errorf(fmt.Sprintf("收线失败：%v", err)), nil
			}
			msg := fmt.Sprintf("战线 #%d 已收（%s）：%s\n", id, state, a.Reason)
			if stats != nil {
				msg += fmt.Sprintf("这条线的统计：意图 %d 条（终态 %d）· 观察 %d · 事实 %d · 发现 %d\n",
					stats.Intents, stats.Terminal, stats.Observations, stats.Facts, stats.Findings)
				if state == db.StateThreadDone && stats.Observations == 0 {
					msg += "⚠ 注意：标了 done 但这条线一条结构化观察都没有 —— " +
						"确认它是靠真实证据挖透的，而不是只派了意图没人真打。\n"
				}
			}
			msg += "现在可以 open_thread 开下一条战线了。"
			return actool.Text(msg), nil
		})
}

// listThreadsTool 列本任务的战线及其状态/统计（planner 复盘用）。
func (t *ToolSet) listThreadsTool() actool.CoreTool {
	return t.readExpTool("list_threads", "列本任务的战线（最新在前）及其状态与统计。",
		obj(map[string]any{
			"state": str("按状态过滤：active/done/parked/abandoned；留空=全部"),
			"limit": intp("最多几条，默认 20"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				State string `json:"state"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(in, &a)
			ns, err := t.ts.ListThreads(a.State, a.Limit)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("查询失败：%v", err)), nil
			}
			out := make([]map[string]any, 0, len(ns))
			for _, n := range ns {
				var p db.ThreadPayload
				_ = json.Unmarshal(n.Payload, &p)
				item := map[string]any{
					"id": n.ID, "state": n.State,
					"summary": p.Summary, "done_when": p.DoneWhen,
				}
				if p.Entry != "" {
					item["entry"] = p.Entry
				}
				if st, err := t.ts.ThreadStatsOf(n.ID); err == nil {
					item["stats"] = st
				}
				out = append(out, item)
			}
			return jsonResult(map[string]any{"threads": out, "total": len(out)})
		})
}
