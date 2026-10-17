package agent

// scope_tool.go —— 授权范围的可操作界面（本地新增 2026-10-17）
//
// 与 scope_guard.go 分工：
//   scope_guard.go  判定与拦截（http_probe 调用它）
//   scope_tool.go   让人/模型能看见当前边界、能主动声明
//
// 为什么需要它：有了闸门却没有「看得见、改得动」的入口，worker 只会反复撞墙。
// 撞墙时的正确行为是【声明范围】而不是【换一种方式绕过】，所以要把这个入口摆在明处。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
)

// scopeStatus 给模型看当前授权边界，并允许显式声明。
func (t *ToolSet) scopeStatus() actool.CoreTool {
	return t.writeExpTool("scope_status",
		"【授权范围】看当前任务的授权边界；或把目标显式声明进范围。\n"+
			"★ 为什么有这一层：http_probe 会在发请求【之前】问一句「这个 host 在授权边界内吗」，"+
			"超范围的请求不会发出。被拦下时的正确反应是【用本工具声明范围】，不是换工具绕过。\n"+
			"★ 三道闸（见 scope_guard.go）：\n"+
			"  ① 绝对禁止段 —— 云元数据 169.254/16、回环 127/8、链路本地、组播、保留段。"+
			"任何授权都不放行（打元数据等于偷凭据，打回环等于 SSRF 打自己）。\n"+
			"  ② 私有网段（10/8 · 172.16/12 · 192.168/16 · 100.64/10 · IPv6 ULA）默认拒绝，必须显式声明。\n"+
			"  ③ 已声明范围外的目标：本任务若已有声明则拒绝；若尚无任何声明则放行但记警告。\n"+
			"★ 只统计 source ∈ {manual,agent} 的声明；source=auto（系统自动累积「碰到的」主机）不构成授权。",
		obj(map[string]any{
			"declare": map[string]any{
				"type": "array",
				"description": "要声明进本任务范围的目标列表。" +
					"可写：域名（如 example.com）、IP（如 172.18.0.5）、CIDR（如 172.18.0.0/16）。" +
					"域名会按【精确子域】加入，不会自动扩成整个根域 —— 要扩根域请显式写根域。",
				"items": map[string]any{"type": "string"},
			},
			"reason": str("声明依据（必填，用于审计）：例如「任务目标明确指定了该主机」"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Declare []string `json:"declare"`
				Reason  string   `json:"reason"`
			}
			_ = json.Unmarshal(in, &a)

			out := map[string]any{}

			// ── 声明 ──
			if len(a.Declare) > 0 {
				if t.as == nil {
					return actool.Errorf("scope_status 无法声明：AssetStore 未初始化"), nil
				}
				if t.taskID <= 0 {
					return actool.Errorf("scope_status 无法声明：缺少任务上下文"), nil
				}
				reason := strings.TrimSpace(a.Reason)
				if reason == "" {
					return actool.Errorf("声明范围必须给 reason（用于审计）。" +
						"例如 reason=\"任务目标明确指定了该主机\""), nil
				}
				var added, skipped, rejected []string
				for _, raw := range a.Declare {
					v := strings.TrimSpace(raw)
					if v == "" {
						continue
					}
					// 绝对禁止段：拒绝声明（写进去也没用，反而误导）
					host := scopeNormHost(v)
					if ip := net.ParseIP(host); ip != nil {
						if n, hit := ipInAny(ip, absolutelyDeniedNets); hit {
							rejected = append(rejected,
								fmt.Sprintf("%s（命中绝对禁止段 %s，任何授权都不放行）", v, n.String()))
							continue
						}
					}
					kind := "subdomain"
					if strings.Contains(v, "/") {
						kind = "cidr"
					} else if ip := net.ParseIP(host); ip != nil {
						kind = "ip"
					}
					if _, err := t.as.AddAgentScope(t.taskID, kind, v, reason, "agent"); err != nil {
						skipped = append(skipped, fmt.Sprintf("%s（%v）", v, err))
					} else {
						added = append(added, fmt.Sprintf("%s:%s", kind, v))
					}
				}
				invalidateScopeGuard(t.taskID)
				out["declared"] = added
				if len(skipped) > 0 {
					out["skipped"] = skipped
				}
				if len(rejected) > 0 {
					out["rejected"] = rejected
				}
				if len(added) == 0 && len(rejected) > 0 {
					out["note"] = "没有任何目标被声明成功 —— 全部命中了绝对禁止段。" +
						"这类目标（云元数据/回环/链路本地/组播/保留）在任何授权语境下都不应被测试。"
				}
			}

			// ── 当前状态 ──
			g := t.loadScopeGuard()
			out["scope"] = g.summary()
			out["mode_env"] = "ARTEX_SCOPE_MODE（strict | declared | audit_only，默认 declared）"

			if !g.declared {
				out["warning"] = "本任务【尚未声明任何范围】。当前只有绝对禁止段生效 —— " +
					"任何公网目标都会被放行。要进入 fail-closed 保护，请先用 declare 声明本任务的授权目标。"
			}
			return jsonResult(out)
		})
}
