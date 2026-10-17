package server

// mcp_action_gate.go —— MCP 动作类工具的黑名单（本地新增 2026-10-17）
//
// 解决什么（实测过的事实）：
//   ARTEX 的 V6（授权范围闸）与 V7（测试规则闸）只挂在 http_probe 上：
//     grep loadScopeGuard / checkMethod / checkReadQuota / checkBudget
//     → 只出现在 agent/http_probe.go
//   而 agent 手边还有一组 MCP 工具能【让别的系统去扫描】：
//     mcp__ScopeSentry__create_project / create_scan_task / create_scan_template
//     mcp__ScopeSentry__add_asset_tag
//   ScopeSentry 的 scan worker 容器跑在 network=host，直接对目标发包 ——
//   ⇒ 这条路上 V6/V7 的全部闸都被绕过。
//
// 为什么用黑名单而不是白名单 —— 以及它的代价（照实写，别把行为说反）：
//
//	本实现是【黑名单】：只有明确列在 mcpActionTools 里的名字会被拦，
//	其余一律 return true（放行）。所以真实语义是：
//	  · 列全了 → 该拦的都拦了
//	  · 列漏了（对方新增了动作类工具）→ 新工具【默认被放行】
//
//	★ 上一版注释写反了（写成"黑名单不全则新工具默认被拦"），与代码行为不符。
//	  黑名单的失效方向就是"漏掉的默认放行"——这是选黑名单必须接受的代价。
//
//	选它的理由：MCP 工具集由对方决定、随版本增减，白名单需要不断同步否则合法工具
//	会被误杀；而对"动作类"工具，误杀一个查询类的代价（少一个能力）通常小于
//	漏放一个扫描类的代价。但"漏放"确实可能发生 —— 新增 ASM 类 MCP 服务器时，
//	必须同步往 mcpActionTools 里补它的动作类工具名。
//
// 怎么放开：
//   ARTEX_MCP_ALLOW_ACTIONS=1 → 全部放行（授权方显式决定）
//   ARTEX_MCP_ALLOW_ACTIONS="ScopeSentry:create_scan_task" → 只放行指定的
//
// 注意：这里的"工具名"是 MCP 原始名（不含 mcp__server__ 前缀），
//       因为过滤发生在展开成 mcp__server__tool 之前。

import (
	"os"
	"strings"
)

// mcpActionTools 是各 MCP 服务器上的【动作类】工具（会产生真实网络行为或写状态）。
// 只列确实有外部影响的；查询类不放这里。
var mcpActionTools = map[string]map[string]bool{
	// ScopeSentry：ASM 测绘平台。它的 scan worker 在 host 网络上真发包。
	"ScopeSentry": {
		"create_project":       true, // 建项目（会带目标范围）
		"create_scan_task":     true, // ★ 发起扫描 —— 这是最关键的一条
		"create_scan_template": true, // 建扫描模板
		"add_asset_tag":        true, // 写资产标签（改状态）
	},
}

// bareToolName 把 mcp__<server>__<tool> 剥成 (server, tool)。
//
// ★ 为什么必须剥（2026-10-17 踩过的坑）：
//
//	norma/mcp/mcp.go:21 的 ToolName() 把工具名展开成 "mcp__"+server+"__"+name，
//	而 wrap() 里 Name 用的就是这个全名 ⇒ 循环里 t.Name() 拿到的是
//	"mcp__ScopeSentry__create_scan_task"，不是 "create_scan_task"。
//	第一版黑名单用裸名比较 ⇒ 全部不匹配 ⇒ 静默全放行（不报错、不打日志）。
//	⇒ 这个函数是那次失败的直接修复；两种形式都接受，避免命名规则再变时又静默失效。
func bareToolName(full string) (server, tool string) {
	if !strings.HasPrefix(full, "mcp__") {
		return "", full
	}
	rest := strings.TrimPrefix(full, "mcp__")
	// server 名里不会出现 "__"（MCP 规范），工具名可能含下划线，所以按首个 "__" 切
	if i := strings.Index(rest, "__"); i > 0 {
		return rest[:i], rest[i+2:]
	}
	return "", rest
}

// normalize 兼容两种入参形式：裸名对，或者带 mcp__ 前缀的全名。
// 调用方可能传 m.Name()/t.Name()（全名），也可能传原始名（裸名）。
func normalize(server, tool string) (string, string) {
	if strings.HasPrefix(tool, "mcp__") {
		if srv, name := bareToolName(tool); name != "" {
			return srv, name
		}
	}
	return server, tool
}

// mcpActionGate 解析 ARTEX_MCP_ALLOW_ACTIONS，返回放行判定函数。// mcpActionGate 解析 ARTEX_MCP_ALLOW_ACTIONS，返回放行判定函数。
//
//	""       → 全部动作类工具被拦（默认）
//	"1"/"all" → 全部放行
//	"ScopeSentry:create_scan_task,other:foo" → 只放行列出的
func mcpActionGate() func(server, tool string) bool {
	raw := strings.TrimSpace(os.Getenv("ARTEX_MCP_ALLOW_ACTIONS"))
	if raw == "" {
		return func(server, tool string) bool {
			srv, name := normalize(server, tool)
			if s, ok := mcpActionTools[srv]; ok && s[name] {
				return false
			}
			return true
		}
	}
	switch strings.ToLower(raw) {
	case "1", "true", "all", "*":
		return func(server, tool string) bool { return true }
	}
	allow := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		allow[strings.ToLower(item)] = true
	}
	return func(server, tool string) bool {
		srv, name := normalize(server, tool)
		if allow[strings.ToLower(srv+":"+name)] {
			return true
		}
		if s, ok := mcpActionTools[srv]; ok && s[name] {
			return false
		}
		return true
	}
}
