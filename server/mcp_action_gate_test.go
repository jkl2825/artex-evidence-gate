package server

import "testing"

// 默认：动作类工具被拦，查询类放行，未知服务器/工具不误伤。
func TestMCPActionGateDefaultDeny(t *testing.T) {
	t.Setenv("ARTEX_MCP_ALLOW_ACTIONS", "")
	ok := mcpActionGate()

	denied := []string{"create_project", "create_scan_task", "create_scan_template", "add_asset_tag"}
	for _, tool := range denied {
		if ok("ScopeSentry", tool) {
			t.Errorf("ScopeSentry.%s 属动作类，默认应拦，实际放行", tool)
		}
	}

	allowed := []string{
		"list_projects", "list_assets", "count_assets", "get_asset_detail",
		"list_nodes", "list_tasks", "list_plugins", "list_scan_templates",
		"get_task", "get_project", "list_projects_data",
	}
	for _, tool := range allowed {
		if !ok("ScopeSentry", tool) {
			t.Errorf("ScopeSentry.%s 是查询类，应放行，实际拦下", tool)
		}
	}

	// 其它 MCP 服务器完全不受影响（不误伤）
	if !ok("browser", "browser_navigate") {
		t.Errorf("browser 服务器不应受 ScopeSentry 黑名单影响")
	}
	if !ok("fofa-relay", "get_alerts") {
		t.Errorf("fofa-relay 不应受影响")
	}
	// 未知工具名放行（黑名单语义：只拦列出的）
	if !ok("ScopeSentry", "some_future_read_tool") {
		t.Errorf("未列出的工具应放行（黑名单语义）")
	}
	t.Logf("✓ 默认：4 个动作类拦下 · 11 个查询类放行 · 其它服务器不误伤")
}

// 全放开。
func TestMCPActionGateAllowAll(t *testing.T) {
	for _, v := range []string{"1", "true", "all", "*", "ALL"} {
		t.Setenv("ARTEX_MCP_ALLOW_ACTIONS", v)
		ok := mcpActionGate()
		if !ok("ScopeSentry", "create_scan_task") {
			t.Errorf("ARTEX_MCP_ALLOW_ACTIONS=%q 时应全放，实际仍拦", v)
		}
	}
	t.Logf("✓ 全放开：1/true/all/* 都生效")
}

// 精确放行：只放列出的那一条，其余动作类仍拦。
func TestMCPActionGateSelective(t *testing.T) {
	t.Setenv("ARTEX_MCP_ALLOW_ACTIONS", "ScopeSentry:create_scan_task")
	ok := mcpActionGate()

	if !ok("ScopeSentry", "create_scan_task") {
		t.Errorf("显式列出的 create_scan_task 应放行")
	}
	for _, tool := range []string{"create_project", "create_scan_template", "add_asset_tag"} {
		if ok("ScopeSentry", tool) {
			t.Errorf("未列出的动作类 %s 仍应拦", tool)
		}
	}
	t.Logf("✓ 精确放行：只放 create_scan_task，其余动作类仍拦")
}

// 大小写与空白容错。
func TestMCPActionGateCaseInsensitive(t *testing.T) {
	t.Setenv("ARTEX_MCP_ALLOW_ACTIONS", " scopesentry:CREATE_SCAN_TASK , ")
	ok := mcpActionGate()
	if !ok("ScopeSentry", "create_scan_task") {
		t.Errorf("放行列表应大小写不敏感且容忍空白")
	}
}

// ★ 回归测试：真实调用方传的是全名（t.Name() = mcp__server__tool）。
// 第一版黑名单用裸名比较，导致全部静默放行 —— 这条就是那次失败的护栏。
func TestMCPActionGateFullName(t *testing.T) {
	t.Setenv("ARTEX_MCP_ALLOW_ACTIONS", "")
	ok := mcpActionGate()

	// 全名形式必须能拦住
	for _, full := range []string{
		"mcp__ScopeSentry__create_scan_task",
		"mcp__ScopeSentry__create_project",
		"mcp__ScopeSentry__create_scan_template",
		"mcp__ScopeSentry__add_asset_tag",
	} {
		if ok("ScopeSentry", full) {
			t.Errorf("全名 %s 应被拦（这是第一版失效的场景），实际放行", full)
		}
	}
	// 全名形式的查询类必须放行
	for _, full := range []string{
		"mcp__ScopeSentry__list_assets",
		"mcp__ScopeSentry__count_assets",
		"mcp__ScopeSentry__list_projects",
	} {
		if !ok("ScopeSentry", full) {
			t.Errorf("全名 %s 是查询类，应放行", full)
		}
	}
	// 其它服务器的全名不误伤
	if !ok("browser", "mcp__browser__browser_navigate") {
		t.Errorf("browser 全名不应受影响")
	}
	t.Logf("✓ 全名形式：4 个动作类拦下 · 3 个查询类放行 · 其它服务器不误伤")
}

// 剥前缀工具本身的边界。
func TestBareToolName(t *testing.T) {
	cases := []struct{ in, srv, tool string }{
		{"mcp__ScopeSentry__create_scan_task", "ScopeSentry", "create_scan_task"},
		{"mcp__browser__browser_click", "browser", "browser_click"},
		{"mcp__fofa-relay__get_alerts", "fofa-relay", "get_alerts"},
		{"create_scan_task", "", "create_scan_task"},
	}
	for _, c := range cases {
		srv, tool := bareToolName(c.in)
		if srv != c.srv || tool != c.tool {
			t.Errorf("bareToolName(%q) = (%q,%q)，期望 (%q,%q)", c.in, srv, tool, c.srv, c.tool)
		}
	}
	t.Logf("✓ 剥前缀 %d 例通过", len(cases))
}
