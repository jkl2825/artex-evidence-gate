package db

import (
	"database/sql"
	"encoding/json"
	"log"
	"sort"
)

// Tool is one row of the built-in tool catalog. key + handler live in code; this
// row carries only the page-editable surface: description, parameter schema
// (structure read-only, per-param description/default editable), agent binding,
// and the on/off switch. See schema.sql §H and agent/toolcatalog.go.
type Tool struct {
	Key         string          `json:"key"`
	System      bool            `json:"system"`
	Description string          `json:"description"`
	Schema      json.RawMessage `json:"schema"`
	Agents      []string        `json:"agents"`
	Enabled     bool            `json:"enabled"`
	Kind        string          `json:"kind"`     // builtin | command | script | http
	Exec        json.RawMessage `json:"exec"`     // 自定义工具执行规格(kind!=builtin)
	Deferred    bool            `json:"deferred"` // schema 延迟(走 SearchExtraTools/ExecuteExtraTool)
	Calls       int             `json:"calls"`    // runtime ledger aggregate; not stored in tools
}

const toolCols = `key, system, description, schema, agents, enabled, kind, exec, deferred`

// SeedTool inserts a built-in tool's code-defined defaults ONCE. ON CONFLICT DO
// NOTHING: an existing row (possibly edited in the UI) is never overwritten on
// startup — that's what keeps page edits from being wiped every restart. Use
// UpsertToolForce for an explicit "reset to code default".
//
// ★ 2026-10-17 追加：【只加不改】的参数补齐。
//
//	背景：ToolResolve 用的是 DB 里的 schema，不是代码里的。所以给内置工具
//	新增一个参数后，模型看不到它 —— 必须手动 UPDATE DB 才行。
//	实测踩过：http_probe 加了 host_override/insecure_tls/cookie_jar，
//	DB 里仍是旧的 12 个参数，模型完全不知道能用，白改一场。
//
//	补法刻意保守：只把【代码有、DB 没有】的 properties 加进去；
//	DB 里已存在的属性（用户可能改过 description/枚举）一律不动；
//	description / agents / enabled 也一律不动。
//	⇒ 既能让新参数到达模型，又不会把用户在 UI 上的编辑冲掉。
func (d *DB) SeedTool(key, desc string, schema, agents json.RawMessage) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled)
VALUES ($1, true, $2, $3, $4, true)
ON CONFLICT (key) DO NOTHING`, key, desc, schema, agents)
	if err != nil {
		return err
	}
	// 已存在的行不会被上面那条覆盖，所以单独补一次缺失参数。
	return d.mergeMissingToolProps(key, schema)
}

// mergeMissingToolProps 把 codeSchema.properties 里【DB 还没有】的键补进 DB。
// 只加不改：任何已存在的属性（含用户编辑）保持原样。
func (d *DB) mergeMissingToolProps(key string, codeSchema json.RawMessage) error {
	var code struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(codeSchema, &code); err != nil || len(code.Properties) == 0 {
		return nil // 代码侧没定义 properties，无事可做
	}

	var raw string
	if err := d.QueryRow(`SELECT schema FROM tools WHERE key=$1 AND system`, key).Scan(&raw); err != nil {
		return nil // 行不存在或读取失败：不阻断启动
	}
	// ★★ 用 map 保留【全部顶层字段】，不能只 unmarshal 到 properties/required ——
	//    那样会把 "type":"object" 之类的字段丢掉，重建出的 schema 就不再是
	//    合法的 function-calling parameters，上游会直接 400/503
	//    （实测：http_probe 丢了 type 后，整个 worker 的请求被网关拒成 11129）。
	cur := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(raw), &cur); err != nil {
		return nil // DB 里的 schema 已损坏：不擅自改写
	}
	curProps := map[string]json.RawMessage{}
	if rawProps, ok := cur["properties"]; ok {
		_ = json.Unmarshal(rawProps, &curProps)
	}
	if curProps == nil {
		curProps = map[string]json.RawMessage{}
	}
	var curReq []string
	if rawReq, ok := cur["required"]; ok {
		_ = json.Unmarshal(rawReq, &curReq)
	}

	added := []string{}
	for k, v := range code.Properties {
		if _, exists := curProps[k]; exists {
			continue // 已存在：保留 DB 版本（可能被用户编辑过）
		}
		curProps[k] = v
		added = append(added, k)
	}
	if len(added) == 0 {
		return nil
	}
	sort.Strings(added)

	// required 只补代码侧声明为必需、而 DB 里没有的
	have := map[string]bool{}
	for _, r := range curReq {
		have[r] = true
	}
	for _, r := range code.Required {
		if !have[r] {
			curReq = append(curReq, r)
			have[r] = true
		}
	}

	pb, err := json.Marshal(curProps)
	if err != nil {
		return nil
	}
	rb, err := json.Marshal(curReq)
	if err != nil {
		return nil
	}
	cur["properties"] = pb
	cur["required"] = rb
	merged, err := json.Marshal(cur)
	if err != nil {
		return nil
	}
	// 保险：只更新 schema 列，绝不动 description/agents/enabled
	_, err = d.Exec(`UPDATE tools SET schema=$1 WHERE key=$2 AND system`, string(merged), key)
	if err != nil {
		return err
	}
	log.Printf("[tools] %s 补齐 %d 个缺失参数: %v", key, len(added), added)
	return nil
}

// AddAgentToToolBinding adds an agent key to the given tools' `agents` arrays if
// not already present (idempotent). Used to give the built-in Auto agent its
// default toolset on existing DBs.
func (d *DB) AddAgentToToolBinding(agentKey string, keys []string) error {
	for _, k := range keys {
		if _, err := d.Exec(`UPDATE tools SET agents = agents || to_jsonb($1::text) WHERE key=$2 AND NOT (agents ? $1)`, agentKey, k); err != nil {
			return err
		}
	}
	return nil
}

// RemoveAgentFromToolBindings strips an agent key from every tool's `agents`
// JSONB array — called when a custom agent is deleted so no tool keeps a dangling
// binding. Uses jsonb `-` (remove array element) guarded by `?` (membership).
func (d *DB) RemoveAgentFromToolBindings(agentKey string) error {
	_, err := d.Exec(`UPDATE tools SET agents = agents - $1 WHERE agents ? $1`, agentKey)
	return err
}

// RemoveAgentFromTool strips one agent key from a SINGLE tool's `agents` array —
// used by one-time migrations that change a tool's default binding on existing DBs
// (SeedTool is first-insert-only, so a changed default never reaches a seeded row).
func (d *DB) RemoveAgentFromTool(agentKey, toolKey string) error {
	_, err := d.Exec(`UPDATE tools SET agents = agents - $1 WHERE key=$2 AND agents ? $1`, agentKey, toolKey)
	return err
}

// UpsertToolForce overwrites a tool row with the given code-default values (used by
// the per-tool "reset" action). It resets description/schema/agents and re-enables
// the tool, but keeps system=true.
func (d *DB) UpsertToolForce(key, desc string, schema, agents json.RawMessage) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled)
VALUES ($1, true, $2, $3, $4, true)
ON CONFLICT (key) DO UPDATE
  SET description = EXCLUDED.description,
      schema      = EXCLUDED.schema,
      agents      = EXCLUDED.agents,
      enabled     = true`, key, desc, schema, agents)
	return err
}

// RefreshToolDefaults updates a system tool's model-facing description + schema to the
// code defaults, PRESERVING the user's agent binding + enabled flag. Used by one-time
// migrations to propagate a code schema change (SeedTool is first-insert-only, so a new
// parameter added in code otherwise never reaches an already-seeded row). No-op for
// custom tools or unknown keys.
func (d *DB) RefreshToolDefaults(key, desc string, schema json.RawMessage) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	_, err := d.Exec(`UPDATE tools SET description=$2, schema=$3, updated_at=now() WHERE key=$1 AND system`, key, desc, schema)
	return err
}

func scanTool(rows interface{ Scan(...any) error }) (*Tool, error) {
	var t Tool
	var agents []byte
	if err := rows.Scan(&t.Key, &t.System, &t.Description, &t.Schema, &agents, &t.Enabled, &t.Kind, &t.Exec, &t.Deferred); err != nil {
		return nil, err
	}
	if len(agents) > 0 {
		_ = json.Unmarshal(agents, &t.Agents)
	}
	if t.Agents == nil {
		t.Agents = []string{}
	}
	return &t, nil
}

// ListTools returns the whole tool catalog, ordered by key.
func (d *DB) ListTools() ([]*Tool, error) {
	rows, err := d.Query(`SELECT ` + toolCols + ` FROM tools ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTool fetches one tool row (nil if absent).
func (d *DB) GetTool(key string) (*Tool, error) {
	row := d.QueryRow(`SELECT `+toolCols+` FROM tools WHERE key=$1`, key)
	t, err := scanTool(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// CreateCustomTool inserts a user-defined tool (system=false) with an execution
// spec. Fails if the key already exists.
func (d *DB) CreateCustomTool(t *Tool) error {
	schema := t.Schema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	exec := t.Exec
	if len(exec) == 0 {
		exec = json.RawMessage("{}")
	}
	agents, _ := json.Marshal(t.Agents)
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
INSERT INTO tools(key, system, description, schema, agents, enabled, kind, exec, deferred)
VALUES ($1, false, $2, $3, $4, $5, $6, $7, $8)`,
		t.Key, t.Description, schema, agents, t.Enabled, t.Kind, exec, t.Deferred)
	return err
}

// UpdateCustomTool updates a custom tool's editable fields (kind/exec/deferred +
// desc/schema/agents/enabled). Only touches system=false rows.
func (d *DB) UpdateCustomTool(t *Tool) error {
	schema := t.Schema
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	exec := t.Exec
	if len(exec) == 0 {
		exec = json.RawMessage("{}")
	}
	agents, _ := json.Marshal(t.Agents)
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
UPDATE tools SET description=$2, schema=$3, agents=$4, enabled=$5, kind=$6, exec=$7, deferred=$8
WHERE key=$1 AND system=false`,
		t.Key, t.Description, schema, agents, t.Enabled, t.Kind, exec, t.Deferred)
	return err
}

// DeleteCustomTool removes a custom tool (system=false only; built-ins protected).
func (d *DB) DeleteCustomTool(key string) error {
	_, err := d.Exec(`DELETE FROM tools WHERE key=$1 AND system=false`, key)
	return err
}

// ListCustomTools returns only the user-defined (system=false) tools.
func (d *DB) ListCustomTools() ([]*Tool, error) {
	rows, err := d.Query(`SELECT ` + toolCols + ` FROM tools WHERE system=false ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tool
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpdateTool saves the page-editable fields. key is never changed (it is welded to
// the Go handler). system tools: the caller must keep the schema structure — only
// per-param description/default and the agent binding are meant to move.
func (d *DB) UpdateTool(key, desc string, schema, agents json.RawMessage, enabled bool) error {
	if len(schema) == 0 {
		schema = json.RawMessage("{}")
	}
	if len(agents) == 0 {
		agents = json.RawMessage("[]")
	}
	_, err := d.Exec(`
UPDATE tools SET description=$2, schema=$3, agents=$4, enabled=$5 WHERE key=$1`,
		key, desc, schema, agents, enabled)
	return err
}
