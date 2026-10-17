package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/artex/db"
)

// ════════════════════════════════════════════════════════════════════════════
// 结构化 HTTP 执行器（上游「首个协议原生通道」）
//
// 存在理由（上游共用实验协议 §观察与计划引用）：
//   「观察明细由受支持执行器先保存，至少包含执行及尝试标识、实际目标、上下文引用、
//     时间、观测渠道和原始记录引用。模型随后生成摘要，不能成为这些字段的唯一来源。」
//
// 它解决的具体问题：在此之前，worker 用 Bash 跑 curl，然后【由模型自己】把 summary/evidence
// 写进 record_fact —— 程序看到的只是模型的措辞，无从判断「这条观察到底用了什么身份、
// 打的什么对象、回了什么」。所以 audit_validity 只能校验「引用是否存在」，
// 无法校验语义。有了本执行器，观察的六要素由程序记录，语义谓词才有依据可查。
//
// 支持（对应上游对首个原生通道的要求）：
//   · 结构化落盘：observation 节点（六要素齐全 + 请求/响应原文）
//   · 会话注入：headers / cookie 由参数给定，落盘时【脱敏】
//   · 对照关联：compare_with 指向另一条 observation，程序自动算差异并可区分性
//   · 动态依赖提取：从响应头/JSON/正则提取值，供后续请求复用
//   · 复用现有证据设施：只用 exploration_nodes，不另建存储
//
// 边界（照实写）：不做浏览器渲染、不自动跟随登录流程、不解析表单；
// 需要 JS 才能观察的效果请用 browser MCP。HTTP 并非天然充分的证据通道。
// ════════════════════════════════════════════════════════════════════════════

const kindObservation = "observation"

// sensitiveHeaderKeys 落盘时要脱敏的请求头（值不落库，只留长度）。
var sensitiveHeaderKeys = []string{"cookie", "authorization", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}

func isSensitiveHeader(k string) bool {
	lk := strings.ToLower(strings.TrimSpace(k))
	for _, s := range sensitiveHeaderKeys {
		if lk == s || strings.Contains(lk, "token") || strings.Contains(lk, "secret") {
			return true
		}
	}
	return false
}

// redactHeaders 脱敏：敏感头的值换成 <redacted:N>，其余原样。
func redactHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		if isSensitiveHeader(k) {
			out[k] = fmt.Sprintf("<redacted:%d chars>", len(v))
		} else {
			out[k] = v
		}
	}
	return out
}

// observationPayload 是一条结构化观察的完整形状（六要素 + 请求响应）。
type observationPayload struct {
	ObsRef      string            `json:"obs_ref"`    // 引用（节点 id 回填后写 <node_id>）
	Attempt     int               `json:"attempt"`    //
	Channel     string            `json:"channel"`    // 观测渠道：http
	ActualURL   string            `json:"actual_url"` // 实际目标（含 query，便于事后复算）
	Target      string            `json:"target"`     // 目标（scheme://host）
	Actor       string            `json:"actor"`      // 上下文：主体（anonymous / session:alice / …）
	Object      string            `json:"object"`     // 上下文：对象引用（item:1 …）
	Purpose     string            `json:"purpose"`    // 上下文：用途
	ReqMethod   string            `json:"req_method"`
	ReqHeaders  map[string]string `json:"req_headers"` // 已脱敏
	ReqBodyLen  int               `json:"req_body_len"`
	RespStatus  int               `json:"resp_status"`
	RespHeaders map[string]string `json:"resp_headers"`
	RespBody    string            `json:"resp_body_excerpt"` // 截断后的响应体
	RespLen     int               `json:"resp_body_len"`
	RespSHA256  string            `json:"resp_body_sha256"`
	ElapsedMS   int64             `json:"elapsed_ms"`
	At          string            `json:"at"` // 时间（RFC3339）
	CompareWith int64             `json:"compare_with,omitempty"`
	CompareSame bool              `json:"compare_identical,omitempty"` // 与对照是否逐字节相同
	CompareNote string            `json:"compare_note,omitempty"`
	Extracted   map[string]string `json:"extracted,omitempty"`  // 动态依赖提取结果
	ModelNote   string            `json:"model_note,omitempty"` // 模型自述（仅供参考，非唯一来源）
	Summary     string            `json:"summary"`
}

// extractRule 动态依赖提取规则。
type extractRule struct {
	Name string `json:"name"` // 提取出的变量名
	From string `json:"from"` // header | json | regex
	Key  string `json:"key"`  // header 名 / JSON 点路径 / 正则
}

// runExtract 执行提取规则。
func runExtract(rules []extractRule, hdr map[string]string, body string) map[string]string {
	if len(rules) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, r := range rules {
		nm := strings.TrimSpace(r.Name)
		if nm == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(r.From)) {
		case "header":
			for k, v := range hdr {
				if strings.EqualFold(k, r.Key) {
					out[nm] = v
					break
				}
			}
		case "json":
			var v any
			if json.Unmarshal([]byte(body), &v) == nil {
				if s, ok := jsonPath(v, r.Key); ok {
					out[nm] = s
				}
			}
		case "regex":
			if re, err := regexp.Compile(r.Key); err == nil {
				if m := re.FindStringSubmatch(body); len(m) > 1 {
					out[nm] = m[1]
				} else if len(m) == 1 {
					out[nm] = m[0]
				}
			}
		}
	}
	return out
}

// jsonPath 支持 "a.b.c" 与 "a.0.b" 的简单点路径。
func jsonPath(v any, path string) (string, bool) {
	cur := v
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		switch t := cur.(type) {
		case map[string]any:
			nv, ok := t[seg]
			if !ok {
				return "", false
			}
			cur = nv
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return "", false
			}
			cur = t[i]
		default:
			return "", false
		}
	}
	switch x := cur.(type) {
	case string:
		return x, true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	case nil:
		return "", true
	default:
		b, _ := json.Marshal(x)
		return string(b), true
	}
}

func excerpt(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + fmt.Sprintf("…(+%d bytes)", len(b)-n)
}

// parseHost 从 URL 取 scheme://host 作为 target。
func parseHost(rawurl string) string {
	u := rawurl
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			return u[:i+3] + rest[:j]
		}
		return u
	}
	return u
}

// httpProbe 是结构化 HTTP 执行器工具。
func (t *ToolSet) httpProbe() actool.CoreTool {
	return t.writeExpTool("http_probe",
		"【结构化 HTTP 执行器】把一次 HTTP 探测由【程序】完整记录下来（请求/响应原文 + 上下文 + 时间 + 渠道），"+
			"返回 observation_id。\n"+
			"★ 为什么必须用它而不是 Bash+curl：程序记录的观察才是【可校验的证据】。\n"+
			"  用 curl 得到的只是你自己写的 summary/evidence，程序无从判断你用了什么身份、打了什么对象、回了什么；\n"+
			"  审计时只能校验「引用是否存在」，无法校验语义。用本工具后，观察的六要素（执行标识/实际目标/"+
			"上下文引用/时间/观测渠道/原始记录引用）由程序落盘，语义谓词才有依据可查。\n"+
			"★ 关键参数：actor（本次用什么身份：anonymous 或 session:xxx）与 object（针对哪个对象，如 item:1）\n"+
			"  —— 这两项决定程序能否判定【会话是否有效】【对象是否存在】。\n"+
			"★ 对照关联：compare_with 填另一条 observation 的 id，程序会自动算两条响应是否可区分。\n"+
			"  「用拥有者验对象存在、再用不存在对象对照」这类判别，就是靠它落成程序可判的证据。\n"+
			"★ 动态依赖提取：extract 可从响应头/JSON/正则取值，供后续请求复用（如登录拿到的 token）。",
		obj(map[string]any{
			"intent_id":    idp("产生本观察的意图 id"),
			"url":          str("完整 URL（含 query）"),
			"method":       str("HTTP 方法；省略=GET"),
			"headers":      map[string]any{"type": "object", "description": "请求头（键值对）。敏感头（Cookie/Authorization 等）落盘时会自动脱敏，只记录长度"},
			"body":         str("请求体（可选）"),
			"actor":        str("★ 本次使用的身份：anonymous（匿名）/ session:<名字>（某个会话/账号）。用于判定会话是否有效，务必如实填"),
			"object":       str("★ 本次针对的对象引用（如 item:1 / file:/etc/passwd / user:42）；不涉及具体对象时留空。用于判定对象是否存在"),
			"purpose":      str("本次探测的用途（如 session-health / object-existence / idor-check）"),
			"compare_with": idp("★ 对照关联：另一条 observation 的 id。程序会算两条响应是否可区分"),
			"extract": map[string]any{"type": "array", "description": "动态依赖提取规则：{name, from(header|json|regex), key}",
				"items": obj(map[string]any{
					"name": str("提取出的变量名"),
					"from": str("header | json | regex"),
					"key":  str("header 名 / JSON 点路径(如 data.token) / 正则"),
				})},
			"note":            str("一句话说明你为什么要发这一发（供人工复核）"),
			"timeout_seconds": intp("超时秒数；省略=15"),
		}, "url", "actor"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IntentID    json.RawMessage   `json:"intent_id"`
				URL         string            `json:"url"`
				Method      string            `json:"method"`
				Headers     map[string]string `json:"headers"`
				Body        string            `json:"body"`
				Actor       string            `json:"actor"`
				Object      string            `json:"object"`
				Purpose     string            `json:"purpose"`
				CompareWith int64             `json:"compare_with"`
				Extract     []extractRule     `json:"extract"`
				Note        string            `json:"note"`
				TimeoutSec  int               `json:"timeout_seconds"`
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.URL) == "" {
				return actool.Errorf("url 必填"), nil
			}
			if !strings.HasPrefix(a.URL, "http://") && !strings.HasPrefix(a.URL, "https://") {
				return actool.Errorf("url 必须带 http:// 或 https:// 前缀（结构化执行器只处理 HTTP 通道）"), nil
			}
			if strings.TrimSpace(a.Actor) == "" {
				return actool.Errorf("actor 必填：本次用什么身份（anonymous 或 session:<名字>）。" +
					"这一项决定程序能否判定会话是否有效，不能省略"), nil
			}
			if a.TimeoutSec <= 0 {
				a.TimeoutSec = 15
			}
			method := strings.ToUpper(strings.TrimSpace(a.Method))
			if method == "" {
				method = "GET"
			}

			// ── ★ 授权范围闸（本地新增）：请求发出【之前】先问一句「这个 host 在授权边界内吗」──
			// 三道闸见 scope_guard.go 文件头。绝对禁止段（云元数据/回环/链路本地/组播/保留）
			// 无论 scope 怎么写都拦下；其余按声明判定。
			guard := t.loadScopeGuard()
			sv := guard.checkURL(a.URL)
			if blocked, verdict := guard.enforce(sv); blocked {
				body, _ := json.MarshalIndent(map[string]any{
					"error":         "目标超出授权范围，请求未发出",
					"scope_verdict": verdict,
					"scope":         guard.summary(),
					"next": "若该目标确在授权范围内：用 add_task_scope 显式加入" +
						"（kind=ip/cidr/subdomain/root_domain，务必填 reason），或调用 " +
						"scope_status(auto_declare=true) 从任务目标文本自动声明。" +
						"绝对禁止段（169.254/16 云元数据、127/8 回环、组播、保留）任何情况下都不放行。",
				}, "", "  ")
				return actool.Errorf(string(body)), nil
			}

			// ── 实际发请求 ──
			var bodyRd io.Reader
			if a.Body != "" {
				bodyRd = strings.NewReader(a.Body)
			}
			reqCtx, cancel := context.WithTimeout(ctx, time.Duration(a.TimeoutSec)*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, method, a.URL, bodyRd)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("构造请求失败：%v", err)), nil
			}
			for k, v := range a.Headers {
				req.Header.Set(k, v)
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "artex-structured-http/1")
			}
			cli := &http.Client{
				Timeout: time.Duration(a.TimeoutSec) * time.Second,
				CheckRedirect: func(r *http.Request, via []*http.Request) error {
					if len(via) >= 10 {
						return fmt.Errorf("重定向次数过多")
					}
					// ★ 每一跳都过范围闸：SSRF 的常见手法就是 302 到云元数据端点，
					// 只在发起时检查会被绕过。
					if blocked, verdict := guard.enforce(guard.checkHost(r.URL.Hostname())); blocked {
						return fmt.Errorf("重定向目标超出授权范围：%s（%s / %s）",
							verdict.Host, verdict.Layer, verdict.Rule)
					}
					return nil
				},
			}
			start := time.Now()
			resp, err := cli.Do(req)
			elapsed := time.Since(start).Milliseconds()
			if err != nil {
				// 传输层失败也要落盘（这本身是一条观察：传输不可达）
				pl := observationPayload{
					Channel: "http", ActualURL: a.URL, Target: parseHost(a.URL),
					Actor: a.Actor, Object: a.Object, Purpose: a.Purpose,
					ReqMethod: method, ReqHeaders: redactHeaders(a.Headers), ReqBodyLen: len(a.Body),
					ElapsedMS: elapsed, At: time.Now().UTC().Format(time.RFC3339),
					ModelNote: a.Note,
					Summary:   fmt.Sprintf("HTTP %s %s → 传输失败(%v) actor=%s", method, a.URL, err, a.Actor),
				}
				id, werr := t.ts.AddNode(kindObservation, mustMap(pl), 0, "confirmed", t.worker, nil)
				if werr != nil {
					return actool.Errorf(fmt.Sprintf("请求失败且观察落盘失败：%v / %v", err, werr)), nil
				}
				_ = t.ts.Link(pid(a.IntentID), db.RelYields, id)
				return jsonResult(map[string]any{
					"observation_id": id, "ok": false, "error": err.Error(),
					"transport": "failed",
					"note":      "传输失败已作为一条观察落盘（它不能支撑任何『不存在漏洞』的结论）。",
				})
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 上限 1MiB
			sum := sha256.Sum256(raw)
			respHeaders := map[string]string{}
			for k, v := range resp.Header {
				respHeaders[k] = strings.Join(v, ", ")
			}

			pl := observationPayload{
				Channel: "http", ActualURL: a.URL, Target: parseHost(a.URL),
				Actor: a.Actor, Object: a.Object, Purpose: a.Purpose,
				ReqMethod: method, ReqHeaders: redactHeaders(a.Headers), ReqBodyLen: len(a.Body),
				RespStatus: resp.StatusCode, RespHeaders: respHeaders,
				RespBody: excerpt(raw, 2000), RespLen: len(raw), RespSHA256: hex.EncodeToString(sum[:]),
				ElapsedMS: elapsed, At: time.Now().UTC().Format(time.RFC3339),
				Extracted: runExtract(a.Extract, respHeaders, string(raw)),
				ModelNote: a.Note,
			}
			pl.Summary = fmt.Sprintf("HTTP %s %s → %d (%d bytes, %dms) actor=%s object=%s",
				method, a.URL, resp.StatusCode, len(raw), elapsed, a.Actor, orDash(a.Object))

			// ── 对照关联：程序自动算可区分性（这是 session.valid / object.exists 的语义依据）──
			if a.CompareWith > 0 {
				pl.CompareWith = a.CompareWith
				if prev, err := t.loadObservation(a.CompareWith); err != nil || prev == nil {
					pl.CompareNote = fmt.Sprintf("对照 observation %d 不存在，无法比较", a.CompareWith)
				} else {
					same := prev.RespStatus == pl.RespStatus && prev.RespSHA256 == pl.RespSHA256
					pl.CompareSame = same
					diff := []string{}
					if prev.RespStatus != pl.RespStatus {
						diff = append(diff, fmt.Sprintf("状态码 %d≠%d", prev.RespStatus, pl.RespStatus))
					}
					if prev.RespSHA256 != pl.RespSHA256 {
						diff = append(diff, fmt.Sprintf("响应体不同(长度 %d≠%d)", prev.RespLen, pl.RespLen))
					}
					if prev.Actor != pl.Actor {
						diff = append(diff, fmt.Sprintf("主体 %s≠%s", prev.Actor, pl.Actor))
					}
					if prev.Object != pl.Object {
						diff = append(diff, fmt.Sprintf("对象 %s≠%s", orDash(prev.Object), orDash(pl.Object)))
					}
					if len(diff) == 0 {
						pl.CompareNote = fmt.Sprintf("与对照 observation %d 【逐字节相同且上下文一致】"+
							"⇒ 本次探测无法区分任何差异（不能据此判定任何一方成立）", a.CompareWith)
					} else {
						pl.CompareNote = fmt.Sprintf("与对照 observation %d 可区分：%s", a.CompareWith, strings.Join(diff, "；"))
					}
				}
			}

			id, err := t.ts.AddNode(kindObservation, mustMap(pl), 0, "confirmed", t.worker, nil)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("观察落盘失败：%v", err)), nil
			}
			pl.ObsRef = strconv.FormatInt(id, 10) // 引用即节点 id（不回填空，避免额外写库）
			_ = t.ts.Link(pid(a.IntentID), db.RelYields, id)

			out := map[string]any{
				"observation_id": id,
				"ok":             resp.StatusCode < 400,
				"status":         resp.StatusCode,
				"elapsed_ms":     elapsed,
				"body_len":       len(raw),
				"body_excerpt":   excerpt(raw, 800),
				"resp_headers":   respHeaders,
				"context": map[string]any{
					"target": pl.Target, "actor": pl.Actor, "object": pl.Object, "purpose": pl.Purpose,
				},
				"channel": "http",
				"at":      pl.At,
				"how_to_use": "把 observation_id 作为 audit_validity 里对应层的 evidence_ref。" +
					"程序会按【结构化观察】核对本层的语义（例如 session.valid 需要一条非匿名主体、" +
					"且与对照可区分的观察），比只给节点 id 严格得多。",
			}
			if len(pl.Extracted) > 0 {
				out["extracted"] = pl.Extracted
			}
			if pl.CompareWith > 0 {
				out["compare"] = map[string]any{
					"with": pl.CompareWith, "identical": pl.CompareSame, "note": pl.CompareNote,
				}
			}
			return jsonResult(out)
		})
}

// loadObservation 读一条结构化观察。
func (t *ToolSet) loadObservation(id int64) (*observationPayload, error) {
	n, err := t.ts.GetNodeWithSources(id)
	if err != nil || n == nil || n.Kind != kindObservation {
		return nil, fmt.Errorf("不是 observation 节点")
	}
	var pl observationPayload
	if err := json.Unmarshal(n.Payload, &pl); err != nil {
		return nil, err
	}
	return &pl, nil
}

func mustMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
