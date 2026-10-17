package agent

import (
	"context"
	_ "embed" // []byte + //go:embed 需要匿名导入
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// ════════════════════════════════════════════════════════════════════════════
// 蜜罐静态指纹识别（honeydetect）—— 本地新增 2026-10-17
//
// 解决什么：R05 的五层有效性是「传输 / 身份 / 业务基线 / 观察能力 / 方法适用性」，
// 但它们都默认【这一层测的对象是真的】。若目标是蜜罐，那么「未复现」这个结论
// 是对一张假图的判断 —— 比「证据不足」更糟：后者只是结论弱，前者是结论错。
//
// ★★ 本实现的诚实边界（必须连同输出一起给，不能只给分数）：
//   ① 签名库来自第三方二改项目 D4rk-3ch0/artex-c，本仓库【未能独立核实】任何一条：
//      核实当轮 raw.githubusercontent.com 不可达，cowrie/opencanary 官方默认配置取不到。
//      故每条签名带 verified=false + verify_note，输出里也标注 authority 等级。
//   ② 只覆盖「用开源蜜罐【默认配置】」的目标。专有蜜罐、改过默认值的蜜罐没有公开指纹
//      —— 本层【查不出来不代表不是蜜罐】。
//   ③ 只在【被动观察】上工作：不发探测包、不扫端口。它回答的是
//      「我手头这些字段像不像某个已知蜜罐的默认值」，不是「这是不是蜜罐」。
//   ④ 故本层【不接入写回门的强制判定】—— 阈值未经实测校准就拿来拦结论属于拍脑袋。
//      它产出线索，由人或模型结合其它证据判断。
//
// ★ 设计上抄了 artex-c 的三条硬约束（与本仓库守则同源，值得留）：
//   · 签名必须带 source，没有出处的签名不收录
//   · 一个条件都没有的签名【永不命中】（防「无条件签名匹配一切」）
//   · 多条件 AND（不是 OR），降低误报
// ════════════════════════════════════════════════════════════════════════════

//go:embed honeydetect_signatures.json
var embeddedHoneypotSignatures []byte

type honeypotMatch struct {
	Port              *int   `json:"port,omitempty"`
	BannerSubstr      string `json:"banner_substr,omitempty"`
	HTTPTitleSubstr   string `json:"http_title_substr,omitempty"`
	HTTPBodySubstr    string `json:"http_body_substr,omitempty"`
	CertSubjectSubstr string `json:"cert_subject_substr,omitempty"`
	CertIssuerSubstr  string `json:"cert_issuer_substr,omitempty"`
}

type honeypotSignature struct {
	Name       string        `json:"name"`
	Product    string        `json:"product"`
	Confidence float64       `json:"confidence"`
	Source     string        `json:"source"`
	Verified   bool          `json:"verified"`
	VerifyNote string        `json:"verify_note,omitempty"`
	Match      honeypotMatch `json:"match"`
}

type serviceView struct {
	Port        int    `json:"port"`
	Banner      string `json:"banner"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	CertSubject string `json:"cert_subject"`
	CertIssuer  string `json:"cert_issuer"`
}

func hpContains(haystack, needle string) bool {
	return haystack != "" && strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

// matches 是【多条件 AND】：任一条件不满足即 false。
// ★ 一个条件都没有的签名永不命中。
func (m honeypotMatch) matches(v serviceView) bool {
	any := false
	if m.Port != nil {
		any = true
		if v.Port != *m.Port {
			return false
		}
	}
	if m.BannerSubstr != "" {
		any = true
		if !hpContains(v.Banner, m.BannerSubstr) {
			return false
		}
	}
	if m.HTTPTitleSubstr != "" {
		any = true
		if !hpContains(v.Title, m.HTTPTitleSubstr) {
			return false
		}
	}
	if m.HTTPBodySubstr != "" {
		any = true
		if !hpContains(v.Body, m.HTTPBodySubstr) {
			return false
		}
	}
	if m.CertSubjectSubstr != "" {
		any = true
		if !hpContains(v.CertSubject, m.CertSubjectSubstr) {
			return false
		}
	}
	if m.CertIssuerSubstr != "" {
		any = true
		if !hpContains(v.CertIssuer, m.CertIssuerSubstr) {
			return false
		}
	}
	return any
}

type honeypotEngine struct {
	mu      sync.RWMutex
	path    string
	modTime time.Time
	sigs    []honeypotSignature
}

func newHoneypotEngine(path string) *honeypotEngine { return &honeypotEngine{path: path} }

func parseHoneypotSignatures(data []byte) []honeypotSignature {
	if len(data) == 0 {
		return nil
	}
	var f struct {
		Signatures []honeypotSignature `json:"signatures"`
	}
	if json.Unmarshal(data, &f) != nil {
		return nil
	}
	return f.Signatures
}

// signatures 返回当前生效签名：外部文件存在则按 mtime 热更新；缺失/损坏回落内嵌库。
func (e *honeypotEngine) signatures() []honeypotSignature {
	fi, err := os.Stat(e.path)
	if err != nil {
		e.mu.Lock()
		if e.sigs == nil {
			e.sigs = parseHoneypotSignatures(embeddedHoneypotSignatures)
		}
		sigs := e.sigs
		e.mu.Unlock()
		return sigs
	}
	e.mu.RLock()
	if fi.ModTime().Equal(e.modTime) && e.sigs != nil {
		sigs := e.sigs
		e.mu.RUnlock()
		return sigs
	}
	e.mu.RUnlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	var raw []byte
	if b, err := os.ReadFile(e.path); err == nil {
		raw = b
	}
	sigs := parseHoneypotSignatures(raw)
	if sigs == nil {
		sigs = parseHoneypotSignatures(embeddedHoneypotSignatures)
	}
	e.sigs, e.modTime = sigs, fi.ModTime()
	return e.sigs
}

type honeypotHit struct {
	Name       string  `json:"name"`
	Product    string  `json:"product"`
	Confidence float64 `json:"confidence"`
	Verified   bool    `json:"verified"`
	Source     string  `json:"source"`
}

func (e *honeypotEngine) evaluate(v serviceView) (float64, []honeypotHit) {
	var best float64
	var hits []honeypotHit
	for _, s := range e.signatures() {
		if s.Confidence <= 0 || !s.Match.matches(v) {
			continue
		}
		hits = append(hits, honeypotHit{
			Name: s.Name, Product: s.Product, Confidence: s.Confidence,
			Verified: s.Verified, Source: s.Source,
		})
		if s.Confidence > best {
			best = s.Confidence
		}
	}
	return best, hits
}

var (
	honeypotOnce   sync.Once
	honeypotGlobal *honeypotEngine
)

// honeypotDataDir 取数据目录：ARTEX_DATA_DIR 优先，否则 /app/data（容器布局）。
func honeypotDataDir() string {
	if d := strings.TrimSpace(os.Getenv("ARTEX_DATA_DIR")); d != "" {
		return d
	}
	return "/app/data"
}

func honeypotEngineInstance() *honeypotEngine {
	honeypotOnce.Do(func() {
		honeypotGlobal = newHoneypotEngine(filepath.Join(honeypotDataDir(), "signatures", "honeypot.json"))
	})
	return honeypotGlobal
}

// honeypotCheck 是工具本体。优先用 observation_id（已有 http_probe 的结构化观察），
// 自动提取 Server 头/响应体/标题；也允许显式传字段覆盖。
func (t *ToolSet) honeypotCheck() actool.CoreTool {
	return t.readExpTool("honeypot_check",
		"【蜜罐指纹检查】判断手头的观察字段像不像某个【已知开源蜜罐的默认值】。\n"+
			"★ 为什么有这一层：R05 的五层有效性（传输/身份/业务基线/观察能力/方法适用性）"+
			"都默认「这一层测的对象是真的」。若目标是蜜罐，「未复现」这个结论就是对一张假图的判断"+
			"—— 比「证据不足」更糟。\n"+
			"★ 但它【只是线索，不是判定】：\n"+
			"  · 签名库来自第三方，本机【未独立核实】任何一条（见返回的 unverified_hits 与 verified 字段）\n"+
			"  · 只覆盖「用开源蜜罐默认配置」的目标；专有蜜罐/改过默认值的一律查不出\n"+
			"  · 查不出来【不代表不是蜜罐】；查出来也【不代表一定是】（真实服务可能恰好用同一默认值）\n"+
			"★ 用法：给 observation_id（自动取 Server 头/响应体/标题），或手填 banner/title/body 等。",
		obj(map[string]any{
			"observation_id": idp("★ 优先用这个：http_probe 落盘的观察 id，自动提取 Server 头与响应体"),
			"port":           intp("服务端口（可选；某些签名要求端口匹配，如 HFish 的 8080）"),
			"banner":         str("协议 banner / HTTP Server 头（可选，覆盖观察里的值）"),
			"title":          str("HTTP <title>（可选）"),
			"body":           str("HTTP 正文或片段（可选，覆盖观察里的值）"),
			"cert_subject":   str("TLS 证书 subject（可选）"),
			"cert_issuer":    str("TLS 证书 issuer（可选）"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				ObservationID int64  `json:"observation_id"`
				Port          int    `json:"port"`
				Banner        string `json:"banner"`
				Title         string `json:"title"`
				Body          string `json:"body"`
				CertSubject   string `json:"cert_subject"`
				CertIssuer    string `json:"cert_issuer"`
			}
			_ = json.Unmarshal(in, &a)

			v := serviceView{
				Port: a.Port, Banner: a.Banner, Title: a.Title,
				Body: a.Body, CertSubject: a.CertSubject, CertIssuer: a.CertIssuer,
			}
			fromObs := false
			if a.ObservationID > 0 {
				o, err := t.loadObservation(a.ObservationID)
				if err != nil || o == nil {
					return actool.Errorf(fmt.Sprintf("observation %d 不存在或不是 http_probe 的观察：%v",
						a.ObservationID, err)), nil
				}
				fromObs = true
				if v.Banner == "" {
					for k, val := range o.RespHeaders {
						if strings.EqualFold(k, "Server") {
							v.Banner = val
						}
					}
				}
				if v.Body == "" {
					v.Body = o.RespBody
				}
				if v.Title == "" {
					lb := strings.ToLower(v.Body)
					if s := strings.Index(lb, "<title>"); s >= 0 {
						rest := v.Body[s+7:]
						if e := strings.Index(strings.ToLower(rest), "</title>"); e >= 0 {
							v.Title = strings.TrimSpace(rest[:e])
						}
					}
				}
			}

			score, hits := honeypotEngineInstance().evaluate(v)

			out := map[string]any{
				"score":         score,
				"hits":          hits,
				"hit_count":     len(hits),
				"signature_set": "artex.honeypot",
				"signature_ver": 1,
				"view_used": map[string]any{
					"port": v.Port, "banner": v.Banner, "title": v.Title,
					"body_len": len(v.Body), "cert_subject": v.CertSubject,
					"cert_issuer": v.CertIssuer, "from_observation": fromObs,
				},
				"authority": "★ 线索，非判定。签名库来自第三方二改项目，本机【未独立核实】任何一条；" +
					"只覆盖开源蜜罐默认配置；查不出不代表不是蜜罐，查出也不代表一定是。",
			}
			var unverified int
			for _, h := range hits {
				if !h.Verified {
					unverified++
				}
			}
			out["unverified_hits"] = unverified

			switch {
			case len(hits) == 0:
				out["verdict"] = "no_signature_hit"
				out["next"] = "未命中任何已知开源蜜罐默认指纹。这不构成「目标为真」的证据 —— " +
					"专有蜜罐与改过默认值的蜜罐没有公开指纹。"
			case unverified == len(hits):
				out["verdict"] = "hit_unverified"
				out["next"] = "命中了签名，但本机未独立核实该签名。请以「线索」对待，不要单独据此下结论；" +
					"要提升可信度，需与被判蜜罐的官方默认配置逐字比对。"
			default:
				out["verdict"] = "hit"
				out["next"] = "命中且至少有已核实签名。仍建议与官方默认配置逐字比对后再下结论。"
			}
			return jsonResult(out)
		})
}
