package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = db.AuthPasswordKey
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// authClaims binds a session to the current credential without exposing its hash.
type authClaims struct {
	Credential string `json:"cv"`
	jwt.RegisteredClaims
}

func credentialBinding(key []byte, hash string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("ARTEX credential binding\x00"))
	mac.Write([]byte(hash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signJWT(key []byte, hash string) (string, error) {
	if hash == "" {
		return "", fmt.Errorf("password not initialized")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, authClaims{
		Credential:       credentialBinding(key, hash),
		RegisteredClaims: jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)), IssuedAt: jwt.NewNumericDate(time.Now())},
	}).SignedString(key)
}

func parseAuthJWT(token string, key []byte) (*authClaims, error) {
	claims := &authClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired(), jwt.WithSubject("ARTEX"), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid || claims.Credential == "" {
		return nil, fmt.Errorf("invalid session")
	}
	return claims, nil
}

func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

type authCredentialContextKey struct{}

func (s *Server) readAuthPassword(r *http.Request) (string, error) {
	if s.m == nil || s.m.pg == nil {
		return "", fmt.Errorf("data source unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	return s.m.pg.AuthPassword(ctx)
}

func (s *Server) authenticatedHash(w http.ResponseWriter, r *http.Request) (string, int) {
	if hash, ok := r.Context().Value(authCredentialContextKey{}).(string); ok {
		return hash, 0
	}
	claims, err := parseAuthJWT(extractToken(r), s.jwtKey)
	if err != nil {
		writeErr(w, 401, "token 无效或已过期，请重新登录")
		return "", 401
	}
	hash, err := s.readAuthPassword(r)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return "", 503
	}
	if hash == "" || !hmac.Equal([]byte(claims.Credential), []byte(credentialBinding(s.jwtKey, hash))) {
		writeErr(w, 401, "登录凭证已失效，请重新登录")
		return "", 401
	}
	return hash, 0
}

func (s *Server) auditSessionFailure(r *http.Request, status int) {
	if status == 503 {
		s.auditAuth(r, "password_change", "unavailable", "data_source")
		return
	}
	s.auditAuth(r, "password_change", "rejected", "invalid_session")
}

func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/status", "/api/auth/init", "/api/auth/login", "/api/health":
			h.ServeHTTP(w, r)
			return
		}
		hash, status := s.authenticatedHash(w, r)
		if status != 0 {
			if r.URL.Path == "/api/auth/change-password" {
				s.auditSessionFailure(r, status)
			}
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer s.authenticationGuard().registerSession(hash, cancel)()
		r = r.WithContext(context.WithValue(ctx, authCredentialContextKey{}, hash))
		// Short requests exit immediately. Long-lived streams also observe resets
		// made by another instance or the operator's password recovery script.
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := parseAuthJWT(extractToken(r), s.jwtKey); err != nil {
						cancel()
						return
					}
					current, err := s.readAuthPassword(r)
					if err != nil || current != hash {
						cancel()
						return
					}
				}
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func decodeAuth(w http.ResponseWriter, r *http.Request, into any) error {
	controller := http.NewResponseController(w)
	decoded := false
	defer func() {
		if decoded {
			_ = controller.SetReadDeadline(time.Time{})
			return
		}
		// Do not drain an incomplete body without a deadline for keep-alive.
		r.Close = true
		w.Header().Set("Connection", "close")
	}()
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid request")
	}
	decoded = true
	return nil
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	hash, err := s.readAuthPassword(r)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	done, ok := s.admitAuth(w, r, "initialize")
	if !ok {
		return
	}
	defer done()
	existing, err := s.readAuthPassword(r)
	if err != nil {
		s.auditAuth(r, "initialize", "unavailable", "data_source")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		s.auditAuth(r, "initialize", "rejected", "already_initialized")
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if decodeAuth(w, r, &req) != nil {
		s.auditAuth(r, "initialize", "rejected", "invalid_request")
		writeErr(w, 400, "请求格式错误")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		s.auditAuth(r, "initialize", "rejected", "invalid_password")
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.auditAuth(r, "initialize", "unavailable", "hashing_failed")
		writeErr(w, 500, "密码加密失败")
		return
	}
	event := db.AuthAuditEvent{Action: "initialize", ClientIP: authClientIP(r)}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	inserted, err := s.m.pg.WriteAuthPassword(ctx, nil, string(hash), &event)
	if err != nil {
		s.auditAuth(r, "initialize", "unavailable", "storage_failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	logAuthEvent(event)
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	token, err := signJWT(s.jwtKey, string(hash))
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": token})
}

func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	done, ok := s.admitAuth(w, r, "password_change")
	if !ok {
		return
	}
	defer done()
	hash, status := s.authenticatedHash(w, r)
	if status != 0 {
		s.auditSessionFailure(r, status)
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if decodeAuth(w, r, &req) != nil {
		s.auditAuth(r, "password_change", "rejected", "invalid_request")
		writeErr(w, 400, "请求格式错误")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		s.auditAuth(r, "password_change", "rejected", "invalid_password")
		writeErr(w, 400, msg)
		return
	}
	if len(req.OldPassword) > maxPasswordBytes || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)) != nil {
		event := db.AuthAuditEvent{Action: "password_change", ClientIP: authClientIP(r)}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_, locked, err := s.m.pg.FinishAuthLogin(ctx, hash, false, &event)
		if err != nil {
			s.auditAuth(r, "password_change", "unavailable", "storage_failed")
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		logAuthEvent(event)
		if locked > 0 {
			authRetry(w, locked, "登录暂时锁定，请稍后重试")
			return
		}
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	event := db.AuthAuditEvent{Action: "password_change", ClientIP: authClientIP(r)}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	changed, err := s.m.pg.WriteAuthPassword(ctx, &hash, string(newHash), &event)
	if err != nil {
		s.auditAuth(r, "password_change", "unavailable", "storage_failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	logAuthEvent(event)
	if !changed {
		writeErr(w, 409, "密码已变化，请重新登录后重试")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
	s.authenticationGuard().revokeSessions(string(newHash))
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	done, ok := s.admitAuth(w, r, "login")
	if !ok {
		return
	}
	defer done()
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeAuth(w, r, &req) != nil {
		s.auditAuth(r, "login", "rejected", "invalid_request")
		writeErr(w, 400, "请求格式错误")
		return
	}
	hash, err := s.readAuthPassword(r)
	if err != nil {
		s.auditAuth(r, "login", "unavailable", "data_source")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if hash == "" {
		s.auditAuth(r, "login", "rejected", "not_initialized")
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	locked, err := s.m.pg.AuthLockRemaining(ctx, hash)
	if err != nil {
		s.auditAuth(r, "login", "unavailable", "data_source")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if locked > 0 {
		s.auditAuth(r, "login", "rejected", "account_locked")
		authRetry(w, locked, "登录暂时锁定，请稍后重试")
		return
	}
	valid := req.Username == "ARTEX" && len(req.Password) <= maxPasswordBytes && bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) == nil
	event := db.AuthAuditEvent{Action: "login", ClientIP: authClientIP(r)}
	allowed, locked, err := s.m.pg.FinishAuthLogin(ctx, hash, valid, &event)
	if err != nil {
		s.auditAuth(r, "login", "unavailable", "storage_failed")
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	logAuthEvent(event)
	if locked > 0 {
		authRetry(w, locked, "登录暂时锁定，请稍后重试")
		return
	}
	if !allowed {
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	token, err := signJWT(s.jwtKey, hash)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": token})
}
