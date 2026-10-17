package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthSlowBodyReleasesAuthenticationSlots(t *testing.T) {
	s, _ := securityAuthFixture(t)
	server := httptest.NewServer(securityAuthMux(s))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	connections := make([]net.Conn, 0, 4)
	defer func() {
		for _, conn := range connections {
			conn.Close()
		}
	}()
	for range 4 {
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		fmt.Fprintf(conn, "POST /api/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n")
	}
	for _, conn := range connections {
		conn.SetReadDeadline(time.Now().Add(7 * time.Second))
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("slow request did not time out and release its slot: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatalf("slow body status=%d", response.StatusCode)
		}
	}
	body := strings.NewReader(`{"username":"ARTEX","password":"FixturePassword!123"}`)
	response, err := server.Client().Post(server.URL+"/api/auth/login", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("authentication slots remained blocked: %d", response.StatusCode)
	}
}

func securityAuthFixture(t *testing.T) (*Server, string) {
	t.Helper()
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skip("test PostgreSQL not configured")
	}
	base, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("auth_test_%d", time.Now().UnixNano())
	if _, err = base.Exec(`CREATE SCHEMA ` + schema); err != nil {
		base.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pg, err := db.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close(); base.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); base.Close() })
	hash, err := bcrypt.GenerateFromPassword([]byte("FixturePassword!123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	event := db.AuthAuditEvent{Action: "initialize", ClientIP: "127.0.0.1"}
	if _, err := pg.WriteAuthPassword(t.Context(), nil, string(hash), &event); err != nil {
		t.Fatal(err)
	}
	return &Server{m: &Manager{pg: pg}, jwtKey: []byte("fixture-signing-key-32-bytes-only!")}, string(hash)
}

func securityAuthMux(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("GET /api/protected", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	return s.requireAuth(mux)
}

func securityAuthCall(h http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, strings.NewReader(string(raw)))
	if body == nil {
		req = httptest.NewRequest("GET", path, nil)
	}
	req.RemoteAddr = "192.0.2.10:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAuthCredentialChangeRevokesAllTokenTransports(t *testing.T) {
	s, hash := securityAuthFixture(t)
	h := securityAuthMux(s)
	token, err := signJWT(s.jwtKey, hash)
	if err != nil {
		t.Fatal(err)
	}
	other := &Server{m: s.m, jwtKey: s.jwtKey}
	w := securityAuthCall(h, "/api/auth/change-password", map[string]string{"old_password": "FixturePassword!123", "new_password": "ReplacementPassword!123"}, token)
	if w.Code != 200 {
		t.Fatalf("change status=%d", w.Code)
	}
	for _, instance := range []*Server{s, other} {
		for _, transport := range []string{"header", "cookie", "query"} {
			req := httptest.NewRequest("GET", "/api/protected", nil)
			switch transport {
			case "header":
				req.Header.Set("Authorization", "Bearer "+token)
			case "cookie":
				req.AddCookie(&http.Cookie{Name: "artex_token", Value: token})
			case "query":
				req.URL.RawQuery = url.Values{"token": {token}}.Encode()
			}
			out := httptest.NewRecorder()
			securityAuthMux(instance).ServeHTTP(out, req)
			if out.Code != 401 {
				t.Fatalf("old session accepted using %s: %d", transport, out.Code)
			}
		}
	}
	login := securityAuthCall(h, "/api/auth/login", map[string]string{"username": "ARTEX", "password": "ReplacementPassword!123"}, "")
	if login.Code != 200 {
		t.Fatalf("new login status=%d", login.Code)
	}
	var data struct {
		Token string `json:"token"`
	}
	json.Unmarshal(login.Body.Bytes(), &data)
	if out := securityAuthCall(securityAuthMux(other), "/api/protected", nil, data.Token); out.Code != 204 {
		t.Fatalf("new session status=%d", out.Code)
	}
}

func TestAuthStrictJWTAndFailClosedValidation(t *testing.T) {
	s, hash := securityAuthFixture(t)
	h := securityAuthMux(s)
	for _, tc := range []struct {
		name   string
		method jwt.SigningMethod
		claims jwt.MapClaims
	}{
		{"legacy", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ARTEX", "exp": time.Now().Add(time.Hour).Unix()}},
		{"no_expiry", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "ARTEX", "cv": credentialBinding(s.jwtKey, hash)}},
		{"wrong_subject", jwt.SigningMethodHS256, jwt.MapClaims{"sub": "other", "exp": time.Now().Add(time.Hour).Unix(), "cv": credentialBinding(s.jwtKey, hash)}},
		{"wrong_algorithm", jwt.SigningMethodHS384, jwt.MapClaims{"sub": "ARTEX", "exp": time.Now().Add(time.Hour).Unix(), "cv": credentialBinding(s.jwtKey, hash)}},
	} {
		token, err := jwt.NewWithClaims(tc.method, tc.claims).SignedString(s.jwtKey)
		if err != nil {
			t.Fatal(err)
		}
		if out := securityAuthCall(h, "/api/protected", nil, token); out.Code != 401 {
			t.Fatalf("%s status=%d", tc.name, out.Code)
		}
	}
	token, _ := signJWT(s.jwtKey, hash)
	s.m.pg.Close()
	if out := securityAuthCall(h, "/api/protected", nil, token); out.Code != 503 {
		t.Fatalf("closed database status=%d", out.Code)
	}
}

func TestAuthLockPersistsAcrossInstancesAndExpires(t *testing.T) {
	s, hash := securityAuthFixture(t)
	for i := 0; i < db.AuthFailureLimit; i++ {
		out := securityAuthCall(securityAuthMux(s), "/api/auth/login", map[string]string{"username": "ARTEX", "password": "WrongFixturePassword!"}, "")
		want := 401
		if i == db.AuthFailureLimit-1 {
			want = 429
		}
		if out.Code != want {
			t.Fatalf("attempt %d status=%d want=%d", i, out.Code, want)
		}
	}
	restarted := &Server{m: s.m, jwtKey: s.jwtKey}
	out := securityAuthCall(securityAuthMux(restarted), "/api/auth/login", map[string]string{"username": "ARTEX", "password": "FixturePassword!123"}, "")
	if out.Code != 429 || out.Header().Get("Retry-After") == "" {
		t.Fatalf("lock not persisted: %d", out.Code)
	}
	// A failure window ending must not shorten an already-active account lock.
	s.m.pg.Exec(`UPDATE auth_login_state SET window_started_at=now()-interval '16 minutes'`)
	event := db.AuthAuditEvent{Action: "login", ClientIP: "192.0.2.10"}
	allowed, remaining, err := s.m.pg.FinishAuthLogin(t.Context(), hash, true, &event)
	if err != nil || allowed || remaining <= 0 {
		t.Fatalf("active lock bypass: allowed=%v remaining=%v err=%v", allowed, remaining, err)
	}
	s.m.pg.Exec(`UPDATE auth_login_state SET locked_until=now()-interval '1 second'`)
	out = securityAuthCall(securityAuthMux(restarted), "/api/auth/login", map[string]string{"username": "ARTEX", "password": "FixturePassword!123"}, "")
	if out.Code != 200 {
		t.Fatalf("expired lock status=%d", out.Code)
	}
}

func TestAuthConcurrentFailuresCannotLoseCounterUpdates(t *testing.T) {
	s, hash := securityAuthFixture(t)
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event := db.AuthAuditEvent{Action: "login", ClientIP: "192.0.2.10"}
			_, _, err := s.m.pg.FinishAuthLogin(t.Context(), hash, false, &event)
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	var failures int
	if err := s.m.pg.QueryRow(`SELECT failures FROM auth_login_state WHERE id=1`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != db.AuthFailureLimit {
		t.Fatalf("counter=%d", failures)
	}
}

func TestAuthAuditIsAtomicAndContainsNoCredentials(t *testing.T) {
	s, hash := securityAuthFixture(t)
	h := securityAuthMux(s)
	token, _ := signJWT(s.jwtKey, hash)
	out := securityAuthCall(h, "/api/auth/login", map[string]string{"username": "untrusted-account-marker\nforged", "password": "WrongFixturePassword!"}, "")
	if out.Code != 401 {
		t.Fatal(out.Code)
	}
	var audit string
	if err := s.m.pg.QueryRow(`SELECT json_agg(a)::text FROM auth_audit_log a`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{hash, token, "WrongFixturePassword!", "untrusted-account-marker"} {
		if strings.Contains(audit, secret) {
			t.Fatal("credential or untrusted input present in audit")
		}
	}
	if !strings.Contains(audit, "192.0.2.10") || !strings.Contains(audit, "invalid_credentials") {
		t.Fatal("audit metadata missing")
	}
	_, err := s.m.pg.Exec(`CREATE FUNCTION reject_auth_audit() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit fixture failure'; END $$ LANGUAGE plpgsql; CREATE TRIGGER reject_audit BEFORE INSERT ON auth_audit_log FOR EACH ROW EXECUTE FUNCTION reject_auth_audit()`)
	if err != nil {
		t.Fatal(err)
	}
	out = securityAuthCall(h, "/api/auth/change-password", map[string]string{"old_password": "FixturePassword!123", "new_password": "ReplacementPassword!123"}, token)
	if out.Code != 503 {
		t.Fatalf("audit failure status=%d", out.Code)
	}
	current, err := s.m.pg.AuthPassword(t.Context())
	if err != nil || current != hash {
		t.Fatal("password write did not roll back with failed audit")
	}
}

func TestAuthRateLimitsAndForwardingHeaders(t *testing.T) {
	s := &Server{}
	g := s.authenticationGuard()
	now := time.Now()
	g.now = func() time.Time { return now }
	for range authPerIPLimit {
		_, _, ok := g.enter("192.0.2.1")
		if !ok {
			t.Fatal("premature limit")
		}
		<-g.slots
	}
	retry, _, ok := g.enter("192.0.2.1")
	if ok || retry <= 0 {
		t.Fatal("source limit absent")
	}
	for i := 0; i < authGlobalLimit-authPerIPLimit; i++ {
		_, _, ok := g.enter(fmt.Sprintf("192.0.2.%d", i+2))
		if !ok {
			t.Fatal("premature global limit")
		}
		<-g.slots
	}
	if _, _, ok := g.enter("198.51.100.1"); ok {
		t.Fatal("global limit absent")
	}
	now = now.Add(authWindow)
	for range 4 {
		if _, _, ok := g.enter("192.0.2.1"); !ok {
			t.Fatal("slots unavailable")
		}
	}
	if _, _, ok := g.enter("192.0.2.1"); ok {
		t.Fatal("bcrypt concurrency limit absent")
	}
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	req.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.2")
	if got := authClientIP(req); got != "192.0.2.1" {
		t.Fatalf("untrusted forwarding header used: %s", got)
	}
}

func TestAuthPasswordChangeClosesActiveRequests(t *testing.T) {
	s, hash := securityAuthFixture(t)
	token, _ := signJWT(s.jwtKey, hash)
	entered, closed := make(chan struct{}), make(chan struct{})
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(closed) }))
	go securityAuthCall(h, "/api/protected", nil, token)
	<-entered
	out := securityAuthCall(securityAuthMux(s), "/api/auth/change-password", map[string]string{"old_password": "FixturePassword!123", "new_password": "ReplacementPassword!123"}, token)
	if out.Code != 200 {
		t.Fatal(out.Code)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("active request not revoked")
	}
	// Recovery writes from another instance invalidate sessions as well.
	current, _ := s.m.pg.AuthPassword(t.Context())
	token, _ = signJWT(s.jwtKey, current)
	entered, closed = make(chan struct{}), make(chan struct{})
	go securityAuthCall(h, "/api/protected", nil, token)
	<-entered
	if err := s.m.pg.SetSetting(db.AuthPasswordKey, "external-reset-fixture"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("external reset not observed by active request")
	}
}
