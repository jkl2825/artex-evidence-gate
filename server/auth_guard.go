package server

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const authWindow = time.Minute
const authPerIPLimit = 10
const authGlobalLimit = 60
const authMaxClients = 4096

type authBucket struct {
	start    time.Time
	count    int
	reported bool
}
type authGuard struct {
	mu           sync.Mutex
	clients      map[string]authBucket
	global       authBucket
	busyReported time.Time
	slots        chan struct{}
	now          func() time.Time
	sessions     map[uint64]authSession
	nextSession  uint64
}

type authSession struct {
	hash   string
	cancel context.CancelFunc
}

func (g *authGuard) registerSession(hash string, cancel context.CancelFunc) func() {
	g.mu.Lock()
	if g.sessions == nil {
		g.sessions = make(map[uint64]authSession)
	}
	g.nextSession++
	id := g.nextSession
	g.sessions[id] = authSession{hash: hash, cancel: cancel}
	g.mu.Unlock()
	return func() { g.mu.Lock(); delete(g.sessions, id); g.mu.Unlock(); cancel() }
}

func (g *authGuard) revokeSessions(currentHash string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, session := range g.sessions {
		if session.hash != currentHash {
			session.cancel()
		}
	}
}

func (s *Server) authenticationGuard() *authGuard {
	s.authOnce.Do(func() {
		s.authGuard = &authGuard{clients: make(map[string]authBucket), slots: make(chan struct{}, 4), now: time.Now}
	})
	return s.authGuard
}

// Never trust forwarding headers unless a trusted-proxy policy is configured.
// Peers behind a reverse proxy share the proxy's limit by default.
func authClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "unknown"
	}
	return ip.Unmap().WithZone("").String()
}

func (g *authGuard) enter(ip string) (time.Duration, bool, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Sub(g.global.start) >= authWindow {
		g.global = authBucket{start: now}
	}
	b, exists := g.clients[ip]
	if !exists || now.Sub(b.start) >= authWindow {
		b = authBucket{start: now}
	}
	if b.count >= authPerIPLimit {
		report := !b.reported
		b.reported = true
		g.clients[ip] = b
		return authWindow - now.Sub(b.start), report, false
	}
	if g.global.count >= authGlobalLimit {
		report := !g.global.reported
		g.global.reported = true
		return authWindow - now.Sub(g.global.start), report, false
	}
	if !exists && len(g.clients) >= authMaxClients {
		for key, value := range g.clients {
			if now.Sub(value.start) >= authWindow {
				delete(g.clients, key)
			}
		}
		if len(g.clients) >= authMaxClients {
			return authWindow, false, false
		}
	}
	b.count++
	g.clients[ip] = b
	g.global.count++
	select {
	case g.slots <- struct{}{}:
		return 0, false, true
	default:
		report := now.Sub(g.busyReported) >= time.Second
		if report {
			g.busyReported = now
		}
		return time.Second, report, false
	}
}

func logAuthEvent(event db.AuthAuditEvent) {
	raw, _ := json.Marshal(event)
	log.Printf("[auth] %s", raw)
}

func (s *Server) auditAuth(r *http.Request, action, outcome, reason string) {
	event := db.AuthAuditEvent{Action: action, Outcome: outcome, Reason: reason, ClientIP: authClientIP(r)}
	logAuthEvent(event)
	if s.m == nil || s.m.pg == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.m.pg.RecordAuthAudit(ctx, event); err != nil {
		// Driver errors may contain connection details; only log a fixed diagnostic.
		log.Printf("[auth] audit persistence unavailable")
	}
}

func authRetry(w http.ResponseWriter, d time.Duration, message string) {
	seconds := int64((d + time.Second - 1) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
	writeErr(w, http.StatusTooManyRequests, message)
}

func (s *Server) admitAuth(w http.ResponseWriter, r *http.Request, action string) (func(), bool) {
	g := s.authenticationGuard()
	retry, report, ok := g.enter(authClientIP(r))
	if !ok {
		if report {
			s.auditAuth(r, action, "rejected", "rate_limited")
		}
		authRetry(w, retry, "认证请求过于频繁，请稍后重试")
		return func() {}, false
	}
	return func() { <-g.slots }, true
}
