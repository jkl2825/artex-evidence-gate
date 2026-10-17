package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"
)

const (
	AuthPasswordKey   = "auth.password_hash"
	AuthFailureLimit  = 5
	AuthFailureWindow = 15 * time.Minute
	AuthLockDuration  = 15 * time.Minute
)

// AuthAuditEvent contains only bounded metadata, never credentials or request bodies.
type AuthAuditEvent struct {
	Action   string `json:"action"`
	Outcome  string `json:"outcome"`
	Reason   string `json:"reason"`
	ClientIP string `json:"client_ip"`
}

func (d *DB) AuthPassword(ctx context.Context) (string, error) {
	var hash string
	err := d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, AuthPasswordKey).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

func authCredentialVersion(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])
}

func appendAuthAudit(ctx context.Context, tx *sql.Tx, event AuthAuditEvent) error {
	var id int64
	err := tx.QueryRowContext(ctx, `INSERT INTO auth_audit_log(action,outcome,reason,client_ip)
VALUES ($1,$2,$3,$4) RETURNING id`, event.Action, event.Outcome, event.Reason, event.ClientIP).Scan(&id)
	if err != nil {
		return err
	}
	// Bound retained history by age and count; pruning runs once per 100 events.
	if id%100 == 0 {
		_, err = tx.ExecContext(ctx, `DELETE FROM auth_audit_log WHERE created_at < now()-interval '90 days' OR id <= $1`, id-100000)
	}
	return err
}

func (d *DB) RecordAuthAudit(ctx context.Context, event AuthAuditEvent) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := appendAuthAudit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

// All credential writes and login completions acquire this row before the
// password row, so concurrent failures and password changes have one lock order.
func lockAuthState(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO auth_login_state(id) VALUES (1) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	var id int
	return tx.QueryRowContext(ctx, `SELECT id FROM auth_login_state WHERE id=1 FOR UPDATE`).Scan(&id)
}

// WriteAuthPassword performs first initialization or a compare-and-swap change.
// The credential and its audit event commit together. Out-of-band password
// resets also invalidate sessions because tokens are bound to the stored hash.
func (d *DB) WriteAuthPassword(ctx context.Context, oldHash *string, newHash string, event *AuthAuditEvent) (bool, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := lockAuthState(ctx, tx); err != nil {
		return false, err
	}
	var result sql.Result
	if oldHash == nil {
		result, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES ($1,$2) ON CONFLICT DO NOTHING`, AuthPasswordKey, newHash)
	} else {
		result, err = tx.ExecContext(ctx, `UPDATE settings SET value=$1,updated_at=now() WHERE key=$2 AND value=$3`, newHash, AuthPasswordKey, *oldHash)
	}
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	changed := n == 1
	if changed {
		_, err = tx.ExecContext(ctx, `UPDATE auth_login_state SET credential_version=$1,failures=0,window_started_at=now(),locked_until=NULL WHERE id=1`, authCredentialVersion(newHash))
		event.Outcome, event.Reason = "success", "completed"
	} else {
		event.Outcome, event.Reason = "rejected", "credential_conflict"
	}
	if err != nil {
		return false, err
	}
	if err := appendAuthAudit(ctx, tx, *event); err != nil {
		return false, err
	}
	return changed, tx.Commit()
}

func (d *DB) AuthLockRemaining(ctx context.Context, hash string) (time.Duration, error) {
	var locked sql.NullTime
	var now time.Time
	err := d.QueryRowContext(ctx, `SELECT locked_until,clock_timestamp() FROM auth_login_state WHERE id=1 AND credential_version=$1`, authCredentialVersion(hash)).Scan(&locked, &now)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if locked.Valid && locked.Time.After(now) {
		return locked.Time.Sub(now), nil
	}
	return 0, nil
}

// FinishAuthLogin rechecks both the credential and account lock after bcrypt.
// Concurrent requests cannot bypass the threshold with an earlier lock check.
func (d *DB) FinishAuthLogin(ctx context.Context, verifiedHash string, valid bool, event *AuthAuditEvent) (bool, time.Duration, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return false, 0, err
	}
	defer tx.Rollback()
	if err := lockAuthState(ctx, tx); err != nil {
		return false, 0, err
	}
	var current string
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1 FOR UPDATE`, AuthPasswordKey).Scan(&current)
	if err != nil {
		return false, 0, err
	}
	var version string
	var failures int
	var started, now time.Time
	var locked sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT credential_version,failures,window_started_at,locked_until,clock_timestamp() FROM auth_login_state WHERE id=1`).Scan(&version, &failures, &started, &locked, &now)
	if err != nil {
		return false, 0, err
	}
	remaining := time.Duration(0)
	allowed := false
	if current != verifiedHash {
		event.Outcome, event.Reason = "rejected", "credential_changed"
	} else {
		currentVersion := authCredentialVersion(current)
		if version != currentVersion || (locked.Valid && !locked.Time.After(now)) || (!locked.Valid && now.Sub(started) >= AuthFailureWindow) {
			failures, started, locked = 0, now, sql.NullTime{}
		}
		if locked.Valid && locked.Time.After(now) {
			remaining = locked.Time.Sub(now)
			event.Outcome, event.Reason = "rejected", "account_locked"
		} else if valid {
			allowed, failures, started = true, 0, now
			event.Outcome, event.Reason = "success", "authenticated"
		} else {
			failures++
			event.Outcome, event.Reason = "rejected", "invalid_credentials"
			if failures >= AuthFailureLimit {
				locked = sql.NullTime{Time: now.Add(AuthLockDuration), Valid: true}
				remaining = AuthLockDuration
				event.Reason = "account_locked"
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE auth_login_state SET credential_version=$1,failures=$2,window_started_at=$3,locked_until=$4 WHERE id=1`, currentVersion, failures, started, locked)
		if err != nil {
			return false, 0, err
		}
	}
	if err := appendAuthAudit(ctx, tx, *event); err != nil {
		return false, 0, err
	}
	return allowed, remaining, tx.Commit()
}
