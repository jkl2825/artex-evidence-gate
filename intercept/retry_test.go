package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewRetryRecoveryAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retries    int
		failures   int
		invalid    bool
		wantCalls  int
		wantAction string
	}{
		{"disabled", 0, 1, false, 1, ""},
		{"transient recovery", 2, 2, false, 3, "deny"},
		{"invalid reply recovery", 1, 1, true, 2, "deny"},
		{"exhausted", 2, 10, false, 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := ReviewInput{Version: 4, Tool: "Bash", Arguments: json.RawMessage(`{"command":"pwd"}`)}
			calls := 0
			rv := func(_ context.Context, profileID int64, prompt string, got ReviewInput) (Decision, error) {
				calls++
				if prompt != "fixed policy" || got.Tool != input.Tool || string(got.Arguments) != string(input.Arguments) {
					t.Fatal("retry changed the review request")
				}
				if calls > 1 && profileID != 42 {
					t.Fatal("resolved review profile changed across retries")
				}
				if calls <= tc.failures {
					if tc.invalid {
						return Decision{ProfileID: 42}, nil
					}
					return Decision{ProfileID: 42}, errors.New("temporary network error")
				}
				return Decision{ProfileID: 42, Action: "deny"}, nil
			}
			out, err := reviewWithRetry(t.Context(), rv, JudgeConfig{RetryCount: tc.retries, Prompt: "fixed policy"}, input)
			if calls != tc.wantCalls || out.Action != tc.wantAction || (err == nil) != (tc.wantAction != "") {
				t.Fatalf("calls=%d out=%+v err=%v", calls, out, err)
			}
			if err != nil && !strings.Contains(err.Error(), "次未成功") {
				t.Fatalf("missing attempt count: %v", err)
			}
		})
	}
}

func TestReviewRetryNeverRepeatsValidVerdict(t *testing.T) {
	for _, action := range []string{"allow", "deny", "ask"} {
		calls := 0
		out, err := reviewWithRetry(t.Context(), func(context.Context, int64, string, ReviewInput) (Decision, error) {
			calls++
			return Decision{Action: action}, nil
		}, JudgeConfig{RetryCount: 10}, ReviewInput{})
		if err != nil || out.Action != action || calls != 1 {
			t.Fatalf("valid %s verdict retried: calls=%d err=%v", action, calls, err)
		}
	}
}

func TestReviewRetryPermanentError(t *testing.T) {
	cause := errors.New("status 401: invalid credentials")
	calls := 0
	_, err := reviewWithRetry(t.Context(), func(context.Context, int64, string, ReviewInput) (Decision, error) {
		calls++
		return Decision{}, NoRetry(cause)
	}, JudgeConfig{RetryCount: 10}, ReviewInput{})
	if calls != 1 || !errors.Is(err, cause) {
		t.Fatalf("permanent error retried or lost: calls=%d err=%v", calls, err)
	}
}

func TestReviewRetryTimeoutHasFreshAttemptContext(t *testing.T) {
	calls := 0
	out, err := reviewWithRetry(t.Context(), func(ctx context.Context, _ int64, _ string, _ ReviewInput) (Decision, error) {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return Decision{}, ctx.Err()
		}
		if ctx.Err() != nil {
			t.Fatal("retry inherited the expired attempt deadline")
		}
		return Decision{Action: "ask"}, nil
	}, JudgeConfig{RetryCount: 1, TimeoutSeconds: 1}, ReviewInput{})
	if err != nil || calls != 2 || out.Action != "ask" {
		t.Fatalf("calls=%d out=%+v err=%v", calls, out, err)
	}
}

func TestReviewRetryCancellationStopsBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		_, err := reviewWithRetry(ctx, func(context.Context, int64, string, ReviewInput) (Decision, error) {
			if calls.Add(1) == 1 {
				close(started)
			}
			return Decision{}, errors.New("unavailable")
		}, JudgeConfig{RetryCount: 10, RetryIntervalMS: 60_000}, ReviewInput{})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
			t.Fatalf("cancellation ignored: calls=%d err=%v", calls.Load(), err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt review backoff")
	}
}

func TestJudgeRetrySettingsBounds(t *testing.T) {
	for _, cfg := range []JudgeConfig{{RetryCount: -1}, {RetryCount: 11}, {RetryIntervalMS: -1}, {RetryIntervalMS: 60_001}} {
		if cfg.ValidateRetry() == nil {
			t.Fatalf("invalid settings accepted: %+v", cfg)
		}
	}
	if err := (JudgeConfig{RetryCount: 10, RetryIntervalMS: 60_000}).ValidateRetry(); err != nil {
		t.Fatal(err)
	}
}
