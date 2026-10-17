package intercept

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	maxJudgeRetries         = 10
	maxJudgeRetryIntervalMS = 60_000
)

// ValidateRetry rejects invalid settings before any configuration is written.
func (c JudgeConfig) ValidateRetry() error {
	if c.RetryCount < 0 || c.RetryCount > maxJudgeRetries {
		return fmt.Errorf("retry_count 必须在 0 到 %d 之间", maxJudgeRetries)
	}
	if c.RetryIntervalMS < 0 || c.RetryIntervalMS > maxJudgeRetryIntervalMS {
		return fmt.Errorf("retry_interval_ms 必须在 0 到 %d 之间", maxJudgeRetryIntervalMS)
	}
	return nil
}

type permanentReviewError struct{ error }

func (e permanentReviewError) Unwrap() error { return e.error }

// NoRetry marks configuration and deterministic provider errors as permanent.
func NoRetry(err error) error {
	if err == nil {
		return nil
	}
	return permanentReviewError{err}
}

// reviewWithRetry repeats only the model review, never the tool operation.
// Each attempt has its own timeout; the parent's cancellation always wins.
func reviewWithRetry(ctx context.Context, rv Reviewer, cfg JudgeConfig, input ReviewInput) (Decision, error) {
	if err := cfg.ValidateRetry(); err != nil {
		return Decision{}, err
	}
	var out Decision
	var err error
	for attempt := 0; attempt <= cfg.RetryCount; attempt++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if attempt > 0 && cfg.RetryIntervalMS > 0 {
			timer := time.NewTimer(time.Duration(cfg.RetryIntervalMS) * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return out, ctx.Err()
			case <-timer.C:
			}
		}
		if err := ctx.Err(); err != nil {
			return out, err
		}
		callCtx := ctx
		cancel := func() {}
		if cfg.TimeoutSeconds > 0 {
			callCtx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		}
		out, err = rv(callCtx, cfg.ProfileID, cfg.Prompt, input)
		callErr := callCtx.Err()
		cancel()
		if callErr != nil {
			err = callErr
		}
		if out.ProfileID > 0 {
			cfg.ProfileID = out.ProfileID // keep the resolved profile for retries
		}
		if err == nil {
			switch out.Action {
			case "allow", "deny", "ask":
				return out, nil
			default:
				err = errors.New("模型输出无法解析")
			}
		}
		var permanent permanentReviewError
		if errors.As(err, &permanent) || attempt == cfg.RetryCount {
			return out, fmt.Errorf("审核尝试 %d 次未成功: %w", attempt+1, err)
		}
	}
	return out, err
}
