package hooks

import (
	builtInFunctions "github.com/multiversx/mx-chain-vm-common-go/builtInFunctions"
)

const (
	drwaMetricSyncApplySuccess          = "sync_apply_success"
	drwaMetricSyncApplyNoop             = "sync_apply_noop"
	drwaMetricSyncApplyFailure          = "sync_apply_failure"
	drwaMetricSyncUnauthorizedCaller    = "sync_unauthorized_caller"
	drwaMetricSyncHashMismatch          = "sync_hash_mismatch"
	drwaMetricSyncReplayRejected        = "sync_replay_rejected"
	drwaMetricSyncDecodeFailure         = "sync_decode_failure"
	drwaMetricRecoverySafeModeReport    = "recovery_safe_mode_report"
	drwaMetricRecoveryNonRepairable     = "recovery_non_repairable_report"
	drwaMetricRolloutVerificationPass   = "rollout_verification_pass"
	drwaMetricRolloutVerificationReject = "rollout_verification_reject"
)

var drwaMetrics = builtInFunctions.NewDrwaCounterSet()

func recordDRWAMetric(metric string) {
	drwaMetrics.Increment(metric)
}

func snapshotDRWAMetrics() map[string]uint64 {
	return drwaMetrics.Snapshot()
}

func resetDRWAMetrics() {
	drwaMetrics.Reset()
}
