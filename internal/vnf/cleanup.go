package vnf

import "context"

func DefaultCleanupHook() CleanupHook {
	return CleanupHookFunc(stopTrafficProcessing)
}

func stopTrafficProcessing(_ context.Context, _ *SessionContext) error {
	return nil
}
