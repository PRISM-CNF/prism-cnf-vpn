package vnf

import (
	"context"

	"nse-ovs-vpn/internal/processor"
)

func DefaultRuntimeHook() RuntimeHook {
	return RuntimeHookFunc(startTrafficProcessing)
}

func startTrafficProcessing(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
	return globalVPNManager.Start(ctx, sessionCtx)
}
