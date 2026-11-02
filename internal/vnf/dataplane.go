package vnf

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"

	"nse-ovs-vpn/internal/processor"
)

type Dataplane interface {
	Connect(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error)
}

type DataplaneFunc func(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error)

func (f DataplaneFunc) Connect(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
	if f == nil {
		return nil, fmt.Errorf("dataplane func is required")
	}
	return f(ctx, sessionCtx)
}

type vpnDataplane struct{}

func NewVPNDataplane() Dataplane {
	return &vpnDataplane{}
}

func (d *vpnDataplane) Connect(_ context.Context, sessionCtx *SessionContext) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}
	if err := setLinkUp(sessionCtx.IngressLink()); err != nil {
		return nil, err
	}
	if err := setLinkUp(sessionCtx.EgressLink()); err != nil {
		return nil, err
	}

	if state := sessionCtx.State(); state != nil {
		state.Store(StateKeyDataplaneKind, "vpn")
		state.Store(StateKeyDataplaneMode, "wireguard-relay")
		state.Store(StateKeyVPNRole, sessionCtx.Config().VPNRole)
		state.Store(StateKeyVPNClearInterface, sessionCtx.ClearInterface())
		state.Store(StateKeyVPNTransportInterface, sessionCtx.TransportInterface())
	}

	return processor.CloseFunc(func(context.Context) error {
		return nil
	}), nil
}

func setLinkUp(link netlink.Link) error {
	if link == nil {
		return nil
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link %s up: %w", link.Attrs().Name, err)
	}
	return nil
}
