package vnf

import (
	"fmt"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/vishvananda/netlink"

	"nse-ovs-vpn/internal"
	"nse-ovs-vpn/internal/processor"
)

type FlowInfo struct {
	ConnectionID         string
	IngressInterface     string
	EgressInterface      string
	UpstreamConnection   *networkservice.Connection
	DownstreamConnection *networkservice.Connection
}

type SessionContext struct {
	flow    FlowInfo
	runtime *processor.Runtime
	state   *SessionState
	config  *internal.Config
}

func newSessionContext(runtime *processor.Runtime, cfg *internal.Config) (*SessionContext, error) {
	if runtime == nil {
		return nil, fmt.Errorf("runtime is required")
	}
	if runtime.Flow == nil {
		return nil, fmt.Errorf("runtime flow is required")
	}
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	return &SessionContext{
		flow: FlowInfo{
			ConnectionID:         runtime.Flow.ConnectionID,
			IngressInterface:     runtime.Flow.IngressInterface,
			EgressInterface:      runtime.Flow.EgressInterface,
			UpstreamConnection:   cloneConnection(runtime.Flow.UpstreamConnection),
			DownstreamConnection: cloneConnection(runtime.Flow.DownstreamConnection),
		},
		runtime: runtime,
		state:   newSessionState(),
		config:  cfg,
	}, nil
}

func (c *SessionContext) Config() *internal.Config {
	if c == nil {
		return nil
	}
	return c.config
}

func (c *SessionContext) Flow() FlowInfo {
	if c == nil {
		return FlowInfo{}
	}
	return c.flow
}

func (c *SessionContext) ConnectionID() string {
	return c.Flow().ConnectionID
}

func (c *SessionContext) IngressInterface() string {
	return c.Flow().IngressInterface
}

func (c *SessionContext) EgressInterface() string {
	return c.Flow().EgressInterface
}

func (c *SessionContext) IngressLink() netlink.Link {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.IngressLink
}

func (c *SessionContext) EgressLink() netlink.Link {
	if c == nil || c.runtime == nil {
		return nil
	}
	return c.runtime.EgressLink
}

func (c *SessionContext) ClearInterface() string {
	cfg := c.Config()
	if cfg != nil && cfg.VPNRole == "decrypt" {
		return c.EgressInterface()
	}
	return c.IngressInterface()
}

func (c *SessionContext) TransportInterface() string {
	cfg := c.Config()
	if cfg != nil && cfg.VPNRole == "decrypt" {
		return c.IngressInterface()
	}
	return c.EgressInterface()
}

func (c *SessionContext) ClearLink() netlink.Link {
	cfg := c.Config()
	if cfg != nil && cfg.VPNRole == "decrypt" {
		return c.EgressLink()
	}
	return c.IngressLink()
}

func (c *SessionContext) TransportLink() netlink.Link {
	cfg := c.Config()
	if cfg != nil && cfg.VPNRole == "decrypt" {
		return c.IngressLink()
	}
	return c.EgressLink()
}

func (c *SessionContext) UpstreamConnection() *networkservice.Connection {
	if c == nil {
		return nil
	}
	return cloneConnection(c.flow.UpstreamConnection)
}

func (c *SessionContext) DownstreamConnection() *networkservice.Connection {
	if c == nil {
		return nil
	}
	return cloneConnection(c.flow.DownstreamConnection)
}

func (c *SessionContext) State() *SessionState {
	if c == nil {
		return nil
	}
	return c.state
}

func cloneConnection(conn *networkservice.Connection) *networkservice.Connection {
	if conn == nil {
		return nil
	}
	return conn.Clone()
}
