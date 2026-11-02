package vnf

import (
	"context"
	"fmt"

	"nse-ovs-vpn/internal"
	"nse-ovs-vpn/internal/processor"
)

type Service struct {
	config    *internal.Config
	dataplane Dataplane
	handler   Handler
}

func New(cfg *internal.Config) processor.FlowSetup {
	return NewService(cfg, NewVPNDataplane(), NewVPNHandler())
}

func NewService(cfg *internal.Config, dataplane Dataplane, handler Handler) processor.FlowSetup {
	return &Service{
		config:    cfg,
		dataplane: dataplane,
		handler:   handler,
	}
}

func (s *Service) Setup(ctx context.Context, runtime *processor.Runtime) (processor.Session, error) {
	if s == nil {
		return nil, fmt.Errorf("service is required")
	}
	if s.config == nil {
		return nil, fmt.Errorf("config is required")
	}

	sessionCtx, err := newSessionContext(runtime, s.config)
	if err != nil {
		return nil, err
	}

	dataplane := s.dataplane
	if dataplane == nil {
		dataplane = NewVPNDataplane()
	}

	handler := s.handler
	if handler == nil {
		handler = NewVPNHandler()
	}

	dataplaneSession, err := dataplane.Connect(ctx, sessionCtx)
	if err != nil {
		return nil, err
	}

	handlerSession, err := handler.Configure(ctx, sessionCtx)
	if err != nil {
		if dataplaneSession != nil {
			_ = dataplaneSession.Close(ctx)
		}
		return nil, err
	}

	return processor.JoinSessions(dataplaneSession, handlerSession), nil
}
