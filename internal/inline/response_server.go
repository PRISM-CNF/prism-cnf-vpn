package inline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/postpone"
	"github.com/vishvananda/netlink"

	"nse-ovs-vpn/internal/processor"
)

const (
	// Keep the synchronous activation window short. A longer wait makes the
	// first inline request miss the upstream NSM deadline, which triggers a
	// second full Request before the original chain has been cleaned up.
	activationTimeout         = 500 * time.Millisecond
	deferredActivationTimeout = 90 * time.Second
	cleanupTimeout            = 20 * time.Second
)

type responseServer struct {
	processor     processor.Processor
	client        networkservice.NetworkServiceClient
	clientOptions []grpc.CallOption
}

func NewResponseServer(vnfProcessor processor.Processor, client networkservice.NetworkServiceClient, callOptions ...grpc.CallOption) networkservice.NetworkServiceServer {
	return &responseServer{
		processor:     vnfProcessor,
		client:        client,
		clientOptions: callOptions,
	}
}

func (s *responseServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	logger := log.FromContext(ctx)
	closeCtxFunc := postpone.ContextWithValues(ctx)

	logrus.Infof("inline response request entered: %s", requestSummary(request))
	preLinks := snapshotInlineLinks()
	conn, err := next.Server(ctx).Request(ctx, request)
	if err != nil {
		logrus.Errorf("inline response inner request failed: %s err=%v", requestSummary(request), err)
		return nil, err
	}
	logrus.Infof("inline response inner response: %s", connectionSummary(conn))

	downstreamConn, _ := loadDownstreamConnection(ctx)
	observedIngress := addedInlineLink(preLinks, snapshotInlineLinks(), mechanismInterfaceName(downstreamConn))
	flow, err := flowForConnectionPath(conn, downstreamConn, observedIngress)
	if err != nil {
		logger.Errorf("inline flow build failed from response path for %s: %v", connectionSummary(conn), err)
		closeCtx, closeCancel := cleanupContext(logger)
		defer closeCancel()
		_ = s.cleanupConnection(closeCtx, conn.GetId(), conn, downstreamConn)
		return nil, err
	}
	if flow == nil {
		logger.Infof(
			"inline response skipping processor for %s because both legs resolve to one interface",
			connectionSummary(conn),
		)
		return conn, nil
	}

	logger.Infof(
		"inline flow resolved for %s: ingress=%s egress=%s",
		connectionSummary(conn),
		flow.IngressInterface,
		flow.EgressInterface,
	)

	activationCtx, activationCancel := context.WithTimeout(log.WithLog(context.Background(), logger), activationTimeout)
	defer activationCancel()

	session, err := s.processor.Activate(activationCtx, flow)
	if err != nil {
		if processor.IsPending(err) {
			logger.Warnf(
				"processor activation is pending for flow %s on %s -> %s: %v",
				flow.ConnectionID,
				flow.IngressInterface,
				flow.EgressInterface,
				err,
			)
			asyncCtx, asyncCancel := closeCtxFunc()
			asyncConn := conn.Clone()
			go func() {
				defer asyncCancel()

				processorCtx, cancel := context.WithTimeout(log.WithLog(context.Background(), logger), deferredActivationTimeout)
				defer cancel()

				asyncSession, asyncErr := s.processor.Activate(processorCtx, flow.Clone())
				if asyncErr != nil {
					logger.Errorf(
						"deferred processor activation failed for flow %s on %s -> %s: %v",
						flow.ConnectionID,
						flow.IngressInterface,
						flow.EgressInterface,
						asyncErr,
					)
					if asyncConn != nil {
						cleanupCtx, cleanupCancel := cleanupContext(logger)
						if closeErr := s.cleanupConnection(cleanupCtx, asyncConn.GetId(), asyncConn, downstreamConn); closeErr != nil {
							logger.Errorf(
								"deferred processor activation cleanup failed for flow %s on %s -> %s: %v",
								flow.ConnectionID,
								flow.IngressInterface,
								flow.EgressInterface,
								closeErr,
							)
						}
						cleanupCancel()
					}
					return
				}
				storeProcessorSession(asyncCtx, asyncSession)
				registerProcessorSession(asyncConn.GetId(), asyncSession)
			}()
			return conn, nil
		}

		logger.Errorf(
			"processor activation failed for flow %s on %s -> %s: %v",
			flow.ConnectionID,
			flow.IngressInterface,
			flow.EgressInterface,
			err,
		)
		closeCtx, closeCancel := cleanupContext(logger)
		defer closeCancel()
		_ = s.cleanupConnection(closeCtx, conn.GetId(), conn, downstreamConn)
		return nil, fmt.Errorf("activate processor for flow %s: %w", flow.ConnectionID, err)
	}

	storeProcessorSession(ctx, session)
	registerProcessorSession(conn.GetId(), session)
	return conn, nil
}

func (s *responseServer) Close(ctx context.Context, conn *networkservice.Connection) (*emptypb.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}

func (s *responseServer) cleanupConnection(ctx context.Context, connectionID string, localConn *networkservice.Connection, downstreamConn *networkservice.Connection) error {
	var errs []error

	if err := closeRegisteredProcessorSession(ctx, connectionID); err != nil {
		errs = append(errs, fmt.Errorf("close processor session: %w", err))
	}
	deleteRegisteredProcessorSession(connectionID)

	if downstreamConn == nil {
		downstreamConn, _ = loadRegisteredDownstreamConnection(connectionID)
	}
	if downstreamConn != nil && s.client != nil {
		if _, err := s.client.Close(ctx, downstreamConn.Clone(), s.clientOptions...); err != nil {
			errs = append(errs, fmt.Errorf("close downstream connection: %w", err))
		}
	}
	deleteRegisteredDownstreamConnection(connectionID)

	if localConn != nil {
		if _, err := next.Server(ctx).Close(ctx, localConn.Clone()); err != nil {
			errs = append(errs, fmt.Errorf("close local connection: %w", err))
		}
	}

	return errors.Join(errs...)
}

func snapshotInlineLinks() []string {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}

	names := make([]string, 0, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		name := link.Attrs().Name
		if name == "" || name == "lo" || name == "eth0" {
			continue
		}
		if len(name) >= len("nse-ovs-vp-") && name[:len("nse-ovs-vp-")] == "nse-ovs-vp-" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func addedInlineLink(before, after []string, exclude string) string {
	if len(after) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(before))
	for _, name := range before {
		seen[name] = struct{}{}
	}
	for _, name := range after {
		if name == exclude {
			continue
		}
		if _, ok := seen[name]; !ok {
			return name
		}
	}
	return ""
}

func cleanupContext(logger log.Logger) (context.Context, context.CancelFunc) {
	return context.WithTimeout(log.WithLog(context.Background(), logger), cleanupTimeout)
}
