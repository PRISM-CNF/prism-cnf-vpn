package inline

import (
	"context"
	"sync"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	nsmetadata "github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"

	"nse-ovs-vpn/internal/processor"
)

type originalConnectionKey struct{}
type downstreamConnectionKey struct{}
type processorSessionKey struct{}

var (
	registeredDownstreamConnections sync.Map
	registeredProcessorSessions     sync.Map
)

func storeOriginalConnection(ctx context.Context, conn *networkservice.Connection) {
	if conn == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(originalConnectionKey{}, conn.Clone())
}

func loadOriginalConnection(ctx context.Context) *networkservice.Connection {
	rawValue, ok := nsmetadata.Map(ctx, false).Load(originalConnectionKey{})
	if !ok {
		return nil
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil
	}
	return conn.Clone()
}

func deleteOriginalConnection(ctx context.Context) {
	_, _ = nsmetadata.Map(ctx, false).LoadAndDelete(originalConnectionKey{})
}

func storeDownstreamConnection(ctx context.Context, conn *networkservice.Connection) {
	if conn == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(downstreamConnectionKey{}, conn.Clone())
}

func registerDownstreamConnection(connectionID string, conn *networkservice.Connection) {
	if connectionID == "" || conn == nil {
		return
	}
	registeredDownstreamConnections.Store(connectionID, conn.Clone())
}

func loadDownstreamConnection(ctx context.Context) (*networkservice.Connection, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).Load(downstreamConnectionKey{})
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func loadAndDeleteDownstreamConnection(ctx context.Context) (*networkservice.Connection, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).LoadAndDelete(downstreamConnectionKey{})
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func loadRegisteredDownstreamConnection(connectionID string) (*networkservice.Connection, bool) {
	rawValue, ok := registeredDownstreamConnections.Load(connectionID)
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func loadAndDeleteRegisteredDownstreamConnection(connectionID string) (*networkservice.Connection, bool) {
	rawValue, ok := registeredDownstreamConnections.LoadAndDelete(connectionID)
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func deleteRegisteredDownstreamConnection(connectionID string) {
	if connectionID == "" {
		return
	}
	registeredDownstreamConnections.Delete(connectionID)
}

func storeProcessorSession(ctx context.Context, session processor.Session) {
	if session == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(processorSessionKey{}, session)
}

func registerProcessorSession(connectionID string, session processor.Session) {
	if connectionID == "" || session == nil {
		return
	}
	registeredProcessorSessions.Store(connectionID, session)
}

func loadAndDeleteProcessorSession(ctx context.Context) (processor.Session, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).LoadAndDelete(processorSessionKey{})
	if !ok {
		return nil, false
	}
	session, ok := rawValue.(processor.Session)
	if !ok || session == nil {
		return nil, false
	}
	return session, true
}

func loadAndDeleteRegisteredProcessorSession(connectionID string) (processor.Session, bool) {
	rawValue, ok := registeredProcessorSessions.LoadAndDelete(connectionID)
	if !ok {
		return nil, false
	}
	session, ok := rawValue.(processor.Session)
	if !ok || session == nil {
		return nil, false
	}
	return session, true
}

func deleteRegisteredProcessorSession(connectionID string) {
	if connectionID == "" {
		return
	}
	registeredProcessorSessions.Delete(connectionID)
}

func closeProcessorSession(ctx context.Context) error {
	session, ok := loadAndDeleteProcessorSession(ctx)
	if !ok {
		return nil
	}
	return session.Close(ctx)
}

func closeRegisteredProcessorSession(ctx context.Context, connectionID string) error {
	session, ok := loadAndDeleteRegisteredProcessorSession(connectionID)
	if !ok {
		return nil
	}
	return session.Close(ctx)
}
