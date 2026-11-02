//go:build linux
// +build linux

package internal

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

type Config struct {
	Name                   string            `default:"nse-ovs-vpn" desc:"Name of the WireGuard-based VPN NSE"`
	ListenOn               string            `default:"listen.on.sock" desc:"listen on socket" split_words:"true"`
	ConnectTo              url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime       time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies []string          `default:"" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	ServiceName            string            `default:"nse-ovs-vpn" desc:"name of provided network service" split_words:"true"`
	Labels                 map[string]string `default:"app:vpn-encrypt" desc:"endpoint labels"`
	DownstreamLabels       map[string]string `default:"" desc:"labels used to select downstream endpoints; empty derives from vpn role" split_words:"true"`
	LogLevel               string            `default:"INFO" desc:"log level" split_words:"true"`
	OpenTelemetryEndpoint  string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint" split_words:"true"`
	MetricsExportInterval  time.Duration     `default:"10s" desc:"interval between metrics exports" split_words:"true"`
	PprofEnabled           bool              `default:"false" desc:"is pprof enabled" split_words:"true"`
	PprofListenOn          string            `default:"localhost:6060" desc:"pprof URL to ListenAndServe" split_words:"true"`

	VPNRole                string `default:"encrypt" desc:"vpn role: encrypt or decrypt" split_words:"true"`
	VPNTransportCIDR       string `default:"169.254.200.0/30" desc:"secondary IPv4 CIDR for the encrypt-to-decrypt outer transport leg" split_words:"true"`
	VPNInnerCIDR           string `default:"10.200.0.0/30" desc:"WireGuard inner tunnel CIDR" split_words:"true"`
	VPNListenPort          int    `default:"51820" desc:"WireGuard UDP listen port" split_words:"true"`
	VPNPrivateKeyPath      string `default:"/etc/wireguard/keys/privatekey" desc:"path to the mounted WireGuard private key" split_words:"true"`
	VPNPeerPublicKeyPath   string `default:"/etc/wireguard/keys/peer_publickey" desc:"path to the mounted WireGuard peer public key" split_words:"true"`
	VPNPersistentKeepalive int    `default:"5" desc:"WireGuard persistent keepalive seconds" split_words:"true"`
	VPNProxyPort           int    `default:"5201" desc:"TCP and UDP port proxied through the VPN tunnel" split_words:"true"`
	VPNInterfaceName       string `default:"wg0" desc:"WireGuard interface name" split_words:"true"`
	VPNTargetIP            string `default:"172.16.1.100" desc:"business IP exposed by the downstream server NSE; configurable to match NSM CIDR settings" split_words:"true"`
}

func LoadConfig(_ context.Context) (*Config, error) {
	config := new(Config)

	if err := envconfig.Usage("nsm", config); err != nil {
		return nil, errors.Wrap(err, "cannot show usage of envconfig nsm")
	}

	if err := envconfig.Process("nsm", config); err != nil {
		return nil, errors.Wrap(err, "cannot process envconfig nsm")
	}

	if config.ServiceName == "" {
		config.ServiceName = config.Name
	}
	if config.VPNInterfaceName == "" {
		config.VPNInterfaceName = "wg0"
	}
	if config.VPNProxyPort <= 0 {
		config.VPNProxyPort = 5201
	}
	if config.VPNListenPort <= 0 {
		config.VPNListenPort = 51820
	}
	if config.VPNPersistentKeepalive < 0 {
		config.VPNPersistentKeepalive = 0
	}
	if config.VPNTargetIP == "" {
		config.VPNTargetIP = "172.16.1.100"
	}
	if err := ValidateVPNRole(config.VPNRole); err != nil {
		return nil, err
	}

	if config.Labels == nil || len(config.Labels) == 0 {
		config.Labels = map[string]string{"app": defaultLabelForRole(config.VPNRole)}
	}

	if len(config.DownstreamLabels) == 0 {
		config.DownstreamLabels = make(map[string]string, len(config.Labels))
		for key, value := range config.Labels {
			config.DownstreamLabels[key] = value
		}
	}

	return config, nil
}

func defaultLabelForRole(role string) string {
	switch role {
	case "decrypt":
		return "vpn-decrypt"
	default:
		return "vpn-encrypt"
	}
}

func ValidateVPNRole(role string) error {
	switch role {
	case "encrypt", "decrypt":
		return nil
	default:
		return fmt.Errorf("unsupported vpn role %q", role)
	}
}
