package tsauth

import (
	"fmt"
	"net/http"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"tailscale.com/client/tailscale"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(TailscaleAuth{})
	httpcaddyfile.RegisterHandlerDirective("tailscale_auth", parseCaddyfile)
}

type TailscaleAuth struct {
	logger *zap.Logger
}

func (TailscaleAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.tailscale",
		New: func() caddy.Module { return new(TailscaleAuth) },
	}
}

func (ta* TailscaleAuth) Provision(ctx caddy.Context) error {
	ta.logger = ctx.Logger()
	return nil
}

func (ta TailscaleAuth) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	user := caddyauth.User{}

	client := tailscale.LocalClient{}
	info, err := client.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		ta.logger.Error("failed to get whois info from tailscaled", zap.String("remote_addr", r.RemoteAddr))
		return user, false, err
	}

	if len(info.Node.Tags) != 0 {
		ta.logger.Error("node has tags", zap.String("hostname", info.Node.Hostinfo.Hostname()))
		return user, false, fmt.Errorf("node %s has tags", info.Node.Hostinfo.Hostname())
	}

	user.ID = info.UserProfile.LoginName
	user.Metadata = map[string]string{
		"tailscale_user":            info.UserProfile.LoginName,
		"tailscale_name":            info.UserProfile.DisplayName,
	}
	return user, true, nil
}

func parseCaddyfile(_ httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ta TailscaleAuth

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"tailscale": caddyconfig.JSON(ta, nil),
		},
	}, nil
}

