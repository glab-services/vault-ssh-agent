package vault

import (
	"context"
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

type Client struct {
	api *vaultapi.Client
}

type NewClientOptions struct {
	Address string
	Token   string
}

func NewClient(opts NewClientOptions) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	if strings.TrimSpace(opts.Address) != "" {
		cfg.Address = strings.TrimSpace(opts.Address)
	}
	api, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	if strings.TrimSpace(opts.Token) != "" {
		api.SetToken(strings.TrimSpace(opts.Token))
	}
	return &Client{api: api}, nil
}

func (c *Client) API() *vaultapi.Client { return c.api }

type SignUserKeyOptions struct {
	Mount           string
	Role            string
	PublicKey       string
	ValidPrincipals []string
	TTL             string
}

// SignUserKey calls Vault's SSH secrets engine sign endpoint and returns the
// signed certificate public key (OpenSSH authorized_keys format).
func (c *Client) SignUserKey(ctx context.Context, opts SignUserKeyOptions) (string, error) {
	mount := strings.Trim(opts.Mount, "/")
	role := strings.Trim(opts.Role, "/")
	if mount == "" || role == "" {
		return "", fmt.Errorf("vault: mount and role are required")
	}
	if strings.TrimSpace(opts.PublicKey) == "" {
		return "", fmt.Errorf("vault: public_key is required")
	}

	path := fmt.Sprintf("%s/sign/%s", mount, role)

	data := map[string]any{
		"public_key": strings.TrimSpace(opts.PublicKey),
		"cert_type":  "user",
	}
	if len(opts.ValidPrincipals) > 0 {
		data["valid_principals"] = strings.Join(opts.ValidPrincipals, ",")
	}
	if strings.TrimSpace(opts.TTL) != "" {
		data["ttl"] = strings.TrimSpace(opts.TTL)
	}

	sec, err := c.api.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return "", fmt.Errorf("vault: write %q: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("vault: empty response for %q", path)
	}
	v, ok := sec.Data["signed_key"]
	if !ok {
		return "", fmt.Errorf("vault: response missing signed_key for %q", path)
	}
	signedKey, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("vault: signed_key is %T, want string", v)
	}
	return strings.TrimSpace(signedKey), nil
}
