package vault

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// KeyStore stores non-sensitive metadata about SSH keys in Vault (separate from
// Transit, which holds the private key material).
//
// It is implemented on top of KV (v1 or v2).
type KeyStore struct {
	api *vaultapi.Client

	mount      string
	pathPrefix string
	version    int
}

type NewKeyStoreOptions struct {
	Mount      string
	PathPrefix string
	Version    int // 1 or 2
}

func NewKeyStore(api *vaultapi.Client, opts NewKeyStoreOptions) (*KeyStore, error) {
	if api == nil {
		return nil, errors.New("vault: keystore api is required")
	}
	mount := strings.Trim(opts.Mount, "/")
	if mount == "" {
		mount = "kv"
	}
	prefix := strings.Trim(opts.PathPrefix, "/")
	if prefix == "" {
		prefix = "vault-ssh-agent"
	}
	ver := opts.Version
	if ver == 0 {
		ver = 2
	}
	if ver != 1 && ver != 2 {
		return nil, fmt.Errorf("vault: keystore version must be 1 or 2")
	}
	return &KeyStore{
		api:        api,
		mount:      mount,
		pathPrefix: prefix,
		version:    ver,
	}, nil
}

type KeyEntry struct {
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Comment       string `json:"comment,omitempty"`
	TransitMount  string `json:"transit_mount"`
	TransitKey    string `json:"transit_key"`
	PublicKey     string `json:"public_key,omitempty"`      // authorized_keys line (no trailing newline)
	Fingerprint   string `json:"fingerprint,omitempty"`     // ssh.FingerprintSHA256(pub)
	KeyType       string `json:"key_type,omitempty"`        // ssh-rsa / ssh-ed25519
	CreatedAtUnix int64  `json:"created_at_unix,omitempty"` // seconds since epoch
}

// Normalize fills defaults for older entries and reports whether it changed.
// This is used as a lightweight migration path.
func (e *KeyEntry) Normalize(defaultTransitMount string) (changed bool) {
	if e == nil {
		return false
	}
	if strings.TrimSpace(e.TransitMount) == "" && strings.TrimSpace(defaultTransitMount) != "" {
		e.TransitMount = strings.TrimSpace(defaultTransitMount)
		changed = true
	}
	if strings.TrimSpace(e.TransitKey) == "" && strings.TrimSpace(e.Name) != "" {
		// Older entries used the name as the transit key.
		e.TransitKey = e.Name
		changed = true
	}
	if e.CreatedAtUnix == 0 {
		// Unknown; leave unset.
	}
	return changed
}

func (ks *KeyStore) keyPath(name string) string {
	// Stored as <prefix>/keys/<name>
	return path.Join(ks.pathPrefix, "keys", name)
}

func (ks *KeyStore) readPath(p string) string {
	if ks.version == 2 {
		return fmt.Sprintf("%s/data/%s", ks.mount, strings.Trim(p, "/"))
	}
	return fmt.Sprintf("%s/%s", ks.mount, strings.Trim(p, "/"))
}

func (ks *KeyStore) writePath(p string) string { return ks.readPath(p) }

func (ks *KeyStore) deletePath(p string) string {
	if ks.version == 2 {
		// KV v2 supports DELETE on /data to delete latest version.
		return fmt.Sprintf("%s/data/%s", ks.mount, strings.Trim(p, "/"))
	}
	return fmt.Sprintf("%s/%s", ks.mount, strings.Trim(p, "/"))
}

func (ks *KeyStore) listPath(prefix string) string {
	prefix = strings.Trim(prefix, "/")
	if ks.version == 2 {
		return fmt.Sprintf("%s/metadata/%s", ks.mount, prefix)
	}
	return fmt.Sprintf("%s/%s", ks.mount, prefix)
}

func (ks *KeyStore) Put(ctx context.Context, e KeyEntry) error {
	if strings.TrimSpace(e.Name) == "" {
		return errors.New("vault: keystore name is required")
	}
	if strings.TrimSpace(e.TransitMount) == "" {
		return errors.New("vault: keystore transit_mount is required")
	}
	if strings.TrimSpace(e.TransitKey) == "" {
		return errors.New("vault: keystore transit_key is required")
	}
	p := ks.keyPath(e.Name)

	body := map[string]any{
		"name":            e.Name,
		"enabled":         e.Enabled,
		"comment":         e.Comment,
		"transit_mount":   e.TransitMount,
		"transit_key":     e.TransitKey,
		"public_key":      e.PublicKey,
		"fingerprint":     e.Fingerprint,
		"key_type":        e.KeyType,
		"created_at_unix": e.CreatedAtUnix,
	}
	if ks.version == 2 {
		body = map[string]any{"data": body}
	}

	_, err := ks.api.Logical().WriteWithContext(ctx, ks.writePath(p), body)
	if err != nil {
		return fmt.Errorf("vault: keystore put %q: %w", p, err)
	}
	return nil
}

func (ks *KeyStore) Get(ctx context.Context, name string) (*KeyEntry, bool, error) {
	if strings.TrimSpace(name) == "" {
		return nil, false, errors.New("vault: keystore name is required")
	}
	p := ks.keyPath(name)
	sec, err := ks.api.Logical().ReadWithContext(ctx, ks.readPath(p))
	if err != nil {
		return nil, false, fmt.Errorf("vault: keystore get %q: %w", p, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, false, nil
	}
	data := sec.Data
	if ks.version == 2 {
		inner, ok := sec.Data["data"].(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("vault: keystore get %q: unexpected data shape", p)
		}
		data = inner
	}
	e := &KeyEntry{Name: name}
	if v, ok := data["enabled"].(bool); ok {
		e.Enabled = v
	}
	if v, ok := data["comment"].(string); ok {
		e.Comment = v
	}
	if v, ok := data["transit_mount"].(string); ok {
		e.TransitMount = v
	}
	if v, ok := data["transit_key"].(string); ok {
		e.TransitKey = v
	}
	if v, ok := data["public_key"].(string); ok {
		e.PublicKey = v
	}
	if v, ok := data["fingerprint"].(string); ok {
		e.Fingerprint = v
	}
	if v, ok := data["key_type"].(string); ok {
		e.KeyType = v
	}
	switch v := data["created_at_unix"].(type) {
	case int64:
		e.CreatedAtUnix = v
	case float64:
		e.CreatedAtUnix = int64(v)
	}
	return e, true, nil
}

func (ks *KeyStore) Delete(ctx context.Context, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("vault: keystore name is required")
	}
	p := ks.keyPath(name)
	_, err := ks.api.Logical().DeleteWithContext(ctx, ks.deletePath(p))
	if err != nil {
		return fmt.Errorf("vault: keystore delete %q: %w", p, err)
	}
	return nil
}

func (ks *KeyStore) ListNames(ctx context.Context) ([]string, error) {
	prefix := path.Join(ks.pathPrefix, "keys")
	sec, err := ks.api.Logical().ListWithContext(ctx, ks.listPath(prefix))
	if err != nil {
		return nil, fmt.Errorf("vault: keystore list %q: %w", prefix, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, nil
	}
	raw, _ := sec.Data["keys"]
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("vault: keystore list: unexpected keys type %T", raw)
	}
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, strings.TrimSuffix(s, "/"))
		}
	}
	sort.Strings(out)
	return out, nil
}
