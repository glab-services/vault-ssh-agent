package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"

	"github.com/example/vault-ssh-agent/internal/crypto/kwp"
)

type TransitKeyType string

const (
	TransitKeyTypeEd25519 TransitKeyType = "ed25519"
	TransitKeyTypeRSA2048 TransitKeyType = "rsa-2048"
	TransitKeyTypeRSA3072 TransitKeyType = "rsa-3072"
	TransitKeyTypeRSA4096 TransitKeyType = "rsa-4096"
)

type TransitManager struct {
	api *vaultapi.Client
}

func NewTransitManager(api *vaultapi.Client) *TransitManager {
	return &TransitManager{api: api}
}

func (m *TransitManager) GetWrappingKey(ctx context.Context, mount string) (*rsa.PublicKey, error) {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "transit"
	}
	path := fmt.Sprintf("%s/wrapping_key", mount)
	sec, err := m.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: unavailable (Vault OSS does not support Transit BYOK import, or transit not enabled at this mount)", path)
	}
	raw, ok := sec.Data["public_key"]
	if !ok {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: missing public_key", path)
	}
	s, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: public_key is %T", path, raw)
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: PEM decode failed", path)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: parse pkix: %w", path, err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("vault: transit wrapping_key %q: key is %T, want *rsa.PublicKey", path, pubAny)
	}
	return pub, nil
}

type TransitImportKeyOptions struct {
	Mount string
	Name  string
	Type  TransitKeyType

	// PrivateKeyDER is PKCS8 DER (unencrypted) private key bytes.
	PrivateKeyDER []byte
}

// ImportKey imports externally-generated private key material into a new
// transit-managed key. See Vault BYOK docs for wrapping details.
func (m *TransitManager) ImportKey(ctx context.Context, opts TransitImportKeyOptions) error {
	mount := strings.Trim(opts.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("vault: transit import name is required")
	}
	if strings.TrimSpace(string(opts.Type)) == "" {
		return errors.New("vault: transit import type is required")
	}
	if len(opts.PrivateKeyDER) == 0 {
		return errors.New("vault: transit import private key is required")
	}

	wrappingKey, err := m.GetWrappingKey(ctx, mount)
	if err != nil {
		return err
	}

	ephemeralAESKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralAESKey); err != nil {
		return fmt.Errorf("vault: transit import: rand aes key: %w", err)
	}

	wrappedTargetKey, err := kwp.Wrap(ephemeralAESKey, opts.PrivateKeyDER)
	if err != nil {
		return fmt.Errorf("vault: transit import: wrap target key: %w", err)
	}

	wrappedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, wrappingKey, ephemeralAESKey, []byte{})
	if err != nil {
		return fmt.Errorf("vault: transit import: wrap aes key: %w", err)
	}

	combined := append(wrappedAESKey, wrappedTargetKey...)
	ciphertext := base64.StdEncoding.EncodeToString(combined)

	path := fmt.Sprintf("%s/keys/%s/import", mount, strings.Trim(opts.Name, "/"))
	_, err = m.api.Logical().WriteWithContext(ctx, path, map[string]any{
		"type":          string(opts.Type),
		"ciphertext":    ciphertext,
		"hash_function": "SHA256",
	})
	if err != nil {
		return fmt.Errorf("vault: transit import %q: %w", path, err)
	}
	return nil
}

// AllowDeletion enables deletion for a given key by updating its config.
// Vault refuses DELETE unless deletion_allowed is set.
func (m *TransitManager) AllowDeletion(ctx context.Context, mount, name string) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("vault: transit key name is required")
	}
	path := fmt.Sprintf("%s/keys/%s/config", mount, strings.Trim(name, "/"))
	_, err := m.api.Logical().WriteWithContext(ctx, path, map[string]any{
		"deletion_allowed": true,
	})
	if err != nil {
		return fmt.Errorf("vault: transit allow deletion %q: %w", path, err)
	}
	return nil
}

type TransitCreateKeyOptions struct {
	Mount string
	Name  string
	Type  TransitKeyType
}

func (m *TransitManager) CreateKey(ctx context.Context, opts TransitCreateKeyOptions) error {
	mount := strings.Trim(opts.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(opts.Name) == "" {
		return errors.New("vault: transit key name is required")
	}
	typ := opts.Type
	if typ == "" {
		typ = TransitKeyTypeEd25519
	}
	path := fmt.Sprintf("%s/keys/%s", mount, strings.Trim(opts.Name, "/"))
	_, err := m.api.Logical().WriteWithContext(ctx, path, map[string]any{
		"type": string(typ),
	})
	if err != nil {
		return fmt.Errorf("vault: transit create key %q: %w", path, err)
	}
	return nil
}

func (m *TransitManager) ListKeys(ctx context.Context, mount string) ([]string, error) {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "transit"
	}
	sec, err := m.api.Logical().ListWithContext(ctx, fmt.Sprintf("%s/keys", mount))
	if err != nil {
		return nil, fmt.Errorf("vault: transit list keys: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return nil, nil
	}
	raw, _ := sec.Data["keys"]
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("vault: transit list keys: unexpected keys type %T", raw)
	}
	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *TransitManager) DeleteKey(ctx context.Context, mount, name string) error {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("vault: transit key name is required")
	}
	path := fmt.Sprintf("%s/keys/%s", mount, strings.Trim(name, "/"))
	_, err := m.api.Logical().DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("vault: transit delete key %q: %w", path, err)
	}
	return nil
}

// ExportPublicKey fetches the current public key material for an asymmetric
// transit key and converts it into an ssh.PublicKey suitable for ssh-agent.
func (m *TransitManager) ExportPublicKey(ctx context.Context, mount, name string) (ssh.PublicKey, TransitKeyType, error) {
	mount = strings.Trim(mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(name) == "" {
		return nil, "", errors.New("vault: transit key name is required")
	}

	// Prefer the export endpoint for public keys. This generally does not require
	// exportable=true for private keys, but Vault behavior may vary by version and
	// policy; callers should grant GET on this path.
	path := fmt.Sprintf("%s/export/public-key/%s/latest", mount, strings.Trim(name, "/"))
	sec, err := m.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, "", fmt.Errorf("vault: transit export public key %q: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, "", fmt.Errorf("vault: transit export public key %q: empty response", path)
	}
	keysAny, ok := sec.Data["keys"].(map[string]any)
	if !ok || len(keysAny) == 0 {
		return nil, "", fmt.Errorf("vault: transit export public key %q: missing keys", path)
	}
	// "latest" export returns a single version in the keys map; take the max key.
	var (
		maxVer int
		val    string
	)
	for k, v := range keysAny {
		ver, _ := strconv.Atoi(k)
		if ver >= maxVer {
			if s, ok := v.(string); ok {
				maxVer = ver
				val = s
			}
		}
	}
	if strings.TrimSpace(val) == "" {
		return nil, "", fmt.Errorf("vault: transit export public key %q: empty key value", path)
	}

	pubBytes, err := decodeMaybePEMOrB64(val)
	if err != nil {
		return nil, "", err
	}

	// Many Vault versions return PEM; handle both PEM and DER.
	if block, _ := pem.Decode(pubBytes); block != nil {
		pubBytes = block.Bytes
	}

	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		return nil, "", fmt.Errorf("vault: parse transit public key: %w", err)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		spk, err := ssh.NewPublicKey(k)
		return spk, TransitKeyTypeEd25519, err
	case *rsa.PublicKey:
		spk, err := ssh.NewPublicKey(k)
		return spk, TransitKeyType("rsa"), err
	default:
		return nil, "", fmt.Errorf("vault: unsupported transit public key type %T", pub)
	}
}

func decodeMaybePEMOrB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "-----BEGIN ") {
		return []byte(s), nil
	}
	// Some Vault endpoints may return base64 without PEM armor.
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		// If it isn't base64, treat it as plain text bytes.
		return []byte(s), nil
	}
	return b, nil
}

type TransitSignAlgorithm string

const (
	TransitSignAlgorithmPKCS1v15 TransitSignAlgorithm = "pkcs1v15"
)

type TransitHashAlgorithm string

const (
	TransitHashSHA2256 TransitHashAlgorithm = "sha2-256"
	TransitHashSHA2512 TransitHashAlgorithm = "sha2-512"
	TransitHashNone    TransitHashAlgorithm = "none"
)

type TransitSignOptions struct {
	Mount string
	Name  string

	// Input is base64-encoded by Vault. If Prehashed is true, this is the digest,
	// otherwise it's the raw message bytes.
	Input     []byte
	Prehashed bool

	HashAlgorithm      TransitHashAlgorithm
	SignatureAlgorithm TransitSignAlgorithm // RSA only; use pkcs1v15 for OpenSSH
}

func (m *TransitManager) Sign(ctx context.Context, opts TransitSignOptions) ([]byte, error) {
	mount := strings.Trim(opts.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("vault: transit key name is required")
	}

	path := fmt.Sprintf("%s/sign/%s", mount, strings.Trim(opts.Name, "/"))
	body := map[string]any{
		"input":          base64.StdEncoding.EncodeToString(opts.Input),
		"prehashed":      opts.Prehashed,
		"hash_algorithm": string(opts.HashAlgorithm),
	}
	if opts.SignatureAlgorithm != "" {
		body["signature_algorithm"] = string(opts.SignatureAlgorithm)
	}

	sec, err := m.api.Logical().WriteWithContext(ctx, path, body)
	if err != nil {
		return nil, fmt.Errorf("vault: transit sign %q: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("vault: transit sign %q: empty response", path)
	}
	raw, ok := sec.Data["signature"]
	if !ok {
		return nil, fmt.Errorf("vault: transit sign %q: missing signature", path)
	}
	sigStr, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("vault: transit sign %q: signature is %T", path, raw)
	}
	sigStr = strings.TrimSpace(sigStr)
	const prefix = "vault:v1:"
	if strings.HasPrefix(sigStr, prefix) {
		sigStr = strings.TrimPrefix(sigStr, prefix)
	}
	sig, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return nil, fmt.Errorf("vault: transit sign %q: decode signature: %w", path, err)
	}
	return sig, nil
}
