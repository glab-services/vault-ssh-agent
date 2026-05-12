package agentd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/example/vault-ssh-agent/internal/config"
	"github.com/example/vault-ssh-agent/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var transitKeyNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// Daemon is an SSH-agent-compatible server that keeps private key material in
// Vault Transit (no local private keys on disk). It signs SSH challenges by
// calling Vault Transit sign API.
//
// Note: we still necessarily keep the socket on disk; "no caching" here means
// we do not persist private keys or certs locally.
type Daemon struct {
	log *slog.Logger
	cfg *config.Config

	vaultAPI *vault.Client
	transit  *vault.TransitManager
	keystore *vault.KeyStore
}

func New(log *slog.Logger, cfg *config.Config) (*Daemon, error) {
	if log == nil {
		return nil, errors.New("agentd: log is required")
	}
	if cfg == nil {
		return nil, errors.New("agentd: cfg is required")
	}
	return &Daemon{log: log, cfg: cfg}, nil
}

func (d *Daemon) InitVault(ctx context.Context) error {
	token, err := vault.LoadToken(ctx, vault.LoadTokenOptions{
		Source:   vault.TokenSource(d.cfg.Vault.TokenSource),
		EnvVar:   d.cfg.Vault.TokenEnvVar,
		FilePath: d.cfg.Vault.TokenFile,
		Command:  d.cfg.Vault.TokenCommand,
	})
	if err != nil {
		return err
	}
	vc, err := vault.NewClient(vault.NewClientOptions{
		Address: d.cfg.Vault.Address,
		Token:   token,
	})
	if err != nil {
		return err
	}
	d.vaultAPI = vc
	d.transit = vault.NewTransitManager(vc.API())
	ks, err := vault.NewKeyStore(vc.API(), vault.NewKeyStoreOptions{
		Mount:      d.cfg.Vault.KeyStore.Mount,
		PathPrefix: d.cfg.Vault.KeyStore.PathPrefix,
		Version:    d.cfg.Vault.KeyStore.Version,
	})
	if err != nil {
		return err
	}
	d.keystore = ks
	return nil
}

func (d *Daemon) Serve(ctx context.Context) error {
	if d.transit == nil || d.keystore == nil {
		return errors.New("agentd: vault transit client not initialized")
	}

	if err := ensureSocketDir(d.cfg.Agent.SocketPath); err != nil {
		return err
	}
	if err := maybeRemoveExistingSocket(d.cfg.Agent.SocketPath, d.cfg.Agent.LockOnStart); err != nil {
		return err
	}

	ln, err := net.Listen("unix", d.cfg.Agent.SocketPath)
	if err != nil {
		return fmt.Errorf("agentd: listen %q: %w", d.cfg.Agent.SocketPath, err)
	}
	defer ln.Close()
	_ = os.Chmod(d.cfg.Agent.SocketPath, 0o600)

	d.log.Info("agent listening", "sock", d.cfg.Agent.SocketPath)

	a := &agentImpl{d: d}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("agentd: accept: %w", err)
		}
		go func() {
			defer c.Close()
			_ = agent.ServeAgent(a, c)
		}()
	}
}

type agentImpl struct {
	d *Daemon
}

func (a *agentImpl) List() ([]*agent.Key, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	names, err := a.d.keystore.ListNames(ctx)
	if err != nil {
		return nil, err
	}

	var out []*agent.Key
	for _, name := range names {
		e, ok, err := a.d.keystore.Get(ctx, name)
		if err != nil {
			a.d.log.Warn("keystore get failed", "name", name, "err", err)
			continue
		}
		if !ok || !e.Enabled {
			continue
		}
		if e.Normalize(a.d.cfg.Vault.TransitMount) {
			_ = a.d.keystore.Put(ctx, *e) // best-effort migration
		}
		var blob []byte
		var format string
		if strings.TrimSpace(e.PublicKey) != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
			if err != nil {
				a.d.log.Warn("keystore public_key parse failed; falling back to transit export", "name", name, "err", err)
			} else {
				format = pk.Type()
				blob = pk.Marshal()
			}
		}
		if blob == nil {
			pub, _, err := a.d.transit.ExportPublicKey(ctx, e.TransitMount, e.TransitKey)
			if err != nil {
				a.d.log.Warn("export public key failed", "name", name, "err", err)
				continue
			}
			format = pub.Type()
			blob = pub.Marshal()
		}
		out = append(out, &agent.Key{Format: format, Blob: blob, Comment: name})
	}
	return out, nil
}

func (a *agentImpl) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *agentImpl) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var (
		ent *vault.KeyEntry
		typ string
	)

	names, err := a.d.keystore.ListNames(ctx)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		e, ok, err := a.d.keystore.Get(ctx, name)
		if err != nil || !ok || !e.Enabled {
			continue
		}
		if e.Normalize(a.d.cfg.Vault.TransitMount) {
			_ = a.d.keystore.Put(ctx, *e) // best-effort migration
		}
		if strings.TrimSpace(e.PublicKey) != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
			if err == nil && bytes.Equal(pk.Marshal(), key.Marshal()) {
				ent = e
				typ = pk.Type()
				break
			}
		} else {
			pub, _, err := a.d.transit.ExportPublicKey(ctx, e.TransitMount, e.TransitKey)
			if err != nil {
				continue
			}
			if bytes.Equal(pub.Marshal(), key.Marshal()) {
				ent = e
				typ = pub.Type()
				break
			}
		}
	}
	if ent == nil {
		return nil, fmt.Errorf("agentd: unknown key")
	}

	switch typ {
	case ssh.KeyAlgoRSA:
		return a.signRSA(ctx, *ent, data, flags)
	case ssh.KeyAlgoED25519:
		sig, err := a.d.transit.Sign(ctx, vault.TransitSignOptions{
			Mount:         ent.TransitMount,
			Name:          ent.TransitKey,
			Input:         data,
			Prehashed:     false,
			HashAlgorithm: vault.TransitHashSHA2256, // ignored for ed25519 per Vault docs
		})
		if err != nil {
			return nil, err
		}
		return &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: sig}, nil
	default:
		return nil, fmt.Errorf("agentd: unsupported key type %q", typ)
	}
}

func (a *agentImpl) signRSA(ctx context.Context, e vault.KeyEntry, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	// Per SSH agent protocol, rsa-sha2 flags request the signature method. We do
	// not support legacy RSA-SHA1 ("ssh-rsa") signatures.
	// See: draft-ietf-sshm-ssh-agent (signature flags). citeturn0search2
	//
	// In practice, OpenSSH sets one of the SHA2 flags for RSA keys unless forced
	// to legacy; if a client doesn't, we default to rsa-sha2-256.
	var (
		hashAlg vault.TransitHashAlgorithm
		sum     []byte
		fmtAlg  string
	)
	switch flags {
	case agent.SignatureFlagRsaSha512:
		d := sha512.Sum512(data)
		sum = d[:]
		hashAlg = vault.TransitHashSHA2512
		fmtAlg = ssh.KeyAlgoRSASHA512
	case agent.SignatureFlagRsaSha256:
		d := sha256.Sum256(data)
		sum = d[:]
		hashAlg = vault.TransitHashSHA2256
		fmtAlg = ssh.KeyAlgoRSASHA256
	default:
		if !a.d.cfg.Vault.AllowLegacySSHRSA {
			return nil, fmt.Errorf("agentd: refusing legacy ssh-rsa (RSA-SHA1) signature request; set vault.allow_legacy_ssh_rsa=true to allow")
		}
		// Legacy-compatible fallback: return rsa-sha2-256 anyway, since Vault Transit
		// won't produce RSA-SHA1. This may not satisfy legacy clients.
		d := sha256.Sum256(data)
		sum = d[:]
		hashAlg = vault.TransitHashSHA2256
		fmtAlg = ssh.KeyAlgoRSASHA256
	}

	sig, err := a.d.transit.Sign(ctx, vault.TransitSignOptions{
		Mount:              e.TransitMount,
		Name:               e.TransitKey,
		Input:              sum,
		Prehashed:          true,
		HashAlgorithm:      hashAlg,
		SignatureAlgorithm: vault.TransitSignAlgorithmPKCS1v15,
	})
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{Format: fmtAlg, Blob: sig}, nil
}

func (a *agentImpl) Add(k agent.AddedKey) error {
	if a.d.transit == nil || a.d.keystore == nil {
		err := errors.New("agentd: vault not initialized")
		a.d.log.Error("add identity failed", "err", err)
		return err
	}
	if k.PrivateKey == nil {
		err := errors.New("agentd: missing private key")
		a.d.log.Error("add identity failed", "err", err)
		return err
	}
	if k.ConfirmBeforeUse || k.LifetimeSecs != 0 || len(k.ConstraintExtensions) != 0 {
		// TODO: model constraints in Vault metadata; ignore for MVP.
	}
	if k.Certificate != nil {
		// TODO: certificate support (Milestone D). For now, refuse to avoid a
		// confusing partially-imported state.
		err := errors.New("agentd: adding certificates via ssh-add is not supported yet")
		a.d.log.Error("add identity failed", "err", err)
		return err
	}

	keyType, pkcs8DER, pub, err := transitImportInputFromAddedKey(k.PrivateKey)
	if err != nil {
		a.d.log.Error("add identity failed", "err", err)
		return err
	}

	fp := ssh.FingerprintSHA256(pub)
	name := keyNameForAddedKey(k.Comment, pub) // display-ish name
	transitKey := transitKeyNameForFingerprint(fp)
	transitMount := strings.TrimSpace(a.d.cfg.Vault.TransitMount)
	if transitMount == "" {
		transitMount = "transit"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Dedup by fingerprint: if we already imported this key, just re-enable it.
	names, err := a.d.keystore.ListNames(ctx)
	if err != nil {
		a.d.log.Error("add identity failed", "err", err)
		return err
	}
	for _, existingName := range names {
		e, ok, err := a.d.keystore.Get(ctx, existingName)
		if err != nil || !ok {
			continue
		}
		if strings.TrimSpace(e.Fingerprint) != "" && e.Fingerprint == fp {
			if !e.Enabled {
				e.Enabled = true
				if strings.TrimSpace(k.Comment) != "" {
					e.Comment = k.Comment
				}
				if err := a.d.keystore.Put(ctx, *e); err != nil {
					a.d.log.Error("add identity failed", "err", err)
					return err
				}
				return nil
			}
			err := fmt.Errorf("agentd: key already added")
			a.d.log.Error("add identity failed", "err", err)
			return err
		}
	}

	// If the chosen name collides, append a stable short suffix.
	if _, ok, err := a.d.keystore.Get(ctx, name); err != nil {
		a.d.log.Error("add identity failed", "err", err)
		return err
	} else if ok {
		name = name + "-" + shortFingerprint(fp)
	}

	if err := a.d.transit.ImportKey(ctx, vault.TransitImportKeyOptions{
		Mount:         transitMount,
		Name:          transitKey,
		Type:          keyType,
		PrivateKeyDER: pkcs8DER,
	}); err != nil {
		a.d.log.Error("add identity failed", "err", err)
		return err
	}

	if err := a.d.keystore.Put(ctx, vault.KeyEntry{
		Name:          name,
		Enabled:       true,
		Comment:       k.Comment,
		TransitMount:  transitMount,
		TransitKey:    transitKey,
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint:   fp,
		KeyType:       pub.Type(),
		CreatedAtUnix: time.Now().Unix(),
	}); err != nil {
		a.d.log.Error("add identity failed", "err", err)
		return err
	}

	return nil
}

func (a *agentImpl) Remove(pub ssh.PublicKey) error {
	if a.d.transit == nil || a.d.keystore == nil {
		err := errors.New("agentd: vault not initialized")
		a.d.log.Error("remove identity failed", "err", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	names, err := a.d.keystore.ListNames(ctx)
	if err != nil {
		a.d.log.Error("remove identity failed", "err", err)
		return err
	}
	for _, name := range names {
		e, ok, err := a.d.keystore.Get(ctx, name)
		if err != nil || !ok {
			continue
		}
		if e.Normalize(a.d.cfg.Vault.TransitMount) {
			_ = a.d.keystore.Put(ctx, *e) // best-effort migration
		}
		var match bool
		if strings.TrimSpace(e.PublicKey) != "" {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.PublicKey))
			match = err == nil && bytes.Equal(pk.Marshal(), pub.Marshal())
		} else {
			tpub, _, err := a.d.transit.ExportPublicKey(ctx, e.TransitMount, e.TransitKey)
			match = err == nil && bytes.Equal(tpub.Marshal(), pub.Marshal())
		}
		if match {
			if a.d.cfg.Vault.DeleteTransitOnRemove {
				_ = a.d.transit.AllowDeletion(ctx, e.TransitMount, e.TransitKey)
				_ = a.d.transit.DeleteKey(ctx, e.TransitMount, e.TransitKey)
				if err := a.d.keystore.Delete(ctx, e.Name); err != nil {
					a.d.log.Error("remove identity failed", "err", err)
					return err
				}
				return nil
			}

			// Default: stop advertising it; don't delete key material.
			e.Enabled = false
			if err := a.d.keystore.Put(ctx, *e); err != nil {
				a.d.log.Error("remove identity failed", "err", err)
				return err
			}
			return nil
		}
	}
	err = fmt.Errorf("agentd: key not found")
	a.d.log.Error("remove identity failed", "err", err)
	return err
}

func (a *agentImpl) RemoveAll() error {
	if a.d.keystore == nil {
		err := errors.New("agentd: vault not initialized")
		a.d.log.Error("remove_all identities failed", "err", err)
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	names, err := a.d.keystore.ListNames(ctx)
	if err != nil {
		a.d.log.Error("remove_all identities failed", "err", err)
		return err
	}
	for _, name := range names {
		e, ok, err := a.d.keystore.Get(ctx, name)
		if err != nil || !ok {
			continue
		}
		if e.Enabled {
			e.Enabled = false
			if err := a.d.keystore.Put(ctx, *e); err != nil {
				a.d.log.Error("remove_all identities failed", "err", err)
				return err
			}
		}
	}
	return nil
}
func (a *agentImpl) Lock(_ []byte) error   { return errors.New("agentd: lock not supported") }
func (a *agentImpl) Unlock(_ []byte) error { return errors.New("agentd: unlock not supported") }

func (a *agentImpl) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("agentd: Signers() not supported for transit-backed keys")
}

func (a *agentImpl) Extension(_ string, _ []byte) ([]byte, error) {
	return nil, errors.New("agentd: extensions not supported")
}

func transitImportInputFromAddedKey(priv any) (vault.TransitKeyType, []byte, ssh.PublicKey, error) {
	// ssh-add may pass *ed25519.PrivateKey (pointer) while x509 PKCS8 expects
	// ed25519.PrivateKey (value). Normalize first.
	switch k := priv.(type) {
	case *ed25519.PrivateKey:
		priv = *k
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", nil, nil, fmt.Errorf("agentd: unsupported private key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", nil, nil, fmt.Errorf("agentd: marshal pkcs8: %w", err)
	}

	switch k := priv.(type) {
	case ed25519.PrivateKey:
		_ = k
		return vault.TransitKeyTypeEd25519, der, signer.PublicKey(), nil
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		switch bits {
		case 2048:
			return vault.TransitKeyTypeRSA2048, der, signer.PublicKey(), nil
		case 3072:
			return vault.TransitKeyTypeRSA3072, der, signer.PublicKey(), nil
		case 4096:
			return vault.TransitKeyTypeRSA4096, der, signer.PublicKey(), nil
		default:
			return "", nil, nil, fmt.Errorf("agentd: unsupported rsa key size %d (supported: 2048/3072/4096)", bits)
		}
	default:
		return "", nil, nil, fmt.Errorf("agentd: unsupported key type %T (supported: ed25519, rsa)", priv)
	}
}

func keyNameForAddedKey(comment string, pub ssh.PublicKey) string {
	if s := strings.TrimSpace(comment); s != "" {
		return s
	}
	fp := strings.TrimPrefix(ssh.FingerprintSHA256(pub), "SHA256:")
	fp = strings.TrimRight(fp, "=")
	fp = strings.ReplaceAll(fp, "+", "-")
	fp = strings.ReplaceAll(fp, "/", "_")
	return "imported-" + strings.ToLower(fp)
}

func sanitizeTransitKeyName(name string) string {
	s := strings.TrimSpace(name)
	s = strings.ToLower(s)
	s = transitKeyNameSanitizer.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "ssh-key"
	}
	return s
}

func transitKeyNameForFingerprint(fp string) string {
	// fp is typically "SHA256:<base64>".
	s := strings.TrimSpace(fp)
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ToLower(s)
	return "ssh-" + s
}

func shortFingerprint(fp string) string {
	s := strings.TrimSpace(fp)
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.TrimRight(s, "=")
	s = strings.ReplaceAll(s, "+", "")
	s = strings.ReplaceAll(s, "/", "")
	if len(s) > 10 {
		s = s[:10]
	}
	if s == "" {
		return "key"
	}
	return strings.ToLower(s)
}

func ensureSocketDir(sockPath string) error {
	dir := filepath.Dir(sockPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("agentd: mkdir %q: %w", dir, err)
	}
	_ = os.Chmod(dir, 0o700)
	return nil
}

func maybeRemoveExistingSocket(sockPath string, lockOnStart bool) error {
	fi, err := os.Lstat(sockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("agentd: stat %q: %w", sockPath, err)
	}
	if lockOnStart {
		return fmt.Errorf("agentd: socket already exists and lock_on_start=true: %q", sockPath)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("agentd: path exists and is not a unix socket: %q", sockPath)
	}
	if err := os.Remove(sockPath); err != nil {
		return fmt.Errorf("agentd: remove existing socket %q: %w", sockPath, err)
	}
	return nil
}
