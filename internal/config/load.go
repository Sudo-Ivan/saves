// SPDX-License-Identifier: 0BSD

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Load reads path into a Config started from Defaults, applies a strict
// JSON decode, then environment overrides and secret file indirection.
func Load(path string) (*Config, error) {
	c := Defaults()
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator supplied config file
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("config: trailing data")
	}
	if err := applyEnv(&c); err != nil {
		return nil, err
	}
	if err := applySecretFiles(&c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// DecodeConfig decodes JSON directly, used by tests and tooling.
func DecodeConfig(r io.Reader) (*Config, error) {
	c := Defaults()
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("config: trailing data")
	}
	if err := applySecretFiles(&c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

const envPrefix = "SAVES_"

// applyEnv applies SAVES_<SECTION>_<KEY> overrides to scalar fields.
// Nested structs extend the path with their json key. Maps, slices, and
// pointers are not reachable through environment variables.
func applyEnv(c *Config) error {
	return walkScalars(reflect.ValueOf(c).Elem(), envPrefix, func(env string, fv reflect.Value) error {
		raw, ok := os.LookupEnv(env)
		if !ok {
			return nil
		}
		return setScalar(env, fv, raw)
	})
}

func envKey(path, jsonName string) string {
	name := strings.ToUpper(strings.ReplaceAll(jsonName, "-", "_"))
	if path == envPrefix {
		return path + name
	}
	return path + "_" + name
}

func walkScalars(v reflect.Value, path string, fn func(string, reflect.Value) error) error {
	t := v.Type()
	for i := range v.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		jname, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if jname == "" || jname == "-" {
			continue
		}
		fv := v.Field(i)
		env := envKey(path, jname)
		switch {
		case fv.Kind() == reflect.Struct && fv.Type() != reflect.TypeOf(Duration(0)) && fv.Type() != reflect.TypeOf(Size(0)):
			if err := walkScalars(fv, env, fn); err != nil {
				return err
			}
		default:
			if err := fn(env, fv); err != nil {
				return err
			}
		}
	}
	return nil
}

func setScalar(env string, fv reflect.Value, raw string) error {
	if fv.Type() == reflect.TypeOf(Duration(0)) {
		d, err := ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetInt(int64(d))
		return nil
	}
	if fv.Type() == reflect.TypeOf(Size(0)) {
		s, err := ParseSize(raw)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetInt(int64(s))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetUint(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("env %s: %w", env, err)
		}
		fv.SetFloat(n)
	}
	return nil
}

// applySecretFiles resolves <name>_file siblings into their secret
// fields. A field tagged secret gets its value from the file named by
// the sibling <Name>File field when that sibling is set.
func applySecretFiles(c *Config) error {
	return walkSecretFiles(reflect.ValueOf(c).Elem())
}

func walkSecretFiles(v reflect.Value) error {
	t := v.Type()
	fields := map[string]int{}
	for i := range v.NumField() {
		fields[t.Field(i).Name] = i
	}
	for i := range v.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			if err := walkSecretFiles(fv); err != nil {
				return err
			}
			continue
		}
		if !hasSecretTag(f) {
			continue
		}
		fi, ok := fields[f.Name+"File"]
		if !ok {
			continue
		}
		file := v.Field(fi).String()
		if file == "" {
			continue
		}
		data, err := os.ReadFile(file) // #nosec G304 -- file is the configured secret indirection path
		if err != nil {
			return fmt.Errorf("config: %s: %w", f.Tag.Get("json"), err)
		}
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(strings.TrimSpace(string(data)))
		case reflect.Slice:
			if fv.Type().Elem().Kind() != reflect.String {
				return fmt.Errorf("config: %s: unsupported secret kind", f.Name)
			}
			var lines []string
			for line := range strings.Lines(string(data)) {
				line = strings.TrimSpace(line)
				if line != "" {
					lines = append(lines, line)
				}
			}
			fv.Set(reflect.ValueOf(lines))
		}
	}
	return nil
}

var validProtocols = map[string]bool{"h1": true, "h2": true, "h3": true, "h2c": true}
var validAuthMethods = map[string]bool{"token": true, "oidc": true, "proxy": true, "anonymous": true}

// Validate checks the whole configuration for consistency.
func (c *Config) Validate() error {
	if c.Listen.Addr == "" {
		return fmt.Errorf("config: listen.addr is required")
	}
	switch c.Listen.TLS.Mode {
	case "none":
	case "files":
		if c.Listen.TLS.CertFile == "" || c.Listen.TLS.KeyFile == "" {
			return fmt.Errorf("config: listen.tls files mode requires cert_file and key_file")
		}
	case "acme":
		if c.Listen.TLS.ACME.CacheDir == "" {
			return fmt.Errorf("config: listen.tls acme mode requires cache_dir")
		}
	default:
		return fmt.Errorf("config: listen.tls.mode %q invalid", c.Listen.TLS.Mode)
	}
	if c.Listen.TLS.MinVersion != "1.2" && c.Listen.TLS.MinVersion != "1.3" {
		return fmt.Errorf("config: listen.tls.min_version must be 1.2 or 1.3")
	}
	for _, p := range c.Listen.Protocols {
		if !validProtocols[p] {
			return fmt.Errorf("config: listen.protocols %q invalid", p)
		}
	}
	if len(c.Listen.Protocols) == 0 {
		return fmt.Errorf("config: listen.protocols is empty")
	}
	switch c.Storage.Blob.Driver {
	case "fs":
		if c.Storage.Blob.FS.Root == "" {
			return fmt.Errorf("config: storage.blob.fs.root is required")
		}
		switch c.Storage.Blob.FS.Fsync {
		case "always", "dir", "never":
		default:
			return fmt.Errorf("config: storage.blob.fs.fsync %q invalid", c.Storage.Blob.FS.Fsync)
		}
	case "s3":
		if c.Storage.Blob.S3.Bucket == "" {
			return fmt.Errorf("config: storage.blob.s3.bucket is required")
		}
	default:
		return fmt.Errorf("config: storage.blob.driver %q invalid", c.Storage.Blob.Driver)
	}
	switch c.Storage.Meta.Driver {
	case "sqlite":
		if c.Storage.Meta.SQLite.Path == "" {
			return fmt.Errorf("config: storage.meta.sqlite.path is required")
		}
	case "postgres":
		if c.Storage.Meta.Postgres.DSN == "" {
			return fmt.Errorf("config: storage.meta.postgres.dsn is required")
		}
	default:
		return fmt.Errorf("config: storage.meta.driver %q invalid", c.Storage.Meta.Driver)
	}
	for _, m := range c.Auth.Order {
		if !validAuthMethods[m] {
			return fmt.Errorf("config: auth.order %q invalid", m)
		}
	}
	if c.Auth.Anonymous.Enabled && c.Auth.IPSecret == "" {
		return fmt.Errorf("config: auth.ip_secret is required when anonymous auth is enabled")
	}
	for _, a := range c.Auth.OIDC.Algs {
		switch a {
		case "RS256", "ES256", "EdDSA":
		default:
			return fmt.Errorf("config: auth.oidc.algs %q invalid, symmetric algs are not allowed", a)
		}
	}
	switch c.Registration.Mode {
	case "closed":
	case "invite":
		if len(c.Registration.InviteCodes) == 0 {
			return fmt.Errorf("config: registration invite mode requires invite_codes")
		}
	case "open":
	default:
		return fmt.Errorf("config: registration.mode %q invalid", c.Registration.Mode)
	}
	if _, ok := c.Quota.Tiers[c.Quota.DefaultTier]; !ok {
		return fmt.Errorf("config: quota.default_tier %q not defined in tiers", c.Quota.DefaultTier)
	}
	if _, ok := c.Quota.Tiers[c.Quota.AnonymousTier]; !ok && c.Auth.Anonymous.Enabled {
		return fmt.Errorf("config: quota.anonymous_tier %q not defined in tiers", c.Quota.AnonymousTier)
	}
	for id := range c.Quota.Apps {
		if err := api.ValidateAppID(id); err != nil {
			return fmt.Errorf("config: quota.apps: %w", err)
		}
	}
	if c.Quota.AllowUnknownApps != "" {
		if _, err := regexp.Compile(c.Quota.AllowUnknownApps); err != nil {
			return fmt.Errorf("config: quota.allow_unknown_apps: %w", err)
		}
	}
	l := c.Limits
	if l.MinChunkBytes <= 0 || l.MaxChunkBytes < l.MinChunkBytes {
		return fmt.Errorf("config: limits chunk sizes invalid")
	}
	if l.MaxManifestBytes <= 0 || l.MaxFileBytes <= 0 || l.MaxSnapshotBytes <= 0 {
		return fmt.Errorf("config: limits byte caps must be positive")
	}
	if c.GC.Interval <= 0 || c.GC.PendingTTL <= 0 || c.GC.GracePeriod < 0 || c.GC.BatchSize <= 0 {
		return fmt.Errorf("config: gc settings invalid")
	}
	switch c.Sandbox.Mode {
	case "off", "best-effort", "enforce":
	default:
		return fmt.Errorf("config: sandbox.mode %q invalid", c.Sandbox.Mode)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level %q invalid", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("config: log.format %q invalid", c.Log.Format)
	}
	if c.CORS.Enabled && len(c.CORS.AllowedOrigins) == 0 {
		return fmt.Errorf("config: cors.enabled requires allowed_origins")
	}
	for _, o := range c.CORS.AllowedOrigins {
		if err := validOrigin(o); err != nil {
			return err
		}
	}
	for _, cidr := range c.Proxy.TrustedCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("config: proxy.trusted_cidrs %q invalid", cidr)
		}
	}
	if err := c.validateWeb(); err != nil {
		return err
	}
	return nil
}

// validOrigin rejects wildcard and malformed cors allowed_origins
// entries; only scheme://host[:port] origin forms are accepted.
func validOrigin(o string) error {
	if o == "*" || o == "null" || o == "" {
		return fmt.Errorf("config: cors.allowed_origins %q invalid", o)
	}
	u, err := url.Parse(o)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("config: cors.allowed_origins %q invalid: must be an origin like https://host[:port]", o)
	}
	return nil
}

// validateWeb checks the web section.
func (c *Config) validateWeb() error {
	w := &c.Web
	switch w.CookieSecure {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("config: web.cookie_secure %q invalid", w.CookieSecure)
	}
	if w.PublicURL != "" {
		u, err := url.Parse(w.PublicURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
			u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("config: web.public_url must be http(s)://host[/prefix] without query, fragment or credentials")
		}
	}
	if !w.Enabled {
		return nil
	}
	if len(w.Secret) < 32 {
		return fmt.Errorf("config: web.secret is required (minimum 32 characters) when web is enabled")
	}
	if !w.PasswordLogin && !w.OIDC.Enabled {
		return fmt.Errorf("config: web requires password_login or web.oidc.enabled")
	}
	if w.LoginPerMin <= 0 || w.Session.Idle <= 0 || w.Session.Absolute <= 0 ||
		w.Session.PendingTTL <= 0 || w.Session.Max2FAAttempts <= 0 {
		return fmt.Errorf("config: web session and login limit values must be positive")
	}
	if w.OIDC.Enabled {
		if w.PublicURL == "" {
			return fmt.Errorf("config: web.public_url is required when web.oidc.enabled")
		}
		if w.OIDC.ClientID == "" {
			return fmt.Errorf("config: web.oidc.client_id is required when web.oidc.enabled")
		}
		iss := w.OIDC.Issuer
		if iss == "" {
			iss = c.Auth.OIDC.Issuer
		}
		if err := validIssuer(iss); err != nil {
			return err
		}
	}
	return nil
}

// validIssuer requires https except for loopback hosts.
func validIssuer(iss string) error {
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" {
		return fmt.Errorf("config: oidc issuer %q invalid", iss)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
		return nil
	}
	return fmt.Errorf("config: oidc issuer %q must be https (http only allowed for loopback)", iss)
}

// Redacted returns a copy of c with every secret field replaced.
func (c Config) Redacted() Config {
	out := c
	redact(reflect.ValueOf(&out).Elem())
	return out
}

func redact(v reflect.Value) {
	t := v.Type()
	for i := range v.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			redact(fv)
			continue
		}
		if !hasSecretTag(f) {
			continue
		}
		switch fv.Kind() {
		case reflect.String:
			if fv.String() != "" {
				fv.SetString("[redacted]")
			}
		case reflect.Slice:
			if fv.Len() > 0 {
				fv.Set(reflect.ValueOf([]string{"[redacted]"}))
			}
		}
	}
}

// ModeWarning returns a warning when the config file permissions are
// wider than 0640, or an empty string otherwise.
func ModeWarning(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if fi.Mode().Perm()&0o137 != 0 {
		return fmt.Sprintf("warning: config file %s has mode %04o, wider than 0640 while it may contain secrets", path, fi.Mode().Perm())
	}
	return ""
}

// Check validates the config at path and writes the effective redacted
// configuration to w, backing the savesd config check subcommand.
func Check(path string, w io.Writer) error {
	if warn := ModeWarning(path); warn != "" {
		fmt.Fprintln(w, warn)
	}
	c, err := Load(path)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(c.Redacted(), "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", out)
	return nil
}

// ReloadableView is the subset of configuration applied on SIGHUP
// without dropping connections: tiers, apps, limits, log level, and
// rate limits.
type ReloadableView struct {
	Quota  QuotaConfig  `json:"quota"`
	Limits LimitsConfig `json:"limits"`
	Log    LogConfig    `json:"log"`
	Auth   AuthConfig   `json:"auth"`
}

// Reloadable extracts the reloadable subset of c.
func (c *Config) Reloadable() ReloadableView {
	return ReloadableView{Quota: c.Quota, Limits: c.Limits, Log: c.Log, Auth: c.Auth}
}

// Diff lists top level config sections whose encoded form changed
// between a and b. Reloadable diffs are reported by DiffReloadable.
func Diff(a, b Config) []string {
	var out []string
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	t := va.Type()
	for i := range va.NumField() {
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, t.Field(i).Tag.Get("json"))
		}
	}
	return out
}

// DiffReloadable lists the reloadable keys that changed between a and b.
func DiffReloadable(a, b Config) []string {
	var out []string
	va, vb := reflect.ValueOf(a.Reloadable()), reflect.ValueOf(b.Reloadable())
	t := va.Type()
	for i := range va.NumField() {
		if !reflect.DeepEqual(va.Field(i).Interface(), vb.Field(i).Interface()) {
			out = append(out, t.Field(i).Tag.Get("json"))
		}
	}
	return out
}

func hasSecretTag(f reflect.StructField) bool {
	_, ok := f.Tag.Lookup("secret")
	return ok
}

// TrustedProxyPrefixes returns the peers allowed to set forwarded
// headers: proxy.trusted_cidrs, else auth.proxy.trusted_cidrs.
func (c *Config) TrustedProxyPrefixes() []netip.Prefix {
	src := c.Proxy.TrustedCIDRs
	if len(src) == 0 {
		src = c.Auth.Proxy.TrustedCIDRs
	}
	var out []netip.Prefix
	for _, s := range src {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
