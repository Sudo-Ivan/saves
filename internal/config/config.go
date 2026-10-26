// SPDX-License-Identifier: 0BSD

package config

import (
	"github.com/Sudo-Ivan/saves/pkg/api"
)

// Config is the root savesd configuration.
type Config struct {
	Listen       ListenConfig       `json:"listen" doc:"main HTTP listener"`
	Ops          OpsConfig          `json:"ops" doc:"operational listener for health, metrics, pprof"`
	Storage      StorageConfig      `json:"storage" doc:"blob and metadata backends"`
	Auth         AuthConfig         `json:"auth" doc:"authentication method chain"`
	Registration RegistrationConfig `json:"registration" doc:"self service user registration"`
	Audit        AuditConfig        `json:"audit" doc:"admin and auth audit log"`
	Analytics    AnalyticsConfig    `json:"analytics" doc:"request and usage metrics collector"`
	Admin        AdminConfig        `json:"admin" doc:"administrative operations"`
	Quota        QuotaConfig        `json:"quota" doc:"tiers, defaults, and per app policy"`
	Limits       LimitsConfig       `json:"limits" doc:"manifest, chunk, and request limits"`
	GC           GCConfig           `json:"gc" doc:"garbage collection schedule"`
	Sandbox      SandboxConfig      `json:"sandbox" doc:"Landlock sandbox policy"`
	Log          LogConfig          `json:"log" doc:"logging"`
	CORS         CORSConfig         `json:"cors" doc:"cross origin resource sharing, off by default"`
	Metrics      MetricsConfig      `json:"metrics" doc:"Prometheus metrics"`
	Web          WebConfig          `json:"web" doc:"browser UI, off by default"`
	Bandwidth    BandwidthConfig    `json:"bandwidth" doc:"bandwidth accounting and limits, off by default"`
	Proxy        ProxyTrustConfig   `json:"proxy" doc:"reverse proxy trust for forwarded headers"`
}

// WebConfig controls the built in browser UI.
type WebConfig struct {
	Enabled         bool             `json:"enabled" doc:"serve the web UI"`
	Description     string           `json:"description" doc:"short site description shown on the homepage"`
	TermsURL        string           `json:"terms_url" doc:"terms of service link"`
	PrivacyURL      string           `json:"privacy_url" doc:"privacy policy link"`
	Contact         string           `json:"contact" doc:"contact link, https or mailto or relative"`
	ClientURL       string           `json:"client_url" doc:"where users download the client, empty hides the link"`
	InstanceName    string           `json:"instance_name" doc:"display name used in pages and TOTP issuer"`
	APIDocs         bool             `json:"api_docs" doc:"serve the public API reference at /docs"`
	PublicURL       string           `json:"public_url" doc:"external base URL like https://host/prefix, required for web OIDC"`
	Homepage        bool             `json:"homepage" doc:"show the landing page at /, otherwise redirect to the sign in page"`
	PasswordLogin   bool             `json:"password_login" doc:"allow username and password sign in"`
	Secret          string           `json:"secret" doc:"master secret for cookie and TOTP sealing, minimum 32 characters" secret:""`
	SecretFile      string           `json:"secret_file" doc:"path to file containing web.secret"`
	Session         WebSessionConfig `json:"session" doc:"session lifetimes and limits"`
	CookieSecure    string           `json:"cookie_secure" doc:"auto, always, or never: Secure cookie attribute control"`
	HSTS            HSTSConfig       `json:"hsts" doc:"Strict-Transport-Security emission"`
	Require2FA      bool             `json:"require_2fa" doc:"force password users to set up TOTP before using the UI"`
	Require2FAAdmin bool             `json:"require_2fa_admin" doc:"force admins signed in by password to set up TOTP"`
	LoginPerMin     float64          `json:"login_per_min" doc:"login attempts per minute per client IP prefix"`
	OIDC            WebOIDCConfig    `json:"oidc" doc:"OIDC authorization code sign in"`
}

// WebSessionConfig controls session lifetimes.
type WebSessionConfig struct {
	Idle           Duration `json:"idle" doc:"idle timeout since last activity"`
	Absolute       Duration `json:"absolute" doc:"maximum session lifetime"`
	PendingTTL     Duration `json:"pending_ttl" doc:"window to finish the second factor step"`
	Max2FAAttempts int      `json:"max_2fa_attempts" doc:"wrong codes allowed on a pending session"`
}

// HSTSConfig controls the Strict-Transport-Security header.
type HSTSConfig struct {
	Enabled           bool     `json:"enabled" doc:"emit HSTS on https requests"`
	MaxAge            Duration `json:"max_age" doc:"max-age value"`
	IncludeSubdomains bool     `json:"include_subdomains" doc:"add includeSubDomains"`
	Preload           bool     `json:"preload" doc:"add preload"`
}

// WebOIDCConfig controls OIDC sign in with authorization code and PKCE.
type WebOIDCConfig struct {
	Enabled          bool   `json:"enabled" doc:"offer OIDC sign in"`
	Issuer           string `json:"issuer" doc:"issuer URL, defaults to auth.oidc.issuer"`
	ClientID         string `json:"client_id" doc:"registered client id"`
	ClientSecret     string `json:"client_secret" doc:"client secret, empty means public client with PKCE only" secret:""`
	ClientSecretFile string `json:"client_secret_file" doc:"path to file containing client_secret"`
	Scopes           string `json:"scopes" doc:"space separated scope request"`
	Label            string `json:"label" doc:"sign in button label"`
	AutoProvision    bool   `json:"auto_provision" doc:"create a user for a first time subject"`
	AdminClaim       string `json:"admin_claim" doc:"id_token claim inspected for admin"`
	AdminValue       string `json:"admin_value" doc:"claim value granting admin"`
}

// ProxyTrustConfig controls trust in reverse proxy forwarded headers.
type ProxyTrustConfig struct {
	TrustedCIDRs []string `json:"trusted_cidrs" doc:"CIDRs allowed to set X-Forwarded-* and Forwarded headers"`
	RealIPHeader string   `json:"real_ip_header" doc:"extra single IP header honored from trusted peers, like X-Real-IP"`
}

// ListenConfig controls the main HTTP listener.
type ListenConfig struct {
	Addr              string      `json:"addr" doc:"listen address"`
	TLS               TLSConfig   `json:"tls" doc:"TLS mode and material"`
	Protocols         []string    `json:"protocols" doc:"enabled protocols: h1, h2, h3, h2c"`
	H3Addr            string      `json:"h3_addr" doc:"UDP listen address for HTTP/3, defaults to addr"`
	AltSvc            string      `json:"alt_svc" doc:"Alt-Svc header value advertised on TCP responses"`
	ReadHeaderTimeout Duration    `json:"read_header_timeout" doc:"deadline for reading request headers"`
	IdleTimeout       Duration    `json:"idle_timeout" doc:"keep alive idle timeout"`
	ShutdownTimeout   Duration    `json:"shutdown_timeout" doc:"graceful drain deadline on SIGTERM"`
	MaxHeaderBytes    Size        `json:"max_header_bytes" doc:"largest accepted request header block"`
	MaxConns          int         `json:"max_conns" doc:"max simultaneous connections, 0 is unlimited"`
	MinThroughput     Size        `json:"min_throughput" doc:"bytes per second floor that extends per request deadlines"`
	UDPBufferBytes    Size        `json:"udp_buffer_bytes" doc:"UDP socket buffer size for HTTP/3"`
	H2                HTTP2Config `json:"h2" doc:"HTTP/2 settings"`
}

// TLSConfig selects certificate material for the listener.
type TLSConfig struct {
	Mode       string     `json:"mode" doc:"files, acme, or none"`
	CertFile   string     `json:"cert_file" doc:"certificate chain PEM for mode files"`
	KeyFile    string     `json:"key_file" doc:"private key PEM for mode files" secret:"path"`
	MinVersion string     `json:"min_version" doc:"1.2 or 1.3"`
	HotReload  bool       `json:"hot_reload" doc:"poll cert files for changes and reload without restart"`
	ACME       ACMEConfig `json:"acme" doc:"ACME client settings for mode acme"`
}

// ACMEConfig controls automatic certificate issuance.
type ACMEConfig struct {
	Email        string   `json:"email" doc:"contact email for the ACME account"`
	DirectoryURL string   `json:"directory_url" doc:"ACME directory URL, empty means the autocert default"`
	CacheDir     string   `json:"cache_dir" doc:"directory holding ACME account and certificate cache"`
	Hosts        []string `json:"hosts" doc:"allowed certificate host names"`
}

// HTTP2Config tunes the HTTP/2 server.
type HTTP2Config struct {
	MaxConcurrentStreams uint32   `json:"max_concurrent_streams" doc:"max streams per connection"`
	MaxReadFrameSize     uint32   `json:"max_read_frame_size" doc:"largest accepted frame payload"`
	IdleTimeout          Duration `json:"idle_timeout" doc:"connection idle timeout"`
}

// OpsConfig controls the operational listener.
type OpsConfig struct {
	Enabled bool   `json:"enabled" doc:"serve the ops listener"`
	Addr    string `json:"addr" doc:"listen address, loopback recommended"`
	Pprof   bool   `json:"pprof" doc:"expose /debug/pprof"`
}

// StorageConfig selects blob and metadata backends.
type StorageConfig struct {
	Blob BlobConfig `json:"blob" doc:"content addressed blob store"`
	Meta MetaConfig `json:"meta" doc:"metadata database"`
}

// BlobConfig selects the blob backend.
type BlobConfig struct {
	Driver string   `json:"driver" doc:"fs or s3"`
	FS     FSConfig `json:"fs" doc:"filesystem backend options"`
	S3     S3Config `json:"s3" doc:"S3 backend options"`
}

// FSConfig configures the filesystem blob store.
type FSConfig struct {
	Root  string `json:"root" doc:"blob store root directory"`
	Fsync string `json:"fsync" doc:"fsync policy: always, dir, or never"`
}

// S3Config configures the S3 blob store.
type S3Config struct {
	Endpoint       string   `json:"endpoint" doc:"S3 endpoint host or URL, empty for AWS"`
	Region         string   `json:"region" doc:"bucket region"`
	Bucket         string   `json:"bucket" doc:"bucket name"`
	Prefix         string   `json:"prefix" doc:"key prefix prepended to all objects"`
	AccessKey      string   `json:"access_key" doc:"access key id" secret:""`
	SecretKey      string   `json:"secret_key" doc:"secret access key" secret:""`
	SecretKeyFile  string   `json:"secret_key_file" doc:"path to file containing the secret key"`
	PathStyle      bool     `json:"path_style" doc:"use path style addressing instead of virtual host"`
	Insecure       bool     `json:"insecure" doc:"use plain HTTP instead of HTTPS"`
	RequestTimeout Duration `json:"request_timeout" doc:"per request deadline"`
	MaxRetries     int      `json:"max_retries" doc:"retry attempts for transient failures"`
}

// MetaConfig selects the metadata backend.
type MetaConfig struct {
	Driver   string         `json:"driver" doc:"sqlite or postgres"`
	SQLite   SQLiteConfig   `json:"sqlite" doc:"sqlite options"`
	Postgres PostgresConfig `json:"postgres" doc:"postgres options"`
}

// SQLiteConfig configures the embedded metadata database.
type SQLiteConfig struct {
	Path string `json:"path" doc:"database file path"`
}

// PostgresConfig configures the postgres metadata database.
type PostgresConfig struct {
	DSN      string `json:"dsn" doc:"connection string" secret:""`
	DSNFile  string `json:"dsn_file" doc:"path to file containing the DSN"`
	MaxConns int32  `json:"max_conns" doc:"pool maximum connections"`
	MinConns int32  `json:"min_conns" doc:"pool minimum connections"`
}

// AuthConfig controls the authentication chain.
type AuthConfig struct {
	Order            []string        `json:"order" doc:"method chain order: token, oidc, proxy, anonymous"`
	Token            TokenAuthConfig `json:"token" doc:"opaque bearer token method"`
	OIDC             OIDCConfig      `json:"oidc" doc:"OIDC JWT bearer method"`
	Proxy            ProxyConfig     `json:"proxy" doc:"trusted reverse proxy header method"`
	Anonymous        AnonymousConfig `json:"anonymous" doc:"anonymous method keyed by client IP"`
	IPSecret         string          `json:"ip_secret" doc:"secret for anonymous identity hashing" secret:""`
	IPSecretFile     string          `json:"ip_secret_file" doc:"path to file containing ip_secret"`
	FailedAuthPerSec float64         `json:"failed_auth_per_sec" doc:"failed auth rate limit per IP"`
}

// TokenAuthConfig configures opaque bearer tokens.
type TokenAuthConfig struct {
	Enabled          bool     `json:"enabled" doc:"accept sv1_ bearer tokens"`
	LastUsedInterval Duration `json:"last_used_interval" doc:"minimum interval between last_used writes"`
	CacheTTL         Duration `json:"cache_ttl" doc:"token validation cache lifetime; revocation propagates within this window"`
	MaxTTL           Duration `json:"max_ttl" doc:"maximum token lifetime; 0 unlimited"`
	DefaultTTL       Duration `json:"default_ttl" doc:"expiry the web create form preselects; does not change API default of never"`
	MaxPerUser       int      `json:"max_per_user" doc:"maximum tokens per user; 0 unlimited"`
	AuditEnabled     bool     `json:"audit_enabled" doc:"write per-token audit events"`
	AuditRetention   Duration `json:"audit_retention" doc:"audit event and usage retention; 0 keeps forever"`
}

// BandwidthConfig configures bandwidth accounting and limits.
type BandwidthConfig struct {
	Enabled       bool     `json:"enabled" doc:"master switch: counting, throttling and caps"`
	GlobalUpBps   Size     `json:"global_upload_bytes_per_sec" doc:"server wide upload rate cap, 0 off"`
	GlobalDownBps Size     `json:"global_download_bytes_per_sec" doc:"server wide download rate cap, 0 off"`
	Retention     Duration `json:"retention" doc:"daily usage retention"`
}

// OIDCConfig configures JWT bearer validation.
type OIDCConfig struct {
	Enabled        bool     `json:"enabled" doc:"accept OIDC JWTs"`
	Issuer         string   `json:"issuer" doc:"expected issuer, used for JWKS discovery"`
	Audience       string   `json:"audience" doc:"expected audience"`
	Algs           []string `json:"algs" doc:"allowed algorithms: RS256, ES256, EdDSA"`
	AutoProvision  bool     `json:"auto_provision" doc:"create a user for an unknown subject"`
	ScopeClaim     string   `json:"scope_claim" doc:"claim carrying scopes"`
	ClockSkew      Duration `json:"clock_skew" doc:"allowed exp and nbf clock skew"`
	JWKSCacheTTL   Duration `json:"jwks_cache_ttl" doc:"JWKS cache lifetime"`
	JWKSMinRefresh Duration `json:"jwks_min_refresh" doc:"minimum interval between JWKS refreshes"`
}

// ProxyConfig trusts identity headers from known proxies.
type ProxyConfig struct {
	Enabled      bool     `json:"enabled" doc:"accept identity headers from trusted proxies"`
	Header       string   `json:"header" doc:"header carrying the user subject"`
	TrustedCIDRs []string `json:"trusted_cidrs" doc:"CIDRs allowed to assert identity"`
}

// AnonymousConfig enables the anonymous method.
type AnonymousConfig struct {
	Enabled bool     `json:"enabled" doc:"accept unauthenticated requests"`
	Scopes  []string `json:"scopes" doc:"scopes granted to anonymous principals"`
}

// RegistrationConfig controls self service registration.
type RegistrationConfig struct {
	Mode            string   `json:"mode" doc:"closed, invite, or open"`
	InviteCodes     []string `json:"invite_codes" doc:"valid invite codes" secret:""`
	InviteCodesFile string   `json:"invite_codes_file" doc:"path to file with one invite code per line"`
	InviteMaxUses   int      `json:"invite_max_uses" doc:"max uses per invite code, 0 is unlimited"`
	PerSec          float64  `json:"per_sec" doc:"registration rate limit per IP for mode open"`
	RequireApproval bool     `json:"require_approval" doc:"new registrations need admin approval"`
	MaxPerIPPerDay  int      `json:"max_per_ip_per_day" doc:"registrations per client IP per day, 0 off"`
}

// QuotaConfig holds tiers and per app policy.
type QuotaConfig struct {
	DefaultTier      string               `json:"default_tier" doc:"tier assigned to new users"`
	AnonymousTier    string               `json:"anonymous_tier" doc:"tier for anonymous principals"`
	AllowUnknownApps string               `json:"allow_unknown_apps" doc:"regex for app ids allowed without a policy entry"`
	Tiers            map[string]Tier      `json:"tiers" doc:"quota tiers by name"`
	Apps             map[string]AppPolicy `json:"apps" doc:"per app policy by app id"`
}

// Tier is a named quota bundle.
type Tier struct {
	QuotaBytes           Size            `json:"quota_bytes" doc:"total byte quota"`
	MaxSlots             int             `json:"max_slots" doc:"max slots per user"`
	MaxSnapshotsPerSlot  int             `json:"max_snapshots_per_slot" doc:"max snapshots kept per slot"`
	MaxFiles             int             `json:"max_files" doc:"max files per snapshot"`
	MaxFileBytes         Size            `json:"max_file_bytes" doc:"max single file size"`
	MaxSnapshotBytes     Size            `json:"max_snapshot_bytes" doc:"max summed file sizes per snapshot"`
	MaxPendingSnapshots  int             `json:"max_pending_snapshots" doc:"max concurrent pending snapshots"`
	Retention            RetentionPolicy `json:"retention" doc:"snapshot retention"`
	Rate                 RateLimit       `json:"rate" doc:"per principal request rate"`
	MaxConcurrentUploads int             `json:"max_concurrent_uploads" doc:"parallel chunk uploads per principal"`
	RequireEncryption    *bool           `json:"require_encryption,omitempty" doc:"require vault encrypted manifests"`
	Bandwidth            BandwidthPolicy `json:"bandwidth" doc:"per-user bandwidth policy, 0 means unlimited"`
}

// BandwidthPolicy throttles and caps transfer for one tier. Zero fields
// are unlimited. Daily and monthly caps count upload plus download.
type BandwidthPolicy struct {
	UpBps   Size `json:"upload_bytes_per_sec" doc:"per-user upload rate cap"`
	DownBps Size `json:"download_bytes_per_sec" doc:"per-user download rate cap"`
	Daily   Size `json:"daily_bytes" doc:"per-user daily transfer cap, UTC day"`
	Monthly Size `json:"monthly_bytes" doc:"per-user monthly transfer cap, UTC month"`
}

// RetentionPolicy controls snapshot pruning.
type RetentionPolicy struct {
	KeepLast int      `json:"keep_last" doc:"snapshots always retained"`
	MaxAge   Duration `json:"max_age" doc:"snapshots older than this are pruned, 0 disables"`
}

// RateLimit is a token bucket.
type RateLimit struct {
	RequestsPerSec float64 `json:"requests_per_sec" doc:"sustained request rate"`
	Burst          int     `json:"burst" doc:"bucket capacity"`
}

// AppPolicy overrides policy for one app id.
type AppPolicy struct {
	Name             string           `json:"name" doc:"display name"`
	AllowForce       bool             `json:"allow_force" doc:"permit force commits that overwrite the head"`
	Retention        *RetentionPolicy `json:"retention" doc:"retention override"`
	Include          []string         `json:"include" doc:"path hints included by clients"`
	Exclude          []string         `json:"exclude" doc:"path hints excluded by clients"`
	MaxFileBytes     Size             `json:"max_file_bytes" doc:"app level max file size, 0 uses tier"`
	MaxSnapshotBytes Size             `json:"max_snapshot_bytes" doc:"app level max snapshot size, 0 uses tier"`
}

// LimitsConfig holds manifest and request limits.
type LimitsConfig struct {
	InlineMaxBytes       Size `json:"inline_max_bytes" doc:"largest file stored inline in a manifest"`
	MinChunkBytes        Size `json:"min_chunk_bytes" doc:"smallest allowed non-final chunk"`
	MaxChunkBytes        Size `json:"max_chunk_bytes" doc:"largest accepted chunk upload"`
	MaxFiles             int  `json:"max_files" doc:"max file entries per snapshot"`
	MaxChunksPerSnapshot int  `json:"max_chunks_per_snapshot" doc:"max total chunk refs per snapshot"`
	MaxFileBytes         Size `json:"max_file_bytes" doc:"global largest single file"`
	MaxSnapshotBytes     Size `json:"max_snapshot_bytes" doc:"global largest summed file sizes"`
	MaxManifestBytes     Size `json:"max_manifest_bytes" doc:"largest accepted manifest body"`
	ManifestCacheBytes   Size `json:"manifest_cache_bytes" doc:"decoded manifest cache size per process, 0 disables"`
	RequireEncryption    bool `json:"require_encryption" doc:"require vault encrypted manifests for all snapshots"`
	MaxPathDepth         int  `json:"max_path_depth" doc:"deepest allowed path component count"`
	MaxConcurrentUploads int  `json:"max_concurrent_uploads" doc:"global parallel chunk upload cap"`
	MaxEventStreams      int  `json:"max_event_streams" doc:"max event streams per user, 0 disables events"`
}

// APILimits projects the configured limits into the wire type.
func (l LimitsConfig) APILimits() api.Limits {
	return api.Limits{
		InlineMaxBytes:       l.InlineMaxBytes.Int64(),
		MinChunkBytes:        l.MinChunkBytes.Int64(),
		MaxChunkBytes:        l.MaxChunkBytes.Int64(),
		MaxFiles:             l.MaxFiles,
		MaxChunksPerSnapshot: l.MaxChunksPerSnapshot,
		MaxFileBytes:         l.MaxFileBytes.Int64(),
		MaxSnapshotBytes:     l.MaxSnapshotBytes.Int64(),
		MaxManifestBytes:     l.MaxManifestBytes.Int64(),
		MaxPathDepth:         l.MaxPathDepth,
	}
}

// GCConfig controls background garbage collection.
type GCConfig struct {
	Interval    Duration `json:"interval" doc:"time between gc cycles"`
	GracePeriod Duration `json:"grace_period" doc:"minimum unreferenced age before deletion"`
	PendingTTL  Duration `json:"pending_ttl" doc:"lifetime of an uncommitted pending snapshot"`
	BatchSize   int      `json:"batch_size" doc:"max rows per gc batch"`
	LeaseHolder string   `json:"lease_holder" doc:"identity used for the gc leader lease"`
}

// SandboxConfig controls the Landlock sandbox.
type SandboxConfig struct {
	Mode                 string   `json:"mode" doc:"off, best-effort, or enforce"`
	AllowRoot            bool     `json:"allow_root" doc:"permit running as uid 0"`
	ExtraROPaths         []string `json:"extra_ro_paths" doc:"additional read only paths"`
	ExtraRWPaths         []string `json:"extra_rw_paths" doc:"additional read write paths"`
	ExtraConnectTCPPorts []uint16 `json:"extra_connect_tcp_ports" doc:"additional outbound TCP ports"`
	ExtraBindTCPPorts    []uint16 `json:"extra_bind_tcp_ports" doc:"additional bound TCP ports"`
}

// LogConfig controls logging.
type LogConfig struct {
	Level  string `json:"level" doc:"debug, info, warn, or error"`
	Format string `json:"format" doc:"json or text"`
	Access bool   `json:"access" doc:"emit an access log line per request"`
}

// CORSConfig controls cross origin resource sharing.
type CORSConfig struct {
	Enabled        bool     `json:"enabled" doc:"emit CORS headers"`
	AllowedOrigins []string `json:"allowed_origins" doc:"allowed origin values"`
	AllowedMethods []string `json:"allowed_methods" doc:"allowed methods"`
	AllowedHeaders []string `json:"allowed_headers" doc:"allowed headers"`
	MaxAge         Duration `json:"max_age" doc:"preflight cache lifetime"`
}

// MetricsConfig controls Prometheus metrics.
type MetricsConfig struct {
	Enabled   bool   `json:"enabled" doc:"expose metrics on the ops listener"`
	Namespace string `json:"namespace" doc:"metric name prefix"`
}

// Defaults returns a configuration with secure defaults.
func Defaults() Config {
	var c Config
	c.Listen = ListenConfig{
		Addr:              "127.0.0.1:8443",
		Protocols:         []string{"h2"},
		ReadHeaderTimeout: Duration(10e9),
		IdleTimeout:       Duration(120e9),
		MaxHeaderBytes:    Size(1 << 20),
		MaxConns:          1024,
		MinThroughput:     Size(32 << 10),
		UDPBufferBytes:    Size(7 << 20),
		TLS: TLSConfig{
			Mode:       "none",
			MinVersion: "1.2",
			HotReload:  true,
		},
		H2: HTTP2Config{MaxConcurrentStreams: 256, MaxReadFrameSize: 1 << 20, IdleTimeout: Duration(60e9)},
	}
	c.Ops = OpsConfig{Enabled: false, Addr: "127.0.0.1:9090"}
	c.Storage = StorageConfig{
		Blob: BlobConfig{Driver: "fs", FS: FSConfig{Root: "/var/lib/saves/blobs", Fsync: "dir"},
			S3: S3Config{Region: "us-east-1", RequestTimeout: Duration(30e9), MaxRetries: 3}},
		Meta: MetaConfig{Driver: "sqlite", SQLite: SQLiteConfig{Path: "/var/lib/saves/meta.db"},
			Postgres: PostgresConfig{MaxConns: 16, MinConns: 2}},
	}
	c.Auth = AuthConfig{
		Order: []string{"token"},
		Token: TokenAuthConfig{Enabled: true, LastUsedInterval: Duration(60e9),
			DefaultTTL: Duration(90 * 24 * 3600e9), MaxPerUser: 50, AuditEnabled: true, AuditRetention: Duration(90 * 24 * 3600e9)},
		OIDC:             OIDCConfig{Algs: []string{"RS256", "ES256", "EdDSA"}, ClockSkew: Duration(60e9), JWKSCacheTTL: Duration(3600e9), JWKSMinRefresh: Duration(60e9)},
		Anonymous:        AnonymousConfig{Scopes: []string{"read"}},
		FailedAuthPerSec: 5,
	}
	c.Registration = RegistrationConfig{Mode: "closed", InviteMaxUses: 1, PerSec: 0.1}
	c.Audit = AuditConfig{Enabled: true, Retention: Duration(365 * 24 * 3600e9)}
	c.Analytics = AnalyticsConfig{Enabled: true}
	c.Quota = QuotaConfig{
		DefaultTier:   "free",
		AnonymousTier: "anon",
		Tiers: map[string]Tier{
			"anon": {QuotaBytes: Size(64 << 20), MaxSlots: 1, MaxSnapshotsPerSlot: 3, MaxFiles: 10000,
				MaxFileBytes: Size(256 << 20), MaxSnapshotBytes: Size(64 << 20), MaxPendingSnapshots: 1,
				Retention: RetentionPolicy{KeepLast: 3, MaxAge: Duration(7 * 24 * 3600e9)},
				Rate:      RateLimit{RequestsPerSec: 2, Burst: 10}, MaxConcurrentUploads: 1},
			"free": {QuotaBytes: Size(10 << 30), MaxSlots: 16, MaxSnapshotsPerSlot: 30, MaxFiles: 1 << 20,
				MaxFileBytes: Size(16 << 30), MaxSnapshotBytes: Size(10 << 30), MaxPendingSnapshots: 4,
				Retention: RetentionPolicy{KeepLast: 30, MaxAge: Duration(90 * 24 * 3600e9)},
				Rate:      RateLimit{RequestsPerSec: 20, Burst: 60}, MaxConcurrentUploads: 4},
		},
	}
	c.Limits = LimitsConfig{
		InlineMaxBytes:       Size(64 << 10),
		MinChunkBytes:        Size(128 << 10),
		MaxChunkBytes:        Size(2 << 20),
		MaxFiles:             1 << 20,
		MaxChunksPerSnapshot: 1 << 22,
		MaxFileBytes:         Size(64 << 30),
		MaxSnapshotBytes:     Size(1 << 40),
		MaxManifestBytes:     Size(4 << 20),
		ManifestCacheBytes:   Size(64 << 20),
		MaxPathDepth:         64,
		MaxConcurrentUploads: 64, MaxEventStreams: 8,
	}
	c.GC = GCConfig{Interval: Duration(600e9), GracePeriod: Duration(24 * 3600e9), PendingTTL: Duration(3600e9), BatchSize: 500, LeaseHolder: "savesd"}
	c.Sandbox = SandboxConfig{Mode: "enforce"}
	c.Log = LogConfig{Level: "info", Format: "json", Access: true}
	c.CORS = CORSConfig{Enabled: false, AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"}, MaxAge: Duration(600e9)}
	c.Metrics = MetricsConfig{Enabled: true, Namespace: "saves"}
	c.Web = WebConfig{
		ClientURL: "https://github.com/Sudo-Ivan/saves/releases", InstanceName: "saves", Homepage: true, PasswordLogin: true, APIDocs: true,
		CookieSecure: "auto",
		Session: WebSessionConfig{
			Idle: Duration(2 * 3600e9), Absolute: Duration(24 * 3600e9),
			PendingTTL: Duration(300e9), Max2FAAttempts: 5,
		},
		HSTS:            HSTSConfig{Enabled: true, MaxAge: Duration(365 * 24 * 3600e9)},
		Require2FAAdmin: true,
		LoginPerMin:     10,
		OIDC:            WebOIDCConfig{Scopes: "openid profile email", Label: "Single sign-on"},
	}
	return c
}

// AuditConfig controls the admin audit log.
type AuditConfig struct {
	Enabled   bool     `json:"enabled" doc:"record admin and auth audit events"`
	Retention Duration `json:"retention" doc:"how long audit rows are kept"`
}

// AnalyticsConfig controls the usage metrics collector.
type AnalyticsConfig struct {
	Enabled bool `json:"enabled" doc:"collect daily usage stats"`
}

// AdminConfig controls admin operations.
type AdminConfig struct {
	BackupDir string `json:"backup_dir" doc:"directory for sqlite metadata backups, empty off"`
}
