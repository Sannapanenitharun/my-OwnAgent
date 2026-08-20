// Package imds reads EC2 instance identity from the Instance Metadata Service.
//
// It never invents an identifier. If IMDS is unreachable, disabled, or returns
// an empty body, the caller gets ErrUnresolved and must leave instance_id unset.
package imds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/obsagent/observability-agent/internal/platform"
)

const (
	defaultBase    = "http://169.254.169.254"
	tokenPath      = "/latest/api/token"
	instancePath   = "/latest/meta-data/instance-id"
	azPath         = "/latest/meta-data/placement/availability-zone"
	regionPath     = "/latest/meta-data/placement/region"
	typePath       = "/latest/meta-data/instance-type"
	amiPath        = "/latest/meta-data/ami-id"
	identityPath   = "/latest/dynamic/instance-identity/document"
	nameTagPath    = "/latest/meta-data/tags/instance/Name"
	localHostPath  = "/latest/meta-data/local-hostname"
	publicHostPath = "/latest/meta-data/public-hostname"
	localIPv4Path  = "/latest/meta-data/local-ipv4"
	publicIPv4Path = "/latest/meta-data/public-ipv4"
	tokenTTL       = "60"
)

// Identity is what IMDS can assert about this machine. Every field may be
// empty; empty means unresolved, not "unknown".
type Identity struct {
	InstanceID     string
	InstanceName   string // EC2 Name tag when instance metadata tags are enabled
	AZ             string
	Region         string
	InstanceType   string
	AMIID          string
	AccountID      string
	LocalHostname  string
	PublicHostname string
	LocalIPv4      string
	PublicIPv4     string
}

// ResourceAttributes returns OpenTelemetry resource attributes for this
// identity. Unresolved fields are omitted; nothing is synthesised from
// hostname, IP or MAC.
func (id Identity) ResourceAttributes() []platform.Attr {
	var out []platform.Attr
	if id.InstanceID != "" {
		out = append(out, platform.A("host.id", id.InstanceID))
		out = append(out, platform.A("cloud.provider", "aws"))
	}
	if id.Region != "" {
		out = append(out, platform.A("cloud.region", id.Region))
	}
	if id.AZ != "" {
		out = append(out, platform.A("cloud.availability_zone", id.AZ))
	}
	if id.InstanceType != "" {
		out = append(out, platform.A("host.type", id.InstanceType))
	}
	if id.AccountID != "" {
		out = append(out, platform.A("cloud.account.id", id.AccountID))
	}
	if id.AMIID != "" {
		out = append(out, platform.A("host.image.id", id.AMIID))
	}
	if id.InstanceName != "" {
		out = append(out, platform.A("host.name", id.InstanceName))
	}
	return out
}

// Client talks to IMDS. Tests inject BaseURL and Transport.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return defaultBase
}

func (c *Client) httpc() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 2 * time.Second}
}

// LookupInstanceID returns the EC2 instance id, or platform.ErrUnresolved.
func (c *Client) LookupInstanceID(ctx context.Context) (string, error) {
	id, err := c.Lookup(ctx)
	if err != nil {
		return "", err
	}
	if id.InstanceID == "" {
		return "", fmt.Errorf("%w: instance-id", platform.ErrUnresolved)
	}
	return id.InstanceID, nil
}

// Lookup reads instance identity. A partial result is allowed: extra fields
// may be empty when instance-id is present.
func (c *Client) Lookup(ctx context.Context) (Identity, error) {
	token, err := c.putToken(ctx)
	if err != nil {
		id, errv1 := c.get(ctx, instancePath, "")
		if errv1 != nil {
			return Identity{}, fmt.Errorf("%w: imds: %v", platform.ErrUnresolved, err)
		}
		return c.fill(ctx, Identity{InstanceID: id}, ""), nil
	}
	id, err := c.get(ctx, instancePath, token)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: imds instance-id: %v", platform.ErrUnresolved, err)
	}
	return c.fill(ctx, Identity{InstanceID: id}, token), nil
}

func (c *Client) fill(ctx context.Context, id Identity, token string) Identity {
	if az, err := c.get(ctx, azPath, token); err == nil {
		id.AZ = az
	}
	if region, err := c.get(ctx, regionPath, token); err == nil {
		id.Region = region
	} else if id.AZ != "" {
		id.Region = regionFromAZ(id.AZ)
	}
	if typ, err := c.get(ctx, typePath, token); err == nil {
		id.InstanceType = typ
	}
	if ami, err := c.get(ctx, amiPath, token); err == nil {
		id.AMIID = ami
	}
	if name, err := c.get(ctx, nameTagPath, token); err == nil {
		id.InstanceName = name
	}
	if h, err := c.get(ctx, localHostPath, token); err == nil {
		id.LocalHostname = h
	}
	if h, err := c.get(ctx, publicHostPath, token); err == nil {
		id.PublicHostname = h
	}
	if ip, err := c.get(ctx, localIPv4Path, token); err == nil {
		id.LocalIPv4 = ip
	}
	if ip, err := c.get(ctx, publicIPv4Path, token); err == nil {
		id.PublicIPv4 = ip
	}
	if acct, region, ami, typ := c.identityDocument(ctx, token); acct != "" {
		id.AccountID = acct
		if id.Region == "" {
			id.Region = region
		}
		if id.AMIID == "" {
			id.AMIID = ami
		}
		if id.InstanceType == "" {
			id.InstanceType = typ
		}
	}
	return id
}

func (c *Client) identityDocument(ctx context.Context, token string) (account, region, ami, instanceType string) {
	raw, err := c.getRaw(ctx, identityPath, token, 4096)
	if err != nil {
		return "", "", "", ""
	}
	var doc struct {
		AccountID    string `json:"accountId"`
		Region       string `json:"region"`
		ImageID      string `json:"imageId"`
		InstanceType string `json:"instanceType"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return "", "", "", ""
	}
	if !validAccountID(doc.AccountID) {
		doc.AccountID = ""
	}
	if !validIMDSValue(regionPath, doc.Region) {
		doc.Region = ""
	}
	if !validIMDSValue(amiPath, doc.ImageID) {
		doc.ImageID = ""
	}
	if !validIMDSValue(typePath, doc.InstanceType) {
		doc.InstanceType = ""
	}
	return doc.AccountID, doc.Region, doc.ImageID, doc.InstanceType
}

func (c *Client) putToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base()+tokenPath, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", tokenTTL)
	resp, err := c.httpc().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token status %d", resp.StatusCode)
	}
	token := strings.TrimSpace(string(body))
	if token == "" {
		return "", fmt.Errorf("empty token")
	}
	return token, nil
}

func (c *Client) get(ctx context.Context, path, token string) (string, error) {
	body, err := c.getRaw(ctx, path, token, 256)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(body))
	if v == "" {
		return "", fmt.Errorf("empty body")
	}
	if !validIMDSValue(path, v) {
		return "", fmt.Errorf("rejected non-identity value")
	}
	return v, nil
}

func (c *Client) getRaw(ctx context.Context, path, token string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base()+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := c.httpc().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return body, nil
}

func validIMDSValue(path, v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 255 {
		return false
	}
	switch path {
	case instancePath:
		return strings.HasPrefix(v, "i-") && len(v) >= 10 && len(v) <= 32 && isAlnumHyphen(v)
	case azPath:
		return len(v) <= 32 && isAlnumHyphen(v)
	case regionPath:
		return len(v) >= 2 && len(v) <= 32 && isAlnumHyphen(v)
	case typePath:
		return len(v) >= 2 && len(v) <= 32 && isAlnumHyphenDot(v)
	case amiPath:
		return strings.HasPrefix(v, "ami-") && len(v) >= 12 && len(v) <= 32 && isAlnumHyphen(v)
	case nameTagPath:
		// EC2 Name tag: printable, no control chars.
		for _, r := range v {
			if r < 32 || r == 127 {
				return false
			}
		}
		return true
	case localHostPath, publicHostPath:
		return isHostnameLike(v)
	case localIPv4Path, publicIPv4Path:
		return isIPv4(v)
	default:
		return false
	}
}

func isHostnameLike(v string) bool {
	if len(v) < 1 || len(v) > 253 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func isIPv4(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func validAccountID(v string) bool {
	if len(v) != 12 {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAlnumHyphen(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func isAlnumHyphenDot(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// regionFromAZ strips the trailing availability-zone letter when the result
// still looks like a region. It is a last-resort fill when the region path is
// missing; a malformed AZ yields empty rather than a guessed region.
func regionFromAZ(az string) string {
	if len(az) < 3 {
		return ""
	}
	last := rune(az[len(az)-1])
	if last < 'a' || last > 'z' {
		return ""
	}
	region := az[:len(az)-1]
	if !validIMDSValue(regionPath, region) {
		return ""
	}
	return region
}

// ResolveHostID picks the host entity id for this agent process.
//
// An explicit operator value (OBSAGENT_HOST_ID) always wins. Otherwise IMDS is
// queried. Failure returns "" — callers must not invent a hostname, IP, or
// MAC-derived stand-in.
func ResolveHostID(ctx context.Context, explicit string, c *Client) string {
	id := Resolve(ctx, explicit, c)
	return id.InstanceID
}

// Resolve returns the full IMDS identity. explicit, when set, is used as
// InstanceID; extra metadata is still fetched from IMDS when reachable so the
// UI and resource attributes can show region/type/name on EC2.
func Resolve(ctx context.Context, explicit string, c *Client) Identity {
	if c == nil {
		c = &Client{}
	}
	if v := strings.TrimSpace(explicit); v != "" {
		token, _ := c.putToken(ctx)
		return c.fill(ctx, Identity{InstanceID: v}, token)
	}
	id, err := c.Lookup(ctx)
	if err != nil {
		return Identity{}
	}
	return id
}
