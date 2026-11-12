package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/dnstapir/tapir-analyse-lib/common"
	"github.com/dnstapir/tapir-analyse-lib/libtapir"
	"github.com/nats-io/nats.go/jetstream"
)

const c_N_HANDLERS = 3
const c_DEFAULT_API_ADDR = "127.0.0.1:8080"

const (
	tagClassCustom      = "custom"
	tagClassWellDefined = "well-defined"
)

// reservedTags are tag names that collide with static routes under /tags/.
var reservedTags = []string{tagClassCustom, tagClassWellDefined}

var errNoAPIKeys = errors.New("no API keys configured: set api_users, TAG_MANAGER_API_KEY or api_test_key")

type Conf struct {
	Debug           bool      `toml:"debug"`
	Interval        int       `toml:"interval"`
	APIAddr         string    `toml:"api_addr"`
	APITestKey      string    `toml:"api_test_key"`
	APIUsers        []APIUser `toml:"api_users"`
	APIAuthDisabled bool      `toml:"api_auth_disabled"`
	AnalystID       string
	Log             common.Logger
	NatsHandle      nats
}

type appHandle struct {
	id          string
	observation string
	log         common.Logger
	natsHandle  nats
	ticker      *time.Ticker
	exitCh      chan<- common.Exit
	apiServer   *http.Server
	customTags  *customTagSet
	refreshMu   sync.Mutex
}

type job struct {
	isTick   bool
	tickData int64
	msg      common.NatsMsg
}

type nats interface {
	Shutdown() error
	SetTagStr(context.Context, string, string, string) error
	ListTagKeys(context.Context, string) ([]string, error)
	GetTagStr(context.Context, string, string) (string, error)
}

// API types
type DomainTagBody struct {
	Value string `json:"value,omitempty" maxLength:"100" doc:"Optional value stored with the tag"`
}

type TagValueOutput struct {
	Body struct {
		Domain string `json:"domain" example:"example.com"`
		Tag    string `json:"tag" example:"internal_testing"`
		Value  string `json:"value" example:"unusual behavior" doc:"Value stored with the tag"`
	}
}

type WellDefinedOutput struct {
	Body struct {
		WellDefined []string `json:"well-defined" example:"[\"anomalous_qtype_distribution\", \"internal_testing\"]" doc:"List of well-defined tags"`
	}
}

type CustomOutput struct {
	Body struct {
		Custom []string `json:"custom" example:"[\"my_tag1\", \"my_tag2\"]" doc:"List of current custom tags"`
	}
}

type DomainsOutput struct {
	Body struct {
		Domains []string `json:"domains" example:"[\"foo.boo\", \"bar.baz\"]" doc:"List of tagged domains"`
	}
}

type TagsOutput struct {
	Body struct {
		Tags []string `json:"tags" example:"[\"internal_testing\", \"my_tag1\"]" doc:"List of domain tags"`
	}
}

// customTagSet is a concurrency-safe set of custom tag names that have been
// set through this service.
//
// NOTE: This relies on tags having an infinite TTL in NATS, so once a custom
// tag has been seen it is assumed to never disappear. If we ever introduce
// TTLs or tag deletion, this needs to be revisited (e.g. by re-deriving the
// set from NATS or by tracking per-tag reference counts).
type customTagSet struct {
	mu   sync.RWMutex
	tags map[string]struct{}
}

func newCustomTagSet() *customTagSet {
	return &customTagSet{tags: make(map[string]struct{})}
}

func (s *customTagSet) add(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range names {
		s.tags[n] = struct{}{}
	}
}

// list returns the tags sorted. It never returns nil, so it serializes as [].
func (s *customTagSet) list() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tags))
	for n := range s.tags {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// replace swaps in a new set of names, dropping any that are not in it.
func (s *customTagSet) replace(names []string) {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	s.mu.Lock()
	s.tags = m
	s.mu.Unlock()
}

func isWellDefinedTag(tag string) bool {
	return slices.Contains(common.TagNames(), tag)
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

// API keys
type APIUser struct {
	Name      string `toml:"name"`
	KeySHA256 string `toml:"key_sha256"`
}

type apiCredential struct {
	name string
	hash [sha256.Size]byte
}

func hashKey(k string) [sha256.Size]byte {
	return sha256.Sum256([]byte(k))
}

func parseAPIUsers(users []APIUser) ([]apiCredential, error) {
	creds := make([]apiCredential, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, u := range users {
		if u.Name == "" {
			return nil, errors.New("api_users: entry with empty name")
		}
		if _, dup := seen[u.Name]; dup {
			return nil, fmt.Errorf("api_users: duplicate name %q", u.Name)
		}
		seen[u.Name] = struct{}{}

		raw, err := hex.DecodeString(strings.TrimSpace(u.KeySHA256))
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("api_users: %q has an invalid key_sha256 (want %d hex chars)",
				u.Name, sha256.Size*2)
		}
		var c apiCredential
		c.name = u.Name
		copy(c.hash[:], raw)
		creds = append(creds, c)
	}
	return creds, nil
}

func buildCredentials(envVal string, users []APIUser, testKey string) ([]apiCredential, error) {
	creds, err := parseAPIUsers(users)
	if err != nil {
		return nil, err
	}
	for i, k := range parseAPIKeys(envVal) {
		creds = append(creds, apiCredential{name: fmt.Sprintf("env-%d", i+1), hash: hashKey(k)})
	}
	if len(creds) == 0 {
		for i, k := range parseAPIKeys(testKey) {
			creds = append(creds, apiCredential{name: fmt.Sprintf("test-%d", i+1), hash: hashKey(k)})
		}
	}
	return creds, nil
}

// resolveAPIKeys returns the keys from the first source that yields any:
// the environment variable first, then the config entry. Both are treated as
// comma-separated lists. The second return value names the source used.
func resolveAPIKeys(envVal, confVal string) ([]string, string) {
	if keys := parseAPIKeys(envVal); len(keys) > 0 {
		return keys, "environment"
	}
	if keys := parseAPIKeys(confVal); len(keys) > 0 {
		return keys, "config"
	}
	return nil, ""
}

// parseAPIKeys splits a comma-separated list of API keys, trimming whitespace
// and dropping empty entries.
func parseAPIKeys(raw string) []string {
	var keys []string
	for _, k := range strings.Split(raw, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

func apiKeyAuth(api huma.API, creds []apiCredential) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		// Only enforce on operations that declare the scheme
		required := false
		for _, req := range ctx.Operation().Security {
			if _, ok := req["apiKey"]; ok {
				required = true
				break
			}
		}
		if !required {
			next(ctx)
			return
		}

		header := ctx.Header("X-API-Key")
		sum := hashKey(header)

		// Compare against every credential, no early exit.
		matched := -1
		for i, c := range creds {
			if subtle.ConstantTimeCompare(sum[:], c.hash[:]) == 1 {
				matched = i
			}
		}
		if header == "" || matched < 0 {
			huma.WriteErr(api, ctx, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		next(huma.WithValue(ctx, userCtxKey{}, creds[matched].name))
	}
}

type userCtxKey struct{}

// <prefix>.tags.custom.<tag-name>.<domain>
func customTagNames(keys []string) []string {
	seen := make(map[string]struct{})

	for _, key := range keys {
		parts := strings.Split(key, common.NATS_DELIM)
		for i := 0; i+2 < len(parts); i++ {
			if parts[i] == "tags" && parts[i+1] == tagClassCustom {
				seen[parts[i+2]] = struct{}{}
				break
			}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// <prefix>.tags.<class>.<tag>.bar.foo -> foo.bar
func taggedDomains(keys []string, tagClass string, tag string) []string {
	seen := make(map[string]struct{})

	for _, key := range keys {
		parts := strings.Split(key, common.NATS_DELIM)
		for i := 0; i+3 < len(parts); i++ {
			if parts[i] == "tags" && parts[i+1] == tagClass && parts[i+2] == tag {
				labels := slices.Clone(parts[i+3:])
				slices.Reverse(labels)
				seen[strings.Join(labels, ".")] = struct{}{}
				break
			}
		}
	}

	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	slices.Sort(domains)
	return domains
}

func domainTags(keys []string, domain string) []string {
	domain = strings.TrimSuffix(domain, ".")
	nLabels := strings.Count(domain, ".") + 1

	seen := make(map[string]struct{})

	for _, key := range keys {
		parts := strings.Split(key, common.NATS_DELIM)

		tagIdx := len(parts) - nLabels - 1
		if tagIdx < 1 {
			continue // malformed key
		}
		seen[parts[tagIdx]] = struct{}{}
	}

	tags := make([]string, 0, len(seen))
	for t := range seen {
		tags = append(tags, t)
	}
	slices.Sort(tags)
	return tags
}

func Create(conf Conf) (*appHandle, error) {
	a := new(appHandle)

	if conf.Log == nil {
		return nil, common.ErrBadHandle
	}
	a.log = conf.Log

	if conf.NatsHandle == nil {
		return nil, common.ErrBadHandle
	}
	a.natsHandle = conf.NatsHandle

	if conf.AnalystID == "" {
		a.log.Error("Bad analyst ID during creation")
		return nil, common.ErrBadParam
	}
	a.id = conf.AnalystID

	if conf.Interval > 0 {
		a.ticker = time.NewTicker(time.Duration(conf.Interval) * time.Second)
	} else {
		a.ticker = time.NewTicker(time.Duration(math.MaxInt32) * time.Second)
		a.ticker.Stop()
		a.log.Warning("No interval set. Won't refresh list.")
	}

	creds, err := buildCredentials(os.Getenv("TAG_MANAGER_API_KEY"), conf.APIUsers, conf.APITestKey)
	if conf.APIAuthDisabled {
		if err != nil || len(creds) > 0 {
			a.log.Warning("api_auth_disabled is set, ignoring configured API keys")
		}
		a.log.Warning("API authentication is DISABLED (api_auth_disabled = true)")
		creds = nil
	} else {
		if err != nil {
			a.log.Error("API credentials: '%s'", err)
			return nil, err
		}
		if len(creds) == 0 {
			a.log.Error("%s", errNoAPIKeys)
			return nil, errNoAPIKeys
		}
	}

	addr := conf.APIAddr
	if addr == "" {
		addr = c_DEFAULT_API_ADDR
	}
	a.apiServer = a.newAPIServer(addr, creds)
	a.customTags = newCustomTagSet()

	a.log.Debug("Main app debug logging enabled")
	return a, nil

}

func (a *appHandle) Run(ctx context.Context, exitCh chan<- common.Exit) {
	defer a.ticker.Stop()

	var err error
	a.exitCh = exitCh

	if a.apiServer != nil {
		a.seedCustomTags(ctx)
		if err := a.startAPI(); err != nil {
			a.log.Error("Failed to start API: '%s'", err)
			if serr := a.natsHandle.Shutdown(); serr != nil {
				a.log.Error("Encountered '%s' during NATS shutdown", serr)
			}
			a.exitCh <- common.Exit{ID: a.id, Err: err}
			return
		}
	}

	jobChan := make(chan job, 10)

	var wg sync.WaitGroup
	for range c_N_HANDLERS {
		wg.Go(func() {
			for j := range jobChan {
				a.handleJob(ctx, j)
			}
			a.log.Info("Worker done!")
		})
	}

MAIN_APP_LOOP:
	for {
		select {
		case t := <-a.ticker.C:
			a.log.Debug("Tick")
			j := job{
				isTick:   true,
				tickData: t.Unix(),
			}
			select {
			case jobChan <- j:
			case <-ctx.Done():
				break MAIN_APP_LOOP
			}
		case <-ctx.Done():
			a.log.Info("Stopping main worker thread")
			break MAIN_APP_LOOP
		}
	}

	if a.apiServer != nil {
		a.stopAPI()
	}

	close(jobChan)

	wg.Wait()

	err = a.natsHandle.Shutdown()
	if err != nil {
		a.log.Error("Encountered '%s' during NATS shutdown", err)
	}

	a.exitCh <- common.Exit{ID: a.id, Err: err}
	a.log.Info("Main app shutdown done")
	return
}

func (a *appHandle) handleJob(ctx context.Context, j job) {
	if j.isTick {
		a.handleTick(ctx, j.tickData)
	}
}

func (a *appHandle) handleTick(ctx context.Context, epoch int64) {
	a.log.Debug("Received tick '%d'", epoch)
	if epoch == 0 {
		a.log.Debug("Tick had zero value, probably garbage. Won't handle...")
		return
	}

	if !a.refreshMu.TryLock() {
		a.log.Debug("Previous refresh still running, skipping")
		return
	}
	defer a.refreshMu.Unlock()

	a.refreshCustomTags(ctx)
}

func (a *appHandle) fetchCustomTags(ctx context.Context) ([]string, error) {
	filter := common.NormalizeNatsSubject(tagClassCustom + common.NATS_DELIM + ">")
	keys, err := a.natsHandle.ListTagKeys(ctx, filter)
	if err != nil {
		return nil, err
	}
	return customTagNames(keys), nil
}

func (a *appHandle) seedCustomTags(ctx context.Context) {
	names, err := a.fetchCustomTags(ctx)
	if err != nil {
		a.log.Error("Failed to seed custom tags from NATS: '%s'", err)
		return
	}
	a.customTags.add(names...)
	a.log.Debug("Seeded custom tag cache, %d tags", len(names))
}

func (a *appHandle) refreshCustomTags(ctx context.Context) {
	names, err := a.fetchCustomTags(ctx)
	if err != nil {
		// Keep the old set on failure rather than wiping the cache.
		a.log.Error("Failed to refresh custom tags from NATS: '%s'", err)
		return
	}
	a.customTags.replace(names)
	a.log.Debug("Refreshed custom tag cache, %d tags", len(names))
}

func (a *appHandle) newAPIServer(addr string, creds []apiCredential) *http.Server {
	router := http.NewServeMux()
	config := huma.DefaultConfig("DNS TAPIR Tag Manager API", "0.0.1")

	config.Info.Description = `
	# Tag Manager API

	Manage tags in DNS TAPIR

	## Getting started
	todo

	## Authentication
	todo
	`

	config.Info.Contact = &huma.Contact{
		Name:  "Jonathan Magnusson",
		Email: "jonathan.magnusson@internetstiftelsen.se",
	}

	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"apiKey": {
			Type: "apiKey",
			In:   "header",
			Name: "X-API-Key",
		},
	}

	api := humago.New(router, config)
	if len(creds) > 0 {
		api.UseMiddleware(apiKeyAuth(api, creds))
	}

	huma.Register(api, huma.Operation{
		OperationID:   "post-domain-tag",
		Method:        http.MethodPost,
		Path:          "/domains/{domain}/tags/{tag}",
		Summary:       "Post a tag for a domain with optional value",
		Security:      []map[string][]string{{"apiKey": {}}},
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, input *struct {
		Domain string         `path:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9_-]+([.][a-zA-Z0-9_-]+)*[.]?$" example:"example.com" doc:"Domain to tag"`
		Tag    string         `path:"tag" maxLength:"60" pattern:"^[a-z0-9_-]+$" example:"internal_testing" doc:"Tag to set"`
		Body   *DomainTagBody `required:"false"`
	}) (*struct{}, error) {
		user, _ := ctx.Value(userCtxKey{}).(string)
		if user == "" {
			user = "anonymous"
		}
		a.log.Debug("Huma API post-domain-tag (%s)", user)
		domain := normalizeDomain(input.Domain)
		if slices.Contains(reservedTags, input.Tag) {
			return nil, huma.Error422UnprocessableEntity(
				fmt.Sprintf("tag name '%s' is reserved", input.Tag))
		}

		value := ""
		if input.Body != nil {
			value = input.Body.Value
		}

		err := a.natsHandle.SetTagStr(ctx, domain, input.Tag, value)
		if err != nil {
			a.log.Error("Failed to set tag in nats: '%s'", err)
			return nil, huma.Error502BadGateway("failed to store tag")
		}

		if !isWellDefinedTag(input.Tag) {
			a.customTags.add(input.Tag)
		}

		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-well-defined",
		Method:      http.MethodGet,
		Path:        "/well-defined/tags",
		Summary:     "Get a list of well-defined tags",
		Description: "Returns a list of tags which are defined.",
		Security:    []map[string][]string{{"apiKey": {}}},
	}, func(ctx context.Context, _ *struct{}) (*WellDefinedOutput, error) {
		a.log.Debug("Huma API get-well-defined")
		out := &WellDefinedOutput{}
		out.Body.WellDefined = common.TagNames()

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-custom",
		Method:      http.MethodGet,
		Path:        "/custom/tags",
		Summary:     "Get a list of in-use custom tags",
		Description: "Returns a list of custom tags in use.",
		Security:    []map[string][]string{{"apiKey": {}}},
	}, func(ctx context.Context, _ *struct{}) (*CustomOutput, error) {
		a.log.Debug("Huma API get-custom")
		out := &CustomOutput{}
		out.Body.Custom = a.customTags.list()

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-tagged-domains",
		Method:      http.MethodGet,
		Path:        "/tags/{tag}/domains",
		Summary:     "Get a list of domains with tag",
		Description: "Returns a list of domains tagged with supplied tag.",
		Security:    []map[string][]string{{"apiKey": {}}},
	}, func(ctx context.Context, input *struct {
		Tag string `path:"tag" maxLength:"60" pattern:"^[a-z0-9_-]+$" example:"internal_testing" doc:"Tag to filter domains"`
	}) (*DomainsOutput, error) {
		a.log.Debug("Huma API get-tagged-domains")
		out := &DomainsOutput{}
		tag := common.StringToTag(input.Tag)
		tagClass := tagClassCustom
		if tag != common.TagUndefined {
			tagClass = tagClassWellDefined
		}
		parts := []string{tagClass, input.Tag, ">"}
		filter := common.NormalizeNatsSubject(strings.Join(parts, common.NATS_DELIM))
		keys, err := a.natsHandle.ListTagKeys(ctx, filter)
		if err != nil {
			a.log.Error("Failed to list domains for tag '%s': '%s'", input.Tag, err)
			return nil, huma.Error502BadGateway("failed to list tagged domains")
		}
		out.Body.Domains = taggedDomains(keys, tagClass, input.Tag)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-domain-tags",
		Method:      http.MethodGet,
		Path:        "/domains/{domain}/tags",
		Summary:     "Get a list of tags on domain",
		Description: "Returns a list of tags for a supplied domain.",
		Security:    []map[string][]string{{"apiKey": {}}},
	}, func(ctx context.Context, input *struct {
		Domain string `path:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9_-]+([.][a-zA-Z0-9_-]+)*[.]?$" example:"example.com" doc:"Domain to filter tags"`
	}) (*TagsOutput, error) {
		a.log.Debug("Huma API get-domain-tags")
		domain := normalizeDomain(input.Domain)
		out := &TagsOutput{}
		parts := []string{"*", "*", libtapir.FlipDomainName(domain)} // any class any tag
		filter := common.NormalizeNatsSubject(strings.Join(parts, common.NATS_DELIM))
		keys, err := a.natsHandle.ListTagKeys(ctx, filter)
		if err != nil {
			a.log.Error("Failed to list tags for domain '%s': '%s'", domain, err)
			return nil, huma.Error502BadGateway("failed to list domain tags")
		}
		out.Body.Tags = domainTags(keys, domain)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-domain-tag-value",
		Method:      http.MethodGet,
		Path:        "/domains/{domain}/tags/{tag}",
		Summary:     "Get value of tag on domain",
		Description: "Get the value of a tag on a domain.",
		Security:    []map[string][]string{{"apiKey": {}}},
		Errors:      []int{http.StatusNotFound},
	}, func(ctx context.Context, input *struct {
		Domain string `path:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9_-]+([.][a-zA-Z0-9_-]+)*[.]?$" example:"example.com" doc:"Domain the tag is set on"`
		Tag    string `path:"tag" maxLength:"60" pattern:"^[a-z0-9_-]+$" example:"internal_testing" doc:"Tag name"`
	}) (*TagValueOutput, error) {
		a.log.Debug("Huma API get-domain-tag-value")
		domain := normalizeDomain(input.Domain)
		value, err := a.natsHandle.GetTagStr(ctx, domain, input.Tag)
		if err != nil {
			if errors.Is(err, jetstream.ErrKeyNotFound) {
				return nil, huma.Error404NotFound(
					fmt.Sprintf("tag '%s' not set on '%s'", input.Tag, domain))
			}
			a.log.Error("Failed to get tag '%s' for domain '%s': '%s'", input.Tag, domain, err)
			return nil, huma.Error502BadGateway("failed to look up tag value")
		}

		out := &TagValueOutput{}
		out.Body.Domain = domain
		out.Body.Tag = input.Tag
		out.Body.Value = value

		return out, nil
	})

	return &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (a *appHandle) startAPI() error {
	ln, err := net.Listen("tcp", a.apiServer.Addr)
	if err != nil {
		return fmt.Errorf("API listen on %s: %w", a.apiServer.Addr, err)
	}
	a.log.Info("Starting Huma API on %s", ln.Addr())
	go func() {
		err := a.apiServer.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("API server failed: '%s'", err)
		}
	}()
	return nil
}

func (a *appHandle) stopAPI() {
	// ctx in Run is already cancelled at this point, so use a fresh one
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := a.apiServer.Shutdown(shutdownCtx)
	if err != nil {
		a.log.Error("Encountered '%s' during API shutdown", err)
	}
}
