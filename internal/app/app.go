package app

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"
	"fmt"
	"strings"
	"slices"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/dnstapir/tapir-analyse-lib/common"
	"github.com/dnstapir/tapir-analyse-lib/libtapir"
)

const c_N_HANDLERS = 3
const c_DEFAULT_API_ADDR = "127.0.0.1:8080"

const (
	tagClassCustom      = "custom"
	tagClassWellDefined = "well-defined"
)

// reservedTags are tag names that collide with static routes under /tags/.
var reservedTags = []string{tagClassCustom, tagClassWellDefined}

type Conf struct {
	Debug      bool 	`toml:"debug"`
	Interval   int  	`toml:"interval"`
	APIAddr    string   `toml:"api_addr"`
	AnalystID  string
	Log        common.Logger
	NatsHandle nats
}

type appHandle struct {
	id          string
	observation string
	log         common.Logger
	natsHandle  nats
	ticker      *time.Ticker
	exitCh      chan<- common.Exit
	apiServer 	*http.Server
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
type TagInput struct {
	Body struct {
		Tag  	string	`json:"tag" maxLength:"30" example:"internal_testing" doc:"Tag name"`
		Domain  string 	`json:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9._-]+$" example:"example.com" doc:"Domain to tag"`
		Message string 	`json:"message,omitempty" maxLength:"100" doc:"Optional message"`
	}
}

type TagValueOutput struct {
	Body struct {
		Domain string `json:"domain" example:"example.com"`
		Tag    string `json:"tag" example:"internal_testing"`
		Value  string `json:"value" example:"unusual behavior" doc:"Message stored with the tag"`
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

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(d, "."))
}

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

	if conf.APIAddr == "" {
		a.apiServer = a.newAPIServer(c_DEFAULT_API_ADDR)
	} else {
		a.apiServer = a.newAPIServer(conf.APIAddr)
	}

	a.log.Debug("Main app debug logging enabled")
	return a, nil
}

func (a *appHandle) Run(ctx context.Context, exitCh chan<- common.Exit) {
	defer a.ticker.Stop()

	var err error
	a.exitCh = exitCh
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

	if a.apiServer != nil {
		a.startAPI()
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

	panic("not impl")
}

func (a *appHandle) newAPIServer(addr string) *http.Server {
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
	api := humago.New(router, config)

	huma.Register(api, huma.Operation{
		OperationID:   "post-tag",
		Method:        http.MethodPost,
		Path:          "/tags",
		Summary:       "Post a tag",
		DefaultStatus: http.StatusCreated,
	}, func(ctx context.Context, i *TagInput) (*struct{}, error) {
		a.log.Debug("POST Tag: %+v", i.Body)
		domain := normalizeDomain(i.Body.Domain)
		if slices.Contains(reservedTags, i.Body.Tag) {
			return nil, huma.Error422UnprocessableEntity(
				fmt.Sprintf("tag name '%s' is reserved", i.Body.Tag))
		}
		err := a.natsHandle.SetTagStr(ctx, domain, i.Body.Tag, i.Body.Message)
		if err != nil {
			a.log.Error("Failed to set tag in nats: '%s'", err)
			return nil, huma.Error502BadGateway("failed to store tag")
		}
		return nil, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-well-defined",
		Method:      http.MethodGet,
		Path:        "/tags/well-defined",
		Summary:     "Get well-defined tags",
		Description: "Returns a list of tags which are defined.",
	}, func(ctx context.Context, _ *struct{}) (*WellDefinedOutput, error) {
		out := &WellDefinedOutput{}
		out.Body.WellDefined = common.TagNames()
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-custom",
		Method:      http.MethodGet,
		Path:        "/tags/custom",
		Summary:     "Get custom tags",
		Description: "Returns a list of custom tags in use.",
	}, func(ctx context.Context, _ *struct{}) (*CustomOutput, error) {
		out := &CustomOutput{}
		filter := common.NormalizeNatsSubject(tagClassCustom + common.NATS_DELIM + ">")
		keys, err := a.natsHandle.ListTagKeys(ctx, filter)
		if err != nil {
			a.log.Error("Failed to list custom tags: '%s'", err)
			return nil, huma.Error502BadGateway("failed to list custom tags")
		}
		out.Body.Custom = customTagNames(keys)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-tagged-domains",
		Method:      http.MethodGet,
		Path:        "/tags/{tag}",
		Summary:     "Get tagged domains",
		Description: "Get a list of domains tagged with the tag.",
	}, func(ctx context.Context, input *struct{
		Tag string `path:"tag" maxLength:"30" pattern:"^[a-z0-9_]+$" example:"internal_testing" doc:"Tag to filter domains"`
	}) (*DomainsOutput, error) {
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
		Summary:     "Get domain tags",
		Description: "Get a list of tags for a domain.",
	}, func(ctx context.Context, input *struct{
		Domain string `path:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9._-]+$" example:"example.com" doc:"Domain to filter tags"`
	}) (*TagsOutput, error) {
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
		Summary:     "Get tag value",
		Description: "Get the value stored for a tag on a domain.",
		Errors:      []int{http.StatusNotFound},
	}, func(ctx context.Context, input *struct {
		Domain string `path:"domain" maxLength:"100" pattern:"^[a-zA-Z0-9_-]+([.][a-zA-Z0-9_-]+)*[.]?$" example:"example.com" doc:"Domain the tag is set on"`
		Tag    string `path:"tag" maxLength:"30" pattern:"^[a-z0-9_]+$" example:"internal_testing" doc:"Tag name"`
	}) (*TagValueOutput, error) {
		domain := normalizeDomain(input.Domain)
		value, err := a.natsHandle.GetTagStr(ctx, domain, input.Tag)
		if err != nil {
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

func (a *appHandle) startAPI() {
	go func() {
		a.log.Info("Starting Huma API on %s", a.apiServer.Addr)
		err := a.apiServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("API server failed: '%s'", err)
		}
	}()
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
