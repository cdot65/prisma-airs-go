package redteam

import (
	"context"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"net/http"
	"net/url"
	"strconv"
)

// AdaptersClient manages target adapter scripts and redacted variables.
type AdaptersClient struct{ mgmtCfg *internal.OAuthServiceConfig }

// NetworkBrokerClient manages channels on the Network Broker service. The
// upstream contract has no delete operation; the SDK does not simulate one.
type NetworkBrokerClient struct{ brokerCfg *internal.OAuthServiceConfig }

// AdapterWriteOpts selects validation. Nil lets the server use its default
// (true); explicit false saves a DRAFT without executing the adapter.
type AdapterWriteOpts struct{ Validate *bool }

// AdapterListOpts controls pagination and optional target-reference counts.
type AdapterListOpts struct {
	ListOpts
	Search             string
	Status             schema.CustomTargetAdapterStatus
	IncludeTargetCount *bool
}

// ChannelListOpts supports repeated status filters and explicit empty fallback.
type ChannelListOpts struct {
	ListOpts
	Status            []schema.ChannelStatus
	Search            string
	IncludeAllIfEmpty *bool
}

// Create calls the pinned Adapters contract.
func (c *AdaptersClient) Create(ctx context.Context, req schema.CustomTargetAdapterCreateRequest, opts AdapterWriteOpts) (*schema.CustomTargetAdapter, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapter](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamAdaptersPath, Body: req, Query: adapterWriteQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List calls the pinned Adapters contract.
func (c *AdaptersClient) List(ctx context.Context, opts AdapterListOpts) (*schema.CustomTargetAdapterList, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapterList](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamAdaptersPath, Query: adapterListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get calls the pinned Adapters contract.
func (c *AdaptersClient) Get(ctx context.Context, uuid string) (*schema.CustomTargetAdapter, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapter](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamAdaptersPath + "/" + seg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update fully replaces the adapter; the variable list defines the complete desired key set and null values keep stored secrets.
func (c *AdaptersClient) Update(ctx context.Context, uuid string, req schema.CustomTargetAdapterUpdateRequest, opts AdapterWriteOpts) (*schema.CustomTargetAdapter, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapter](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.RedTeamAdaptersPath + "/" + seg(uuid), Body: req, Query: adapterWriteQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Delete calls the pinned Adapters contract.
func (c *AdaptersClient) Delete(ctx context.Context, uuid string) error {
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.RedTeamAdaptersPath + "/" + seg(uuid), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// GetConfig calls the pinned Adapters contract.
func (c *AdaptersClient) GetConfig(ctx context.Context) (*schema.CustomTargetAdapterConfigResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapterConfigResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamAdaptersPath + "/config"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Validate calls the pinned Adapters contract.
func (c *AdaptersClient) Validate(ctx context.Context, req schema.CustomTargetAdapterValidateRequest) (*schema.CustomTargetAdapterValidateResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomTargetAdapterValidateResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamAdaptersPath + "/validate", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List calls the pinned NetworkBroker contract.
func (c *NetworkBrokerClient) List(ctx context.Context, opts ChannelListOpts) (*schema.ChannelListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ChannelListResponse](ctx, c.brokerCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamChannelsPath, Query: channelListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create calls the pinned NetworkBroker contract.
func (c *NetworkBrokerClient) Create(ctx context.Context, req schema.CreateChannelRequest) (*schema.Channel, error) {
	resp, err := internal.DoMgmtRequest[schema.Channel](ctx, c.brokerCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.RedTeamChannelsPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get calls the pinned NetworkBroker contract.
func (c *NetworkBrokerClient) Get(ctx context.Context, uuid string) (*schema.Channel, error) {
	resp, err := internal.DoMgmtRequest[schema.Channel](ctx, c.brokerCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamChannelsPath + "/" + seg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update calls the pinned NetworkBroker contract.
func (c *NetworkBrokerClient) Update(ctx context.Context, uuid string, req schema.UpdateChannelRequest) (*schema.Channel, error) {
	resp, err := internal.DoMgmtRequest[schema.Channel](ctx, c.brokerCfg, internal.MgmtRequestOptions{Method: http.MethodPatch, Path: aisec.RedTeamChannelsPath + "/" + seg(uuid), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetStats calls the pinned NetworkBroker contract.
func (c *NetworkBrokerClient) GetStats(ctx context.Context) (*schema.ChannelStats, error) {
	resp, err := internal.DoMgmtRequest[schema.ChannelStats](ctx, c.brokerCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.RedTeamChannelsPath + "/stats"})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func adapterWriteQuery(opts AdapterWriteOpts) url.Values {
	q := url.Values{}
	if opts.Validate != nil {
		q.Set("validate", strconv.FormatBool(*opts.Validate))
	}
	return q
}
func extensionListQuery(opts ListOpts) url.Values {
	q := url.Values{}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Skip > 0 {
		q.Set("skip", strconv.Itoa(opts.Skip))
	}
	return q
}
func adapterListQuery(opts AdapterListOpts) url.Values {
	q := extensionListQuery(opts.ListOpts)
	if opts.Search != "" {
		q.Set("search", opts.Search)
	}
	if opts.Status != "" {
		q.Set("status", string(opts.Status))
	}
	if opts.IncludeTargetCount != nil {
		q.Set("include_target_count", strconv.FormatBool(*opts.IncludeTargetCount))
	}
	return q
}
func channelListQuery(opts ChannelListOpts) url.Values {
	q := extensionListQuery(opts.ListOpts)
	for _, v := range opts.Status {
		q.Add("status", string(v))
	}
	if opts.Search != "" {
		q.Set("search", opts.Search)
	}
	if opts.IncludeAllIfEmpty != nil {
		q.Set("include_all_if_empty", strconv.FormatBool(*opts.IncludeAllIfEmpty))
	}
	return q
}
