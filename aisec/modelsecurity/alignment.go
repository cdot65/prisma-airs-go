package modelsecurity

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	"github.com/cdot65/prisma-airs-go/aisec/modelsecurity/schema"
	"net/http"
	"net/url"
	"strconv"
)

// ModelsClient provides model inventory on the data plane.
type ModelsClient struct{ dataCfg *internal.OAuthServiceConfig }

// ModelVersionsClient provides version details and files on the data plane.
type ModelVersionsClient struct{ dataCfg *internal.OAuthServiceConfig }

// CustomRulesClient manages custom conditions and security-group assignments.
// Archive is reversible; the upstream API has no custom-rule delete operation.
type CustomRulesClient struct{ mgmtCfg *internal.OAuthServiceConfig }

// List calls the current Models API contract.
func (c *ModelsClient) List(ctx context.Context, opts ModelListOpts) (*schema.ModelList, error) {
	resp, err := internal.DoMgmtRequest[schema.ModelList](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecModelsPath, Query: modelListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get calls the current Models API contract.
func (c *ModelsClient) Get(ctx context.Context, uuid string) (*schema.ModelResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecModelsPath + "/" + internal.PathSeg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListVersions calls the current Models API contract.
func (c *ModelsClient) ListVersions(ctx context.Context, uuid string, opts ModelVersionListOpts) (*schema.ModelVersionList, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelVersionList](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecModelsPath + "/" + internal.PathSeg(uuid) + "/model-versions", Query: versionListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get calls the current ModelVersions API contract.
func (c *ModelVersionsClient) Get(ctx context.Context, uuid string) (*schema.ModelVersionResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelVersionResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecModelVersionsPath + "/" + internal.PathSeg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListFiles calls the current ModelVersions API contract.
func (c *ModelVersionsClient) ListFiles(ctx context.Context, uuid string, opts PageOpts) (*schema.FileList, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.FileList](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecModelVersionsPath + "/" + internal.PathSeg(uuid) + "/files", Query: pageQuery(opts.Limit, opts.Skip)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// List calls the current CustomRules API contract.
func (c *CustomRulesClient) List(ctx context.Context, opts CustomRuleListOpts) (*schema.ListCustomRulesResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ListCustomRulesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecCustomRulesPath, Query: customRuleListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Create calls the current CustomRules API contract.
func (c *CustomRulesClient) Create(ctx context.Context, req schema.CustomRuleCreateRequest) (*schema.CustomRuleResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.CustomRuleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.ModelSecCustomRulesPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Get calls the current CustomRules API contract.
func (c *CustomRulesClient) Get(ctx context.Context, uuid string) (*schema.CustomRuleResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.CustomRuleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Update calls the current CustomRules API contract.
func (c *CustomRulesClient) Update(ctx context.Context, uuid string, req schema.CustomRuleUpdateRequest) (*schema.CustomRuleResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.CustomRuleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// Archive calls the current CustomRules API contract.
func (c *CustomRulesClient) Archive(ctx context.Context, uuid string) error {
	if !aisec.IsValidUUID(uuid) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid) + "/archive", ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// Unarchive calls the current CustomRules API contract.
func (c *CustomRulesClient) Unarchive(ctx context.Context, uuid string) error {
	if !aisec.IsValidUUID(uuid) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid) + "/unarchive", ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// ListSecurityGroups calls the current CustomRules API contract.
func (c *CustomRulesClient) ListSecurityGroups(ctx context.Context, uuid string, opts PageOpts) (*schema.ListCustomRuleSecurityGroupsResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ListCustomRuleSecurityGroupsResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid) + "/security-groups", Query: pageQuery(opts.Limit, opts.Skip)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// AssignSecurityGroups returns every item of the HTTP 207 multi-status response, including per-group failures.
func (c *CustomRulesClient) AssignSecurityGroups(ctx context.Context, uuid string, req schema.BatchAssignCustomRuleRequest) (*schema.BatchAssignCustomRuleResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.BatchAssignCustomRuleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid) + "/security-groups", Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// RemoveAssignment calls the current CustomRules API contract.
func (c *CustomRulesClient) RemoveAssignment(ctx context.Context, uuid, sgUUID string) error {
	if !aisec.IsValidUUID(uuid) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	if !aisec.IsValidUUID(sgUUID) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodDelete, Path: aisec.ModelSecCustomRulesPath + "/" + internal.PathSeg(uuid) + "/security-groups/" + internal.PathSeg(sgUUID), ResponsePolicy: internal.AllowEmptyJSON})
	return err
}

// ListVersions calls the current CustomRules API contract.
func (c *CustomRulesClient) ListVersions(ctx context.Context, opts SnapshotListOpts) (*schema.SnapshotVersionListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SnapshotVersionListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecCustomRulesPath + "/versions", Query: snapshotQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListVersions calls the current SecurityRules API contract.
func (c *SecurityRulesClient) ListVersions(ctx context.Context, opts SnapshotListOpts) (*schema.SnapshotVersionListResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.SnapshotVersionListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecSecurityRulesPath + "/versions", Query: snapshotQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListRuleInstanceVersions calls the current SecurityGroups API contract.
func (c *SecurityGroupsClient) ListRuleInstanceVersions(ctx context.Context, uuid string, opts SnapshotListOpts) (*schema.SnapshotVersionListResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.SnapshotVersionListResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + internal.PathSeg(uuid) + "/rule-instances/versions", Query: snapshotQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// CreateDetails calls the current Scans API contract.
func (c *ScansClient) CreateDetails(ctx context.Context, req schema.ScanCreateRequest) (*schema.ScanBaseResponse, error) {
	resp, err := internal.DoMgmtRequest[schema.ScanBaseResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodPost, Path: aisec.ModelSecScansPath, Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetDetails calls the current Scans API contract.
func (c *ScansClient) GetDetails(ctx context.Context, uuid string) (*schema.ScanBaseResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ScanBaseResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/" + internal.PathSeg(uuid)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListDetails calls the current Scans API contract.
func (c *ScansClient) ListDetails(ctx context.Context, opts ScanListOpts) (*schema.ScanList, error) {
	resp, err := internal.DoMgmtRequest[schema.ScanList](ctx, c.dataCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecScansPath, Query: scanListQuery(opts)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateFields calls the current SecurityGroups API contract.
func (c *SecurityGroupsClient) UpdateFields(ctx context.Context, uuid string, req schema.ModelSecurityGroupUpdateRequest) (*schema.ModelSecurityGroupResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelSecurityGroupResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.ModelSecSecurityGroupsPath + "/" + internal.PathSeg(uuid), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// GetRuleInstanceDetails calls the current SecurityGroups API contract.
func (c *SecurityGroupsClient) GetRuleInstanceDetails(ctx context.Context, sgUUID, riUUID string) (*schema.ModelSecurityRuleInstanceResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	if !aisec.IsValidUUID(riUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", riUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelSecurityRuleInstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + internal.PathSeg(sgUUID) + "/rule-instances/" + internal.PathSeg(riUUID)})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// ListRuleInstanceDetails calls the current SecurityGroups API contract.
func (c *SecurityGroupsClient) ListRuleInstanceDetails(ctx context.Context, sgUUID string, opts RuleInstanceListOpts) (*schema.ListModelSecurityRuleInstancesResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ListModelSecurityRuleInstancesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + internal.PathSeg(sgUUID) + "/rule-instances", Query: queryValues(buildRuleInstanceListParams(opts))})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// UpdateRuleInstanceFields calls the current SecurityGroups API contract.
func (c *SecurityGroupsClient) UpdateRuleInstanceFields(ctx context.Context, sgUUID, riUUID string, req schema.ModelSecurityRuleInstanceUpdateRequest) (*schema.ModelSecurityRuleInstanceResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	if !aisec.IsValidUUID(riUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid uuid: %s", riUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[schema.ModelSecurityRuleInstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{Method: http.MethodPut, Path: aisec.ModelSecSecurityGroupsPath + "/" + internal.PathSeg(sgUUID) + "/rule-instances/" + internal.PathSeg(riUUID), Body: req})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func pageQuery(limit, skip int) url.Values {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if skip > 0 {
		q.Set("skip", strconv.Itoa(skip))
	}
	return q
}
func queryValues(params map[string]string) url.Values {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	return q
}
func setQuery(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}
func snapshotQuery(opts SnapshotListOpts) url.Values {
	q := pageQuery(opts.Limit, 0)
	setQuery(q, "next_token", opts.NextToken)
	return q
}
func versionListQuery(opts ModelVersionListOpts) url.Values {
	q := pageQuery(opts.Limit, opts.Skip)
	setQuery(q, "sort_order", opts.SortOrder)
	return q
}
func modelListQuery(opts ModelListOpts) url.Values {
	q := pageQuery(opts.Limit, opts.Skip)
	setQuery(q, "search_query", opts.SearchQuery)
	setQuery(q, "sort_field", opts.SortField)
	setQuery(q, "sort_order", opts.SortOrder)
	setQuery(q, "latest_version_scan_time_before", opts.LatestVersionScanTimeBefore)
	setQuery(q, "start_time", opts.StartTime)
	setQuery(q, "end_time", opts.EndTime)
	for _, v := range opts.LatestVersionOutcomes {
		q.Add("latest_version_outcomes", v)
	}
	for _, v := range opts.LatestVersionFormats {
		q.Add("latest_version_formats", v)
	}
	for _, v := range opts.LatestVersionSourceTypes {
		q.Add("latest_version_source_types", v)
	}
	return q
}
func customRuleListQuery(opts CustomRuleListOpts) url.Values {
	q := pageQuery(opts.Limit, opts.Skip)
	setQuery(q, "sort_field", opts.SortField)
	setQuery(q, "sort_dir", opts.SortDir)
	setQuery(q, "search_query", opts.SearchQuery)
	if opts.IsArchived != nil {
		q.Set("is_archived", strconv.FormatBool(*opts.IsArchived))
	}
	if opts.Generation != nil {
		q.Set("generation", strconv.FormatInt(*opts.Generation, 10))
	}
	for _, v := range opts.SourceTypes {
		q.Add("source_types", v)
	}
	return q
}

// OpenAPI form arrays default to explode=true (repeated keys).
func scanListQuery(opts ScanListOpts) url.Values {
	q := queryValues(buildScanListParams(opts))
	if len(opts.SourceTypes) > 0 {
		q["source_types"] = opts.SourceTypes
	}
	if len(opts.EvalOutcomes) > 0 {
		q["eval_outcomes"] = opts.EvalOutcomes
	}
	return q
}
func groupListQuery(opts GroupListOpts) url.Values {
	q := queryValues(buildGroupListParams(opts))
	if len(opts.SourceTypes) > 0 {
		q["source_types"] = opts.SourceTypes
	}
	if len(opts.EnabledRules) > 0 {
		q["enabled_rules"] = opts.EnabledRules
	}
	return q
}
