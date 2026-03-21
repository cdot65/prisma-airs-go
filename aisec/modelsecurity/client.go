package modelsecurity

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
)

// Opts are options for creating a ModelSecurityClient.
type Opts struct {
	ClientID      string
	ClientSecret  string
	TsgID         string
	DataEndpoint  string
	MgmtEndpoint  string
	TokenEndpoint string
	NumRetries    int
}

// Client is the Model Security API client with dual-endpoint routing.
type Client struct {
	Scans          *ScansClient
	SecurityGroups *SecurityGroupsClient
	SecurityRules  *SecurityRulesClient

	mgmtCfg *internal.OAuthServiceConfig
}

// NewClient creates a new Model Security API client.
func NewClient(opts Opts) (*Client, error) {
	dataEndpoint := opts.DataEndpoint
	if dataEndpoint == "" {
		dataEndpoint = aisec.DefaultModelSecDataEndpoint
	}

	mgmtEndpoint := opts.MgmtEndpoint
	if mgmtEndpoint == "" {
		mgmtEndpoint = aisec.DefaultModelSecMgmtEndpoint
	}

	mgmtCfg, err := internal.ResolveOAuthConfig(internal.ResolveOAuthConfigOpts{
		ClientID:          opts.ClientID,
		ClientSecret:      opts.ClientSecret,
		TsgID:             opts.TsgID,
		BaseURL:           mgmtEndpoint,
		NumRetries:        opts.NumRetries,
		TokenEndpoint:     opts.TokenEndpoint,
		PrimaryEnvPrefix:  "PANW_MODEL_SEC",
		FallbackEnvPrefix: "PANW_MGMT",
	})
	if err != nil {
		return nil, err
	}

	// Data plane config shares the same OAuth client but different base URL.
	dataCfg := &internal.OAuthServiceConfig{
		BaseURL:    dataEndpoint,
		OAuth:      mgmtCfg.OAuth,
		NumRetries: mgmtCfg.NumRetries,
		TsgID:      mgmtCfg.TsgID,
	}

	c := &Client{mgmtCfg: mgmtCfg}
	c.Scans = &ScansClient{dataCfg: dataCfg}
	c.SecurityGroups = &SecurityGroupsClient{mgmtCfg: mgmtCfg}
	c.SecurityRules = &SecurityRulesClient{mgmtCfg: mgmtCfg}

	return c, nil
}

// GetPyPIAuth gets PyPI authentication credentials for Google Artifact Registry.
func (c *Client) GetPyPIAuth(ctx context.Context) (*PyPIAuthResponse, error) {
	resp, err := internal.DoMgmtRequest[PyPIAuthResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecPyPIAuthPath,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Scans Client (data plane) ---

// ScansClient provides model security scan operations via the data plane.
type ScansClient struct {
	dataCfg *internal.OAuthServiceConfig
}

func (c *ScansClient) Create(ctx context.Context, req ScanCreateRequest) (*ScanBaseResponse, error) {
	resp, err := internal.DoMgmtRequest[ScanBaseResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.ModelSecScansPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) List(ctx context.Context, opts ScanListOpts) (*ScanList, error) {
	resp, err := internal.DoMgmtRequest[ScanList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath, Params: buildScanListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) Get(ctx context.Context, uuid string) (*ScanBaseResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ScanBaseResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetEvaluations(ctx context.Context, scanUUID string, opts EvaluationListOpts) (*RuleEvaluationList, error) {
	if !aisec.IsValidUUID(scanUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[RuleEvaluationList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/" + scanUUID + "/evaluations", Params: buildEvaluationListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetEvaluation(ctx context.Context, uuid string) (*RuleEvaluationResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid evaluation uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[RuleEvaluationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecEvaluationsPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetFiles(ctx context.Context, scanUUID string, opts FileListOpts) (*FileList, error) {
	if !aisec.IsValidUUID(scanUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[FileList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/" + scanUUID + "/files", Params: buildFileListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetViolations(ctx context.Context, scanUUID string, opts ViolationListOpts) (*ViolationList, error) {
	if !aisec.IsValidUUID(scanUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ViolationList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/" + scanUUID + "/rule-violations", Params: buildViolationListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetViolation(ctx context.Context, uuid string) (*ViolationResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid violation uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ViolationResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecViolationsPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) AddLabels(ctx context.Context, scanUUID string, req LabelsCreateRequest) (*LabelsResponse, error) {
	if !aisec.IsValidUUID(scanUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[LabelsResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.ModelSecScansPath + "/" + scanUUID + "/labels", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) SetLabels(ctx context.Context, scanUUID string, req LabelsCreateRequest) (*LabelsResponse, error) {
	if !aisec.IsValidUUID(scanUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[LabelsResponse](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.ModelSecScansPath + "/" + scanUUID + "/labels", Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) DeleteLabels(ctx context.Context, scanUUID string, keys []string) error {
	if !aisec.IsValidUUID(scanUUID) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid scan uuid: %s", scanUUID), aisec.UserRequestPayloadError)
	}
	// Build repeated query params: ?keys=key1&keys=key2
	q := url.Values{}
	for _, k := range keys {
		q.Add("keys", k)
	}
	path := aisec.ModelSecScansPath + "/" + scanUUID + "/labels"
	if qs := q.Encode(); qs != "" {
		path += "?" + qs
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: path,
	})
	return err
}

func (c *ScansClient) GetLabelKeys(ctx context.Context, opts LabelListOpts) (*LabelKeyList, error) {
	resp, err := internal.DoMgmtRequest[LabelKeyList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/label-keys", Params: buildLabelListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ScansClient) GetLabelValues(ctx context.Context, key string, opts LabelListOpts) (*LabelValueList, error) {
	resp, err := internal.DoMgmtRequest[LabelValueList](ctx, c.dataCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecScansPath + "/label-keys/" + url.PathEscape(key) + "/values", Params: buildLabelListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Security Groups Client (mgmt plane) ---

// SecurityGroupsClient provides security group CRUD and nested rule instance operations.
type SecurityGroupsClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

func (c *SecurityGroupsClient) Create(ctx context.Context, req ModelSecurityGroupCreateRequest) (*ModelSecurityGroupResponse, error) {
	resp, err := internal.DoMgmtRequest[ModelSecurityGroupResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPost, Path: aisec.ModelSecSecurityGroupsPath, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) List(ctx context.Context, opts GroupListOpts) (*ListModelSecurityGroupsResponse, error) {
	resp, err := internal.DoMgmtRequest[ListModelSecurityGroupsResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath, Params: buildGroupListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) Get(ctx context.Context, uuid string) (*ModelSecurityGroupResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ModelSecurityGroupResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) Update(ctx context.Context, uuid string, req ModelSecurityGroupUpdateRequest) (*ModelSecurityGroupResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ModelSecurityGroupResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.ModelSecSecurityGroupsPath + "/" + uuid, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) Delete(ctx context.Context, uuid string) error {
	if !aisec.IsValidUUID(uuid) {
		return aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	_, err := internal.DoMgmtRequest[any](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodDelete, Path: aisec.ModelSecSecurityGroupsPath + "/" + uuid,
	})
	return err
}

func (c *SecurityGroupsClient) ListRuleInstances(ctx context.Context, sgUUID string, opts RuleInstanceListOpts) (*ListModelSecurityRuleInstancesResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ListModelSecurityRuleInstancesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + sgUUID + "/rule-instances", Params: buildRuleInstanceListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) GetRuleInstance(ctx context.Context, sgUUID, riUUID string) (*ModelSecurityRuleInstanceResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	if !aisec.IsValidUUID(riUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid rule instance uuid: %s", riUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ModelSecurityRuleInstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityGroupsPath + "/" + sgUUID + "/rule-instances/" + riUUID,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityGroupsClient) UpdateRuleInstance(ctx context.Context, sgUUID, riUUID string, req ModelSecurityRuleInstanceUpdateRequest) (*ModelSecurityRuleInstanceResponse, error) {
	if !aisec.IsValidUUID(sgUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security group uuid: %s", sgUUID), aisec.UserRequestPayloadError)
	}
	if !aisec.IsValidUUID(riUUID) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid rule instance uuid: %s", riUUID), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ModelSecurityRuleInstanceResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodPut, Path: aisec.ModelSecSecurityGroupsPath + "/" + sgUUID + "/rule-instances/" + riUUID, Body: req,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Security Rules Client (mgmt plane, read-only) ---

// SecurityRulesClient provides read-only access to security rules.
type SecurityRulesClient struct {
	mgmtCfg *internal.OAuthServiceConfig
}

func (c *SecurityRulesClient) List(ctx context.Context, opts RuleListOpts) (*ListModelSecurityRulesResponse, error) {
	resp, err := internal.DoMgmtRequest[ListModelSecurityRulesResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityRulesPath, Params: buildRuleListParams(opts),
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *SecurityRulesClient) Get(ctx context.Context, uuid string) (*ModelSecurityRuleResponse, error) {
	if !aisec.IsValidUUID(uuid) {
		return nil, aisec.NewAISecSDKError(fmt.Sprintf("invalid security rule uuid: %s", uuid), aisec.UserRequestPayloadError)
	}
	resp, err := internal.DoMgmtRequest[ModelSecurityRuleResponse](ctx, c.mgmtCfg, internal.MgmtRequestOptions{
		Method: http.MethodGet, Path: aisec.ModelSecSecurityRulesPath + "/" + uuid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// --- Param builders ---

func buildScanListParams(opts ScanListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SortBy != "" {
		params["sort_by"] = opts.SortBy
	}
	if opts.SortOrder != "" {
		params["sort_order"] = opts.SortOrder
	}
	if opts.SearchQuery != "" {
		params["search_query"] = opts.SearchQuery
	}
	if opts.SecurityGroupUUID != "" {
		params["security_group_uuid"] = opts.SecurityGroupUUID
	}
	if opts.StartTime != "" {
		params["start_time"] = opts.StartTime
	}
	if opts.EndTime != "" {
		params["end_time"] = opts.EndTime
	}
	if opts.LabelsQuery != "" {
		params["labels_query"] = opts.LabelsQuery
	}
	return params
}

func buildEvaluationListParams(opts EvaluationListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SortField != "" {
		params["sort_field"] = opts.SortField
	}
	if opts.SortOrder != "" {
		params["sort_order"] = opts.SortOrder
	}
	if opts.Result != "" {
		params["result"] = opts.Result
	}
	if opts.RuleInstanceUUID != "" {
		params["rule_instance_uuid"] = opts.RuleInstanceUUID
	}
	return params
}

func buildFileListParams(opts FileListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SortField != "" {
		params["sort_field"] = opts.SortField
	}
	if opts.SortDir != "" {
		params["sort_dir"] = opts.SortDir
	}
	if opts.Type != "" {
		params["type"] = opts.Type
	}
	if opts.Result != "" {
		params["result"] = opts.Result
	}
	if opts.QueryPath != "" {
		params["query_path"] = opts.QueryPath
	}
	return params
}

func buildLabelListParams(opts LabelListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.Search != "" {
		params["search"] = opts.Search
	}
	return params
}

func buildViolationListParams(opts ViolationListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	return params
}

func buildGroupListParams(opts GroupListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SortField != "" {
		params["sort_field"] = opts.SortField
	}
	if opts.SortDir != "" {
		params["sort_dir"] = opts.SortDir
	}
	if opts.SearchQuery != "" {
		params["search_query"] = opts.SearchQuery
	}
	return params
}

func buildRuleInstanceListParams(opts RuleInstanceListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SecurityRuleUUID != "" {
		params["security_rule_uuid"] = opts.SecurityRuleUUID
	}
	if opts.State != "" {
		params["state"] = opts.State
	}
	return params
}

func buildRuleListParams(opts RuleListOpts) map[string]string {
	params := map[string]string{}
	if opts.Skip > 0 {
		params["skip"] = fmt.Sprintf("%d", opts.Skip)
	}
	if opts.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", opts.Limit)
	}
	if opts.SourceType != "" {
		params["source_type"] = opts.SourceType
	}
	if opts.SearchQuery != "" {
		params["search_query"] = opts.SearchQuery
	}
	return params
}
