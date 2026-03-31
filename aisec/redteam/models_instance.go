package redteam

// --- Instance/Licensing types ---

// InstanceRequest is the request body for creating or updating an instance.
type InstanceRequest struct {
	TsgID              string                `json:"tsg_id"`
	TenantID           string                `json:"tenant_id"`
	AppID              string                `json:"app_id"`
	Region             string                `json:"region"`
	SupportAccountID   string                `json:"support_account_id,omitempty"`
	SupportAccountName string                `json:"support_account_name,omitempty"`
	CreatedBy          string                `json:"created_by,omitempty"`
	Internal           *bool                 `json:"internal,omitempty"`
	TenantInstanceName string                `json:"tenant_instance_name,omitempty"`
	Extra              *InstanceExtraDetails `json:"extra,omitempty"`
	IAMControlled      *bool                 `json:"iam_controlled,omitempty"`
	PlatformRegion     string                `json:"platform_region,omitempty"`
	CspTenantID        string                `json:"csp_tenant_id,omitempty"`
	TsgInstances       []map[string]any      `json:"tsg_instances,omitempty"`
}

// InstanceResponse is the response for instance create/update/delete operations.
type InstanceResponse struct {
	TsgID     string `json:"tsg_id"`
	TenantID  string `json:"tenant_id,omitempty"`
	AppID     string `json:"app_id,omitempty"`
	IsSuccess *bool  `json:"is_success,omitempty"`
}

// InstanceGetResponse is the response for getting an instance.
type InstanceGetResponse struct {
	TsgID              string               `json:"tsg_id"`
	TenantID           string               `json:"tenant_id"`
	AppID              string               `json:"app_id"`
	Region             string               `json:"region"`
	SupportAccountID   string               `json:"support_account_id,omitempty"`
	SupportAccountName string               `json:"support_account_name,omitempty"`
	CreatedBy          string               `json:"created_by,omitempty"`
	Internal           *bool                `json:"internal,omitempty"`
	TenantInstanceName string               `json:"tenant_instance_name,omitempty"`
	DeploymentProfiles []InstanceDPMetadata `json:"deployment_profiles,omitempty"`
}

// InstanceExtraDetails holds extra details for an instance request.
type InstanceExtraDetails struct {
	DeploymentProfiles []DeploymentProfileRequest `json:"deployment_profiles,omitempty"`
	AirsSharedByTsg    map[string]any             `json:"airs_shared_by_tsg,omitempty"`
	AirsUnsharedDps    []string                   `json:"airs_unshared_dps,omitempty"`
}

// InstanceDPMetadata holds deployment profile metadata in an instance response.
type InstanceDPMetadata struct {
	AuthCode     string `json:"auth_code"`
	DpID         string `json:"dp_id,omitempty"`
	DpName       string `json:"dp_name,omitempty"`
	CreatedBy    string `json:"created_by,omitempty"`
	UpdatedBy    string `json:"updated_by,omitempty"`
	LicExpTs     string `json:"lic_exp_ts,omitempty"`
	DeviceSerial string `json:"device_serial,omitempty"`
	Status       string `json:"status,omitempty"`
	DeviceStatus string `json:"device_status,omitempty"`
	ActivatedTs  string `json:"activated_ts,omitempty"`
}

// DeploymentProfileRequest is a deployment profile in an instance request.
type DeploymentProfileRequest struct {
	DAuthCode           string                       `json:"dAuthCode,omitempty"`
	DeploymentProfileID string                       `json:"deploymentProfileId,omitempty"`
	LicenseExpiration   string                       `json:"license_expiration,omitempty"`
	ProfileName         string                       `json:"profileName,omitempty"`
	SubType             string                       `json:"subType,omitempty"`
	Subscriptions       []any                        `json:"subscriptions,omitempty"`
	Type                string                       `json:"type,omitempty"`
	AveTextRecord       *int                         `json:"aveTextRecord,omitempty"`
	Attributes          []DeploymentProfileAttribute `json:"attributes,omitempty"`
}

// DeploymentProfileAttribute is an attribute in a deployment profile.
type DeploymentProfileAttribute struct {
	Quantity      string `json:"quantity,omitempty"`
	UnitOfMeasure string `json:"unit_of_measure,omitempty"`
}

// DeviceRequest is the request body for creating or updating devices.
type DeviceRequest struct {
	Instance  DeviceInstance `json:"instance"`
	CreatedBy string         `json:"created_by,omitempty"`
	Devices   []Device       `json:"devices,omitempty"`
}

// DeviceInstance identifies the instance for a device operation.
type DeviceInstance struct {
	AppID    string `json:"app_id"`
	Region   string `json:"region"`
	TenantID string `json:"tenant_id"`
	TsgID    string `json:"tsg_id"`
}

// Device represents a device in a device request.
type Device struct {
	SerialNumber     string          `json:"serial_number"`
	Model            string          `json:"model,omitempty"`
	SKU              string          `json:"sku,omitempty"`
	DeviceType       string          `json:"device_type,omitempty"`
	DeviceName       string          `json:"device_name,omitempty"`
	TsgID            string          `json:"tsg_id,omitempty"`
	SupportAccountID string          `json:"support_account_id,omitempty"`
	AssetType        string          `json:"asset_type,omitempty"`
	Licenses         []DeviceLicense `json:"licenses,omitempty"`
}

// DeviceLicense represents a license on a device.
type DeviceLicense struct {
	AuthorizationCode          string `json:"authorizationCode,omitempty"`
	ExpirationDate             string `json:"expirationDate,omitempty"`
	LicensePanDbIdentification string `json:"licensePanDbIdentification,omitempty"`
	PartNumber                 string `json:"partNumber,omitempty"`
	SerialNumber               string `json:"serialNumber,omitempty"`
	SubtypeName                string `json:"subtypeName,omitempty"`
	RegistrationDate           string `json:"registrationDate,omitempty"`
}

// DeviceResponse is the response for device operations.
type DeviceResponse struct {
	Devices []DeviceStatus `json:"devices,omitempty"`
	Status  string         `json:"status,omitempty"`
}

// DeviceStatus represents the status of a device in a response.
type DeviceStatus struct {
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}
