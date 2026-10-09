package runtime

// These wrappers scope presence and extension handling to security profiles.
// Each local alias removes only the outer JSON methods; nested profile models
// still use their own methods.

func (v LatencyConfig) MarshalJSON() ([]byte, error) {
	type plain LatencyConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *LatencyConfig) UnmarshalJSON(data []byte) error {
	type plain LatencyConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = LatencyConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v LatencyConfig) FieldPresence(name string) JSONPresence {
	type plain LatencyConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ToxicCategoryConfig) MarshalJSON() ([]byte, error) {
	type plain ToxicCategoryConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ToxicCategoryConfig) UnmarshalJSON(data []byte) error {
	type plain ToxicCategoryConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ToxicCategoryConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ToxicCategoryConfig) FieldPresence(name string) JSONPresence {
	type plain ToxicCategoryConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v TopicRef) MarshalJSON() ([]byte, error) {
	type plain TopicRef
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *TopicRef) UnmarshalJSON(data []byte) error {
	type plain TopicRef
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = TopicRef(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v TopicRef) FieldPresence(name string) JSONPresence {
	type plain TopicRef
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v TopicArrayConfig) MarshalJSON() ([]byte, error) {
	type plain TopicArrayConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *TopicArrayConfig) UnmarshalJSON(data []byte) error {
	type plain TopicArrayConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = TopicArrayConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v TopicArrayConfig) FieldPresence(name string) JSONPresence {
	type plain TopicArrayConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v DataLeakMember) MarshalJSON() ([]byte, error) {
	type plain DataLeakMember
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *DataLeakMember) UnmarshalJSON(data []byte) error {
	type plain DataLeakMember
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = DataLeakMember(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v DataLeakMember) FieldPresence(name string) JSONPresence {
	type plain DataLeakMember
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v DataLeakDetectionConfig) MarshalJSON() ([]byte, error) {
	type plain DataLeakDetectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *DataLeakDetectionConfig) UnmarshalJSON(data []byte) error {
	type plain DataLeakDetectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = DataLeakDetectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v DataLeakDetectionConfig) FieldPresence(name string) JSONPresence {
	type plain DataLeakDetectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v DatabaseSecurityConfig) MarshalJSON() ([]byte, error) {
	type plain DatabaseSecurityConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *DatabaseSecurityConfig) UnmarshalJSON(data []byte) error {
	type plain DatabaseSecurityConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = DatabaseSecurityConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v DatabaseSecurityConfig) FieldPresence(name string) JSONPresence {
	type plain DatabaseSecurityConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v DataProtectionConfig) MarshalJSON() ([]byte, error) {
	type plain DataProtectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *DataProtectionConfig) UnmarshalJSON(data []byte) error {
	type plain DataProtectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = DataProtectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v DataProtectionConfig) FieldPresence(name string) JSONPresence {
	type plain DataProtectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v URLCategoryMember) MarshalJSON() ([]byte, error) {
	type plain URLCategoryMember
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *URLCategoryMember) UnmarshalJSON(data []byte) error {
	type plain URLCategoryMember
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = URLCategoryMember(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v URLCategoryMember) FieldPresence(name string) JSONPresence {
	type plain URLCategoryMember
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v MaliciousCodeProtectionConfig) MarshalJSON() ([]byte, error) {
	type plain MaliciousCodeProtectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *MaliciousCodeProtectionConfig) UnmarshalJSON(data []byte) error {
	type plain MaliciousCodeProtectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = MaliciousCodeProtectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v MaliciousCodeProtectionConfig) FieldPresence(name string) JSONPresence {
	type plain MaliciousCodeProtectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v AppProtectionConfig) MarshalJSON() ([]byte, error) {
	type plain AppProtectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *AppProtectionConfig) UnmarshalJSON(data []byte) error {
	type plain AppProtectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = AppProtectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v AppProtectionConfig) FieldPresence(name string) JSONPresence {
	type plain AppProtectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ModelProtectionConfig) MarshalJSON() ([]byte, error) {
	type plain ModelProtectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ModelProtectionConfig) UnmarshalJSON(data []byte) error {
	type plain ModelProtectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ModelProtectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ModelProtectionConfig) FieldPresence(name string) JSONPresence {
	type plain ModelProtectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v AgentProtectionConfig) MarshalJSON() ([]byte, error) {
	type plain AgentProtectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *AgentProtectionConfig) UnmarshalJSON(data []byte) error {
	type plain AgentProtectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = AgentProtectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v AgentProtectionConfig) FieldPresence(name string) JSONPresence {
	type plain AgentProtectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ModelConfiguration) MarshalJSON() ([]byte, error) {
	type plain ModelConfiguration
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ModelConfiguration) UnmarshalJSON(data []byte) error {
	type plain ModelConfiguration
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ModelConfiguration(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ModelConfiguration) FieldPresence(name string) JSONPresence {
	type plain ModelConfiguration
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v AiSecurityProfileConfig) MarshalJSON() ([]byte, error) {
	type plain AiSecurityProfileConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *AiSecurityProfileConfig) UnmarshalJSON(data []byte) error {
	type plain AiSecurityProfileConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = AiSecurityProfileConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v AiSecurityProfileConfig) FieldPresence(name string) JSONPresence {
	type plain AiSecurityProfileConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v DLPDataProfileConfig) MarshalJSON() ([]byte, error) {
	type plain DLPDataProfileConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *DLPDataProfileConfig) UnmarshalJSON(data []byte) error {
	type plain DLPDataProfileConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = DLPDataProfileConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v DLPDataProfileConfig) FieldPresence(name string) JSONPresence {
	type plain DLPDataProfileConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ProfilePolicy) MarshalJSON() ([]byte, error) {
	type plain ProfilePolicy
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ProfilePolicy) UnmarshalJSON(data []byte) error {
	type plain ProfilePolicy
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ProfilePolicy(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ProfilePolicy) FieldPresence(name string) JSONPresence {
	type plain ProfilePolicy
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v SecurityProfile) MarshalJSON() ([]byte, error) {
	type plain SecurityProfile
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *SecurityProfile) UnmarshalJSON(data []byte) error {
	type plain SecurityProfile
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = SecurityProfile(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v SecurityProfile) FieldPresence(name string) JSONPresence {
	type plain SecurityProfile
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v CreateProfileRequest) MarshalJSON() ([]byte, error) {
	type plain CreateProfileRequest
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *CreateProfileRequest) UnmarshalJSON(data []byte) error {
	type plain CreateProfileRequest
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = CreateProfileRequest(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v CreateProfileRequest) FieldPresence(name string) JSONPresence {
	type plain CreateProfileRequest
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v UpdateProfileRequest) MarshalJSON() ([]byte, error) {
	type plain UpdateProfileRequest
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *UpdateProfileRequest) UnmarshalJSON(data []byte) error {
	type plain UpdateProfileRequest
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = UpdateProfileRequest(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v UpdateProfileRequest) FieldPresence(name string) JSONPresence {
	type plain UpdateProfileRequest
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v SeverityByConfidence) MarshalJSON() ([]byte, error) {
	type plain SeverityByConfidence
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *SeverityByConfidence) UnmarshalJSON(data []byte) error {
	type plain SeverityByConfidence
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = SeverityByConfidence(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v SeverityByConfidence) FieldPresence(name string) JSONPresence {
	type plain SeverityByConfidence
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v SourceCodeDetectionConfig) MarshalJSON() ([]byte, error) {
	type plain SourceCodeDetectionConfig
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *SourceCodeDetectionConfig) UnmarshalJSON(data []byte) error {
	type plain SourceCodeDetectionConfig
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = SourceCodeDetectionConfig(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v SourceCodeDetectionConfig) FieldPresence(name string) JSONPresence {
	type plain SourceCodeDetectionConfig
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ProtectionConfiguration) MarshalJSON() ([]byte, error) {
	type plain ProtectionConfiguration
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ProtectionConfiguration) UnmarshalJSON(data []byte) error {
	type plain ProtectionConfiguration
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ProtectionConfiguration(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ProtectionConfiguration) FieldPresence(name string) JSONPresence {
	type plain ProtectionConfiguration
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

func (v ContentTypeConfigurations) MarshalJSON() ([]byte, error) {
	type plain ContentTypeConfigurations
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *ContentTypeConfigurations) UnmarshalJSON(data []byte) error {
	type plain ContentTypeConfigurations
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = ContentTypeConfigurations(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v ContentTypeConfigurations) FieldPresence(name string) JSONPresence {
	type plain ContentTypeConfigurations
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v LatencyConfig) HasField(name string) bool {
	type plain LatencyConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ToxicCategoryConfig) HasField(name string) bool {
	type plain ToxicCategoryConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v TopicRef) HasField(name string) bool {
	type plain TopicRef
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v TopicArrayConfig) HasField(name string) bool {
	type plain TopicArrayConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v DataLeakMember) HasField(name string) bool {
	type plain DataLeakMember
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v DataLeakDetectionConfig) HasField(name string) bool {
	type plain DataLeakDetectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v DatabaseSecurityConfig) HasField(name string) bool {
	type plain DatabaseSecurityConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v DataProtectionConfig) HasField(name string) bool {
	type plain DataProtectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v URLCategoryMember) HasField(name string) bool {
	type plain URLCategoryMember
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v MaliciousCodeProtectionConfig) HasField(name string) bool {
	type plain MaliciousCodeProtectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v AppProtectionConfig) HasField(name string) bool {
	type plain AppProtectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ModelProtectionConfig) HasField(name string) bool {
	type plain ModelProtectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v AgentProtectionConfig) HasField(name string) bool {
	type plain AgentProtectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ModelConfiguration) HasField(name string) bool {
	type plain ModelConfiguration
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v AiSecurityProfileConfig) HasField(name string) bool {
	type plain AiSecurityProfileConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v DLPDataProfileConfig) HasField(name string) bool {
	type plain DLPDataProfileConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ProfilePolicy) HasField(name string) bool {
	type plain ProfilePolicy
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v SecurityProfile) HasField(name string) bool {
	type plain SecurityProfile
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v CreateProfileRequest) HasField(name string) bool {
	type plain CreateProfileRequest
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v UpdateProfileRequest) HasField(name string) bool {
	type plain UpdateProfileRequest
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v SeverityByConfidence) HasField(name string) bool {
	type plain SeverityByConfidence
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v SourceCodeDetectionConfig) HasField(name string) bool {
	type plain SourceCodeDetectionConfig
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ProtectionConfiguration) HasField(name string) bool {
	type plain ProtectionConfiguration
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
// Check it before FieldPresence to distinguish omission from a field-name typo.
func (v ContentTypeConfigurations) HasField(name string) bool {
	type plain ContentTypeConfigurations
	return profileHasField(plain(v), v.ProfileJSON, name)
}

func (v SecurityProfileListResponse) MarshalJSON() ([]byte, error) {
	type plain SecurityProfileListResponse
	return marshalProfileObject(plain(v), v.ProfileJSON)
}

func (v *SecurityProfileListResponse) UnmarshalJSON(data []byte) error {
	type plain SecurityProfileListResponse
	var next plain
	if err := unmarshalProfileObject(data, &next); err != nil {
		return err
	}
	*v = SecurityProfileListResponse(next)
	return nil
}

// FieldPresence reports the current wire presence of a field by its JSON name.
func (v SecurityProfileListResponse) FieldPresence(name string) JSONPresence {
	type plain SecurityProfileListResponse
	return profileFieldPresence(plain(v), v.ProfileJSON, name)
}

// HasField recognizes a typed JSON name (even when omitted) or a stored extension.
func (v SecurityProfileListResponse) HasField(name string) bool {
	type plain SecurityProfileListResponse
	return profileHasField(plain(v), v.ProfileJSON, name)
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v LatencyConfig) FieldNames() []string {
	type plain LatencyConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ToxicCategoryConfig) FieldNames() []string {
	type plain ToxicCategoryConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v TopicRef) FieldNames() []string {
	type plain TopicRef
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v TopicArrayConfig) FieldNames() []string {
	type plain TopicArrayConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v DataLeakMember) FieldNames() []string {
	type plain DataLeakMember
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v DataLeakDetectionConfig) FieldNames() []string {
	type plain DataLeakDetectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v DatabaseSecurityConfig) FieldNames() []string {
	type plain DatabaseSecurityConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v DataProtectionConfig) FieldNames() []string {
	type plain DataProtectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v URLCategoryMember) FieldNames() []string {
	type plain URLCategoryMember
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v MaliciousCodeProtectionConfig) FieldNames() []string {
	type plain MaliciousCodeProtectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v AppProtectionConfig) FieldNames() []string {
	type plain AppProtectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ModelProtectionConfig) FieldNames() []string {
	type plain ModelProtectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v AgentProtectionConfig) FieldNames() []string {
	type plain AgentProtectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ModelConfiguration) FieldNames() []string {
	type plain ModelConfiguration
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v AiSecurityProfileConfig) FieldNames() []string {
	type plain AiSecurityProfileConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v DLPDataProfileConfig) FieldNames() []string {
	type plain DLPDataProfileConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ProfilePolicy) FieldNames() []string {
	type plain ProfilePolicy
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v SecurityProfile) FieldNames() []string {
	type plain SecurityProfile
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v CreateProfileRequest) FieldNames() []string {
	type plain CreateProfileRequest
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v UpdateProfileRequest) FieldNames() []string {
	type plain UpdateProfileRequest
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v SeverityByConfidence) FieldNames() []string {
	type plain SeverityByConfidence
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v SourceCodeDetectionConfig) FieldNames() []string {
	type plain SourceCodeDetectionConfig
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ProtectionConfiguration) FieldNames() []string {
	type plain ProtectionConfiguration
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v ContentTypeConfigurations) FieldNames() []string {
	type plain ContentTypeConfigurations
	return profileFieldNames(plain(v))
}

// FieldNames returns a fresh sorted list of known typed JSON field names, including
// omitted fields. Extension keys are available separately through Extensions.
func (v SecurityProfileListResponse) FieldNames() []string {
	type plain SecurityProfileListResponse
	return profileFieldNames(plain(v))
}
