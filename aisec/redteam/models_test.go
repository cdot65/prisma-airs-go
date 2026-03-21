package redteam

import (
	"encoding/json"
	"testing"
)

// --- Enum tests ---

func TestAttackStatus_Values(t *testing.T) {
	vals := []AttackStatus{
		AttackStatusInit, AttackStatusAttack, AttackStatusDetection,
		AttackStatusReport, AttackStatusCompleted, AttackStatusFailed,
	}
	expected := []string{"INIT", "ATTACK", "DETECTION", "REPORT", "COMPLETED", "FAILED"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("AttackStatus[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestAttackType_Values(t *testing.T) {
	vals := []AttackType{AttackTypeNormal, AttackTypeCustom}
	expected := []string{"NORMAL", "CUSTOM"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("AttackType[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestAuthType_Values(t *testing.T) {
	vals := []AuthType{AuthTypeOAuth, AuthTypeAccessToken}
	expected := []string{"OAUTH", "ACCESS_TOKEN"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("AuthType[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestBrandSubCategory_Values(t *testing.T) {
	vals := []BrandSubCategory{
		BrandSubCategoryCompetitorEndorsements,
		BrandSubCategoryBrandTarnishing,
		BrandSubCategoryDiscriminatingClaims,
		BrandSubCategoryPoliticalEndorsements,
	}
	expected := []string{"COMPETITOR_ENDORSEMENTS", "BRAND_TARNISHING_SELF_CRITICISM", "DISCRIMINATING_CLAIMS", "POLITICAL_ENDORSEMENTS"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("BrandSubCategory[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestComplianceSubCategory_Values(t *testing.T) {
	vals := []ComplianceSubCategory{
		ComplianceSubCategoryOWASP, ComplianceSubCategoryMITREATLAS,
		ComplianceSubCategoryNIST, ComplianceSubCategoryDASFV2,
	}
	expected := []string{"OWASP", "MITRE_ATLAS", "NIST", "DASF_V2"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("ComplianceSubCategory[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestSafetySubCategory_Values(t *testing.T) {
	vals := []SafetySubCategory{
		SafetySubCategoryBias, SafetySubCategoryCBRN, SafetySubCategoryCybercrime,
		SafetySubCategoryDrugs, SafetySubCategoryHateToxicAbuse,
		SafetySubCategoryNonViolentCrimes, SafetySubCategoryPolitical,
		SafetySubCategorySelfHarm, SafetySubCategorySexual,
		SafetySubCategoryViolentCrimesWeapons,
	}
	expected := []string{
		"BIAS", "CBRN", "CYBERCRIME", "DRUGS", "HATE_TOXIC_ABUSE",
		"NON_VIOLENT_CRIMES", "POLITICAL", "SELF_HARM", "SEXUAL", "VIOLENT_CRIMES_WEAPONS",
	}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("SafetySubCategory[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestSecuritySubCategory_Values(t *testing.T) {
	vals := []SecuritySubCategory{
		SecuritySubCategoryAdversarialSuffix, SecuritySubCategoryEvasion,
		SecuritySubCategoryIndirectPromptInjection, SecuritySubCategoryJailbreak,
		SecuritySubCategoryMultiTurn, SecuritySubCategoryPromptInjection,
		SecuritySubCategoryRemoteCodeExecution, SecuritySubCategorySystemPromptLeak,
		SecuritySubCategoryToolLeak, SecuritySubCategoryMalwareGeneration,
	}
	expected := []string{
		"ADVERSARIAL_SUFFIX", "EVASION", "INDIRECT_PROMPT_INJECTION", "JAILBREAK",
		"MULTI_TURN", "PROMPT_INJECTION", "REMOTE_CODE_EXECUTION", "SYSTEM_PROMPT_LEAK",
		"TOOL_LEAK", "MALWARE_GENERATION",
	}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("SecuritySubCategory[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestErrorSource_Values(t *testing.T) {
	vals := []ErrorSource{
		ErrorSourceTarget, ErrorSourceJob, ErrorSourceSystem,
		ErrorSourceValidation, ErrorSourceTargetProfiling,
	}
	expected := []string{"TARGET", "JOB", "SYSTEM", "VALIDATION", "TARGET_PROFILING"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("ErrorSource[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestErrorTypeEnum_Values(t *testing.T) {
	vals := []ErrorTypeEnum{
		ErrorTypeContentFilter, ErrorTypeRateLimit, ErrorTypeAuthentication,
		ErrorTypeNetwork, ErrorTypeValidation, ErrorTypeNetworkChannel, ErrorTypeUnknown,
	}
	expected := []string{"CONTENT_FILTER", "RATE_LIMIT", "AUTHENTICATION", "NETWORK", "VALIDATION", "NETWORK_CHANNEL", "UNKNOWN"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("ErrorTypeEnum[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestProfilingStatus_Values(t *testing.T) {
	vals := []ProfilingStatus{
		ProfilingStatusInit, ProfilingStatusQueued, ProfilingStatusInProgress,
		ProfilingStatusCompleted, ProfilingStatusFailed,
	}
	expected := []string{"INIT", "QUEUED", "IN_PROGRESS", "COMPLETED", "FAILED"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("ProfilingStatus[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestStreamType_Values(t *testing.T) {
	vals := []StreamType{StreamTypeNormal, StreamTypeAdversarial}
	expected := []string{"NORMAL", "ADVERSARIAL"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("StreamType[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestPolicyType_Values(t *testing.T) {
	vals := []PolicyType{
		PolicyTypePromptInjection, PolicyTypeToxicContent,
		PolicyTypeCustomTopicGuardrails, PolicyTypeMaliciousCodeDetection,
		PolicyTypeMaliciousURLDetection, PolicyTypeSensitiveDataProtection,
	}
	expected := []string{
		"PROMPT_INJECTION", "TOXIC_CONTENT", "CUSTOM_TOPIC_GUARDRAILS",
		"MALICIOUS_CODE_DETECTION", "MALICIOUS_URL_DETECTION", "SENSITIVE_DATA_PROTECTION",
	}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("PolicyType[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestGuardrailAction_Values(t *testing.T) {
	vals := []GuardrailAction{GuardrailActionAllow, GuardrailActionBlock}
	expected := []string{"ALLOW", "BLOCK"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("GuardrailAction[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestDateRangeFilter_Values(t *testing.T) {
	vals := []DateRangeFilter{
		DateRangeFilterLast7Days, DateRangeFilterLast15Days,
		DateRangeFilterLast30Days, DateRangeFilterAll,
	}
	expected := []string{"LAST_7_DAYS", "LAST_15_DAYS", "LAST_30_DAYS", "ALL"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("DateRangeFilter[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

func TestCountedQuotaEnum_Values(t *testing.T) {
	vals := []CountedQuotaEnum{CountedQuotaHeld, CountedQuotaCounted, CountedQuotaNotCounted}
	expected := []string{"HELD", "COUNTED", "NOT_COUNTED"}
	for i, v := range vals {
		if string(v) != expected[i] {
			t.Errorf("CountedQuotaEnum[%d] = %q, want %q", i, v, expected[i])
		}
	}
}

// --- Struct tests ---

func TestCustomPromptResponse_UserDefinedGoalBool(t *testing.T) {
	j := `{"uuid":"p1","user_defined_goal":true,"status":"ACTIVE","updated_at":"2025-01-01T00:00:00Z"}`
	var p CustomPromptResponse
	if err := json.Unmarshal([]byte(j), &p); err != nil {
		t.Fatal(err)
	}
	if !p.UserDefinedGoal {
		t.Error("UserDefinedGoal should be true")
	}
	if p.Status != "ACTIVE" {
		t.Errorf("Status = %q", p.Status)
	}
	if p.UpdatedAt != "2025-01-01T00:00:00Z" {
		t.Errorf("UpdatedAt = %q", p.UpdatedAt)
	}
}

func TestCustomPromptSetResponse_ExtraFields(t *testing.T) {
	j := `{
		"uuid":"s1","name":"test","version":"1","property_names":["color","size"],
		"created_by_user_id":"u1","updated_by_user_id":"u2"
	}`
	var s CustomPromptSetResponse
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != "1" {
		t.Errorf("Version = %q", s.Version)
	}
	if len(s.PropertyNames) != 2 {
		t.Errorf("PropertyNames = %v", s.PropertyNames)
	}
	if s.CreatedByUserID != "u1" {
		t.Errorf("CreatedByUserID = %q", s.CreatedByUserID)
	}
}

func TestCustomPromptSetReference_FullFields(t *testing.T) {
	j := `{
		"uuid":"r1","name":"ref-set","version":"2","status":"ACTIVE",
		"active":true,"tsg_id":"t1","created_at":"2025-01-01","updated_at":"2025-06-01"
	}`
	var r CustomPromptSetReference
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if r.Name != "ref-set" {
		t.Errorf("Name = %q", r.Name)
	}
	if r.Version != "2" {
		t.Errorf("Version = %q", r.Version)
	}
	if r.Status != "ACTIVE" {
		t.Errorf("Status = %q", r.Status)
	}
	if !r.Active {
		t.Error("Active should be true")
	}
	if r.TsgID != "t1" {
		t.Errorf("TsgID = %q", r.TsgID)
	}
}

func TestGoal_FullFields(t *testing.T) {
	j := `{
		"uuid":"g1","goal_type":"BASE","status":"COMPLETED",
		"goal":"extract secrets","safe_response":"I cannot help",
		"jailbroken_response":"here are the secrets",
		"goal_metadata":{"key":"val"},"custom_goal":true,
		"tsg_id":"t1","job_id":"j1","threat":true,"version":2
	}`
	var g Goal
	if err := json.Unmarshal([]byte(j), &g); err != nil {
		t.Fatal(err)
	}
	if g.UUID != "g1" {
		t.Errorf("UUID = %q", g.UUID)
	}
	if g.Goal != "extract secrets" {
		t.Errorf("Goal = %q", g.Goal)
	}
	if g.SafeResponse != "I cannot help" {
		t.Errorf("SafeResponse = %q", g.SafeResponse)
	}
	if g.JailbrokenResponse != "here are the secrets" {
		t.Errorf("JailbrokenResponse = %q", g.JailbrokenResponse)
	}
	if !g.CustomGoal {
		t.Error("CustomGoal should be true")
	}
	if g.TsgID != "t1" {
		t.Errorf("TsgID = %q", g.TsgID)
	}
	if g.JobID != "j1" {
		t.Errorf("JobID = %q", g.JobID)
	}
	if g.Threat == nil || !*g.Threat {
		t.Error("Threat should be true")
	}
	if g.Version == nil || *g.Version != 2 {
		t.Errorf("Version = %v", g.Version)
	}
}

func TestTargetMetadata_JSON(t *testing.T) {
	j := `{
		"multi_turn":true,"rate_limit":10,"rate_limit_enabled":true,
		"content_filter_enabled":true,"probe_message":"hello","request_timeout":30
	}`
	var m TargetMetadata
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	if !m.MultiTurn {
		t.Error("MultiTurn should be true")
	}
	if m.RateLimit == nil || *m.RateLimit != 10 {
		t.Errorf("RateLimit = %v", m.RateLimit)
	}
	if !m.RateLimitEnabled {
		t.Error("RateLimitEnabled should be true")
	}
	if m.ProbeMessage != "hello" {
		t.Errorf("ProbeMessage = %q", m.ProbeMessage)
	}
}

func TestTargetBackground_JSON(t *testing.T) {
	j := `{"industry":"finance","use_case":"chatbot","competitors":["a","b"]}`
	var b TargetBackground
	if err := json.Unmarshal([]byte(j), &b); err != nil {
		t.Fatal(err)
	}
	if b.Industry != "finance" {
		t.Errorf("Industry = %q", b.Industry)
	}
	if len(b.Competitors) != 2 {
		t.Errorf("Competitors = %v", b.Competitors)
	}
}

func TestTargetAdditionalContext_JSON(t *testing.T) {
	j := `{
		"base_model":"gpt-4","system_prompt":"you are helpful",
		"languages_supported":["en","fr"],"banned_keywords":["hack"]
	}`
	var c TargetAdditionalContext
	if err := json.Unmarshal([]byte(j), &c); err != nil {
		t.Fatal(err)
	}
	if c.BaseModel != "gpt-4" {
		t.Errorf("BaseModel = %q", c.BaseModel)
	}
	if c.SystemPrompt != "you are helpful" {
		t.Errorf("SystemPrompt = %q", c.SystemPrompt)
	}
	if len(c.LanguagesSupported) != 2 {
		t.Errorf("LanguagesSupported = %v", c.LanguagesSupported)
	}
}

func TestPropertyAssignment_JSON(t *testing.T) {
	j := `{"property_name":"color","property_value":"red"}`
	var p PropertyAssignment
	if err := json.Unmarshal([]byte(j), &p); err != nil {
		t.Fatal(err)
	}
	if p.PropertyName != "color" {
		t.Errorf("PropertyName = %q", p.PropertyName)
	}
	if p.PropertyValue != "red" {
		t.Errorf("PropertyValue = %q", p.PropertyValue)
	}
}

func TestErrorLog_JSON(t *testing.T) {
	j := `{
		"job_id":"j1","target_id":"t1","error_source":"TARGET",
		"error_type":"RATE_LIMIT","error_message":"too fast","created_at":"2025-01-01"
	}`
	var e ErrorLog
	if err := json.Unmarshal([]byte(j), &e); err != nil {
		t.Fatal(err)
	}
	if e.JobID != "j1" {
		t.Errorf("JobID = %q", e.JobID)
	}
	if e.ErrorSource != "TARGET" {
		t.Errorf("ErrorSource = %q", e.ErrorSource)
	}
	if e.ErrorType != "RATE_LIMIT" {
		t.Errorf("ErrorType = %q", e.ErrorType)
	}
}

func TestStaticJobReport_TypedFields(t *testing.T) {
	j := `{
		"asr":75.5,"score":82.3,"report_summary":"test summary",
		"severity_report":{"low":5,"medium":3,"high":1,"critical":0}
	}`
	var r StaticJobReport
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if r.ASR == nil || *r.ASR != 75.5 {
		t.Errorf("ASR = %v", r.ASR)
	}
	if r.Score == nil || *r.Score != 82.3 {
		t.Errorf("Score = %v", r.Score)
	}
	if r.ReportSummary != "test summary" {
		t.Errorf("ReportSummary = %q", r.ReportSummary)
	}
}

func TestDynamicJobReport_TypedFields(t *testing.T) {
	j := `{
		"total_goals":10,"total_streams":5,"total_threats":3,
		"goals_achieved":7,"score":65.0,"asr":30.0,"report_summary":"dynamic test"
	}`
	var r DynamicJobReport
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if r.TotalGoals != 10 {
		t.Errorf("TotalGoals = %d", r.TotalGoals)
	}
	if r.TotalStreams != 5 {
		t.Errorf("TotalStreams = %d", r.TotalStreams)
	}
	if r.Score != 65.0 {
		t.Errorf("Score = %f", r.Score)
	}
}

func TestAttackDetailResponse_TypedFields(t *testing.T) {
	j := `{
		"uuid":"a1","tsg_id":"t1","job_id":"j1","target_id":"tgt1",
		"prompt":"test prompt","status":"COMPLETED","threat":true,
		"attack_type":"NORMAL","multi_turn":false,"severity":"HIGH",
		"category":"SECURITY","sub_category":"JAILBREAK",
		"category_display_name":"Security","sub_category_display_name":"Jailbreak"
	}`
	var a AttackDetailResponse
	if err := json.Unmarshal([]byte(j), &a); err != nil {
		t.Fatal(err)
	}
	if a.UUID != "a1" {
		t.Errorf("UUID = %q", a.UUID)
	}
	if a.TsgID != "t1" {
		t.Errorf("TsgID = %q", a.TsgID)
	}
	if a.Prompt != "test prompt" {
		t.Errorf("Prompt = %q", a.Prompt)
	}
	if a.Status != "COMPLETED" {
		t.Errorf("Status = %q", a.Status)
	}
	if a.Threat == nil || !*a.Threat {
		t.Error("Threat should be true")
	}
	if a.AttackType != "NORMAL" {
		t.Errorf("AttackType = %q", a.AttackType)
	}
	if a.Category != "SECURITY" {
		t.Errorf("Category = %q", a.Category)
	}
	if a.SubCategory != "JAILBREAK" {
		t.Errorf("SubCategory = %q", a.SubCategory)
	}
	if a.CategoryDisplayName != "Security" {
		t.Errorf("CategoryDisplayName = %q", a.CategoryDisplayName)
	}
}

func TestScoreTrendResponse_TypedFields(t *testing.T) {
	j := `{"labels":["2025-01","2025-02"],"series":[{"label":"STATIC","data":[70.5,80.2]}]}`
	var r ScoreTrendResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Labels) != 2 {
		t.Errorf("Labels = %v", r.Labels)
	}
	if len(r.Series) != 1 {
		t.Errorf("Series len = %d", len(r.Series))
	}
	if r.Series[0].Label != "STATIC" {
		t.Errorf("Series[0].Label = %q", r.Series[0].Label)
	}
	if len(r.Series[0].Data) != 2 {
		t.Errorf("Series[0].Data = %v", r.Series[0].Data)
	}
}

func TestQuotaSummary_TypedFields(t *testing.T) {
	j := `{
		"static":{"allocated":100,"unlimited":false,"consumed":50},
		"dynamic":{"allocated":200,"unlimited":true,"consumed":30},
		"custom":{"allocated":50,"unlimited":false,"consumed":10}
	}`
	var q QuotaSummary
	if err := json.Unmarshal([]byte(j), &q); err != nil {
		t.Fatal(err)
	}
	if q.Static.Allocated != 100 {
		t.Errorf("Static.Allocated = %d", q.Static.Allocated)
	}
	if q.Dynamic.Consumed != 30 {
		t.Errorf("Dynamic.Consumed = %d", q.Dynamic.Consumed)
	}
}

func TestScanStatisticsResponse_TypedFields(t *testing.T) {
	j := `{
		"total_scans":100,"targets_scanned":5,
		"targets_scanned_by_type":[{"name":"APPLICATION","count":3}],
		"scan_status":[{"name":"COMPLETED","count":80}],
		"risk_profile":[{"level":"HIGH","count":10}]
	}`
	var s ScanStatisticsResponse
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		t.Fatal(err)
	}
	if s.TotalScans != 100 {
		t.Errorf("TotalScans = %d", s.TotalScans)
	}
	if s.TargetsScanned != 5 {
		t.Errorf("TargetsScanned = %d", s.TargetsScanned)
	}
	if len(s.TargetsScannedByType) != 1 {
		t.Errorf("TargetsScannedByType = %v", s.TargetsScannedByType)
	}
}

// --- Spec alignment: "data" JSON key for list responses ---

func TestJobListResponse_DataKey(t *testing.T) {
	j := `{"data":[{"uuid":"j1","name":"test"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r JobListResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 || r.Data[0].UUID != "j1" {
		t.Errorf("Data = %+v", r.Data)
	}
}

func TestAttackListResponse_DataKey(t *testing.T) {
	j := `{"data":[{"id":"a1"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r AttackListResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 {
		t.Errorf("Data len = %d", len(r.Data))
	}
}

func TestGoalListResponse_DataKey(t *testing.T) {
	j := `{"data":[{"uuid":"g1","goal_type":"BASE"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r GoalListResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 || r.Data[0].UUID != "g1" {
		t.Errorf("Data = %+v", r.Data)
	}
}

func TestTargetList_DataKey(t *testing.T) {
	j := `{"data":[{"uuid":"t1","name":"test","tsg_id":"tsg1","status":"ACTIVE","active":true,"validated":true,"created_at":"2025-01-01","updated_at":"2025-01-01"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r TargetList
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 || r.Data[0].UUID != "t1" {
		t.Errorf("Data = %+v", r.Data)
	}
}

// --- Spec alignment: target model JSON keys ---

func TestTargetCreateRequest_SpecAlignedJSONKeys(t *testing.T) {
	bg := &TargetBackground{Industry: "finance", UseCase: "chatbot"}
	ctx := &TargetAdditionalContext{BaseModel: "gpt-4"}
	meta := &TargetMetadata{MultiTurn: true}
	req := TargetCreateRequest{
		Name:              "test",
		TargetBackground:  bg,
		AdditionalContext: ctx,
		TargetMeta:        meta,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Spec keys must be target_background, additional_context, target_metadata
	if _, ok := m["target_background"]; !ok {
		t.Error("missing JSON key target_background")
	}
	if _, ok := m["additional_context"]; !ok {
		t.Error("missing JSON key additional_context")
	}
	if _, ok := m["target_metadata"]; !ok {
		t.Error("missing JSON key target_metadata")
	}
	// Old wrong keys must NOT appear
	if _, ok := m["background"]; ok {
		t.Error("unexpected JSON key background (should be target_background)")
	}
	if _, ok := m["context"]; ok {
		t.Error("unexpected JSON key context (should be additional_context)")
	}
	if _, ok := m["metadata"]; ok {
		t.Error("unexpected JSON key metadata (should be target_metadata)")
	}
}

func TestTargetUpdateRequest_SpecAlignedFields(t *testing.T) {
	bg := &TargetBackground{Industry: "healthcare"}
	ctx := &TargetAdditionalContext{SystemPrompt: "you are helpful"}
	meta := &TargetMetadata{ProbeMessage: "hello"}
	req := TargetUpdateRequest{
		Name:                     "updated",
		APIEndpointType:          APIEndpointTypePrivate,
		ResponseMode:             ResponseModeRest,
		SessionSupported:         true,
		ExtraInfo:                map[string]any{"k": "v"},
		NetworkBrokerChannelUUID: "ch-uuid",
		TargetMeta:               meta,
		TargetBackground:         bg,
		AdditionalContext:        ctx,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"name", "api_endpoint_type", "response_mode", "session_supported",
		"extra_info", "network_broker_channel_uuid",
		"target_metadata", "target_background", "additional_context",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}
}

func TestTargetContextUpdate_SpecAlignedKeys(t *testing.T) {
	req := TargetContextUpdate{
		TargetBackground:  &TargetBackground{Industry: "tech"},
		AdditionalContext: &TargetAdditionalContext{BaseModel: "claude"},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["target_background"]; !ok {
		t.Error("missing JSON key target_background")
	}
	if _, ok := m["additional_context"]; !ok {
		t.Error("missing JSON key additional_context")
	}
	// Must NOT have old wrong keys
	if _, ok := m["background"]; ok {
		t.Error("unexpected JSON key background")
	}
	if _, ok := m["context"]; ok {
		t.Error("unexpected JSON key context")
	}
	if _, ok := m["metadata"]; ok {
		t.Error("unexpected JSON key metadata — not in spec")
	}
}

func TestTargetProfileResponse_SpecAlignedFields(t *testing.T) {
	j := `{
		"target_id":"t1",
		"target_version":3,
		"status":"COMPLETED",
		"target_background":{"industry":"finance"},
		"additional_context":{"base_model":"gpt-4"},
		"other_details":{"items":{"code_execution":true}},
		"ai_generated_fields":["industry","base_model"],
		"profiling_status":"COMPLETED"
	}`
	var r TargetProfileResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if r.TargetID != "t1" {
		t.Errorf("TargetID = %q, want t1", r.TargetID)
	}
	if r.TargetVersion != 3 {
		t.Errorf("TargetVersion = %d, want 3", r.TargetVersion)
	}
	if r.Status != "COMPLETED" {
		t.Errorf("Status = %q", r.Status)
	}
	if r.TargetBackground == nil || r.TargetBackground.Industry != "finance" {
		t.Error("TargetBackground.Industry should be finance")
	}
	if r.AdditionalContext == nil || r.AdditionalContext.BaseModel != "gpt-4" {
		t.Error("AdditionalContext.BaseModel should be gpt-4")
	}
	if r.OtherDetails == nil {
		t.Error("OtherDetails should not be nil")
	}
	if len(r.AIGeneratedFields) != 2 {
		t.Errorf("AIGeneratedFields = %v", r.AIGeneratedFields)
	}
	if r.ProfilingStatus != ProfilingStatusCompleted {
		t.Errorf("ProfilingStatus = %q", r.ProfilingStatus)
	}
}

func TestTargetResponse_RequiredFieldsNoOmitempty(t *testing.T) {
	// Zero-value TargetResponse should still serialize required fields
	resp := TargetResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	required := []string{"uuid", "tsg_id", "name", "status", "active", "validated", "created_at", "updated_at"}
	for _, key := range required {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from zero-value JSON", key)
		}
	}
}

func TestTargetListItem_SpecFields(t *testing.T) {
	j := `{
		"uuid":"t1","tsg_id":"tsg1","name":"test","status":"ACTIVE",
		"active":true,"validated":true,"created_at":"2025-01-01","updated_at":"2025-01-01",
		"target_type":"APPLICATION","connection_type":"CUSTOM",
		"version":2,"session_supported":false
	}`
	var item TargetListItem
	if err := json.Unmarshal([]byte(j), &item); err != nil {
		t.Fatal(err)
	}
	if item.UUID != "t1" {
		t.Errorf("UUID = %q", item.UUID)
	}
	if item.TsgID != "tsg1" {
		t.Errorf("TsgID = %q", item.TsgID)
	}
	if item.Name != "test" {
		t.Errorf("Name = %q", item.Name)
	}
	if item.Status != TargetStatusActive {
		t.Errorf("Status = %q", item.Status)
	}
}

func TestTargetList_UsesTargetListItem(t *testing.T) {
	j := `{"data":[{"uuid":"t1","tsg_id":"tsg1","name":"test","status":"ACTIVE","active":true,"validated":true,"created_at":"2025-01-01","updated_at":"2025-01-01"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r TargetList
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 {
		t.Fatalf("Data len = %d", len(r.Data))
	}
	// Verify Data is []TargetListItem (compile-time check via field access)
	item := r.Data[0]
	if item.UUID != "t1" {
		t.Errorf("UUID = %q", item.UUID)
	}
}

func TestOtherDetails_JSON(t *testing.T) {
	j := `{"items":{"code_execution":true,"internet_access":false}}`
	var d OtherDetails
	if err := json.Unmarshal([]byte(j), &d); err != nil {
		t.Fatal(err)
	}
	if d.Items == nil {
		t.Fatal("Items should not be nil")
	}
	if d.Items["code_execution"] != true {
		t.Errorf("Items = %v", d.Items)
	}
}

func TestErrorLogListResponse_DataKey(t *testing.T) {
	j := `{"data":[{"job_id":"j1","error_source":"TARGET"}],"pagination":{"total":1,"skip":0,"limit":10}}`
	var r ErrorLogListResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 1 || r.Data[0].JobID != "j1" {
		t.Errorf("Data = %+v", r.Data)
	}
}

// --- QuotaSummary nested structure ---

func TestQuotaSummary_NestedStructure(t *testing.T) {
	j := `{
		"static":{"allocated":100,"unlimited":false,"consumed":50},
		"dynamic":{"allocated":200,"unlimited":true,"consumed":30},
		"custom":{"allocated":50,"unlimited":false,"consumed":10}
	}`
	var q QuotaSummary
	if err := json.Unmarshal([]byte(j), &q); err != nil {
		t.Fatal(err)
	}
	if q.Static.Allocated != 100 {
		t.Errorf("Static.Allocated = %d", q.Static.Allocated)
	}
	if q.Dynamic.Unlimited != true {
		t.Error("Dynamic.Unlimited should be true")
	}
	if q.Custom.Consumed != 10 {
		t.Errorf("Custom.Consumed = %d", q.Custom.Consumed)
	}
}

// --- StreamDetailResponse typed ---

func TestStreamDetailResponse_TypedFields(t *testing.T) {
	j := `{
		"uuid":"s1","tsg_id":"t1","job_id":"j1","target_id":"tgt1",
		"goal_id":"g1","stream_idx":0,"stream_type":"NORMAL",
		"threat":true,"marked_safe":false,"iteration":3,
		"created_at":"2025-01-01","updated_at":"2025-06-01","version":1
	}`
	var s StreamDetailResponse
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		t.Fatal(err)
	}
	if s.UUID != "s1" {
		t.Errorf("UUID = %q", s.UUID)
	}
	if s.TsgID != "t1" {
		t.Errorf("TsgID = %q", s.TsgID)
	}
	if s.JobID != "j1" {
		t.Errorf("JobID = %q", s.JobID)
	}
	if s.StreamType != "NORMAL" {
		t.Errorf("StreamType = %q", s.StreamType)
	}
	if s.Threat == nil || !*s.Threat {
		t.Error("Threat should be true")
	}
	if s.Iteration != 3 {
		t.Errorf("Iteration = %d", s.Iteration)
	}
}

// --- TargetResponse context fields ---

func TestTargetResponse_ContextFields(t *testing.T) {
	j := `{
		"uuid":"t1","name":"test",
		"target_metadata":{"multi_turn":true,"probe_message":"hi"},
		"target_background":{"industry":"finance"},
		"additional_context":{"base_model":"gpt-4"}
	}`
	var t2 TargetResponse
	if err := json.Unmarshal([]byte(j), &t2); err != nil {
		t.Fatal(err)
	}
	if t2.TargetMeta == nil || !t2.TargetMeta.MultiTurn {
		t.Error("TargetMeta.MultiTurn should be true")
	}
	if t2.Background == nil || t2.Background.Industry != "finance" {
		t.Error("Background.Industry should be finance")
	}
	if t2.AdditionalCtx == nil || t2.AdditionalCtx.BaseModel != "gpt-4" {
		t.Error("AdditionalCtx.BaseModel should be gpt-4")
	}
}

// --- PropertyNamesListResponse typed ---

func TestPropertyNamesListResponse_DataKey(t *testing.T) {
	j := `{"data":["color","size"]}`
	var r PropertyNamesListResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data) != 2 || r.Data[0] != "color" {
		t.Errorf("Data = %v", r.Data)
	}
}

// --- PropertyValuesMultipleResponse data key ---

func TestPropertyValuesMultipleResponse_DataKey(t *testing.T) {
	j := `{"data":{"color":["red","blue"]}}`
	var r PropertyValuesMultipleResponse
	if err := json.Unmarshal([]byte(j), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Data["color"]) != 2 {
		t.Errorf("Data = %v", r.Data)
	}
}

func TestCategoryModel_RequiredFieldsSerialized(t *testing.T) {
	resp := CategoryModel{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "sub_categories"} {
		if _, ok := m[key]; !ok {
			t.Errorf("required field %q missing from JSON", key)
		}
	}
}
