package runtime_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	sdk "github.com/cdot65/prisma-airs-go/aisec/runtime"
)

const consumerSuccessPrefix = "consumer policy written: "

func consumerMarshal(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func consumerTree(t *testing.T, body []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func consumerEqual(t *testing.T, want, got []byte) {
	t.Helper()
	if !reflect.DeepEqual(consumerTree(t, want), consumerTree(t, got)) {
		t.Fatalf("policy changed beyond managed edits\nwant: %s\ngot: %s", want, got)
	}
}

func consumerPolicy(t *testing.T, body []byte) sdk.ProfilePolicy {
	t.Helper()
	var policy sdk.ProfilePolicy
	if err := json.Unmarshal(body, &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func consumerExtension(t *testing.T, target *sdk.ProfileJSON, name, raw string) {
	t.Helper()
	if err := target.SetExtension(name, json.RawMessage(raw)); err != nil {
		t.Fatal(err)
	}
}

// A new test process receives paths and an operation, never an SDK object or
// presence cache. Its only policy input is the JSON bytes on disk.
func consumerProcess(t *testing.T, input, output, operation string) []byte {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestTerraformProfileConsumerProcess$", "-test.v", "--", input, output, operation)
	log, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("consumer process %s: %v\n%s", operation, err, log)
	}
	if !bytes.Contains(log, []byte(consumerSuccessPrefix+operation)) {
		t.Fatalf("consumer process did not confirm %s ran\n%s", operation, log)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type consumerFields interface {
	FieldNames() []string
	FieldPresence(string) sdk.JSONPresence
}

// Reconstruct metadata exclusively through the public API, with no private state
// copied from source. FieldNames includes omitted fields and excludes extensions.
func consumerState(t *testing.T, source consumerFields, extensions map[string]json.RawMessage) sdk.ProfileJSON {
	t.Helper()
	var target sdk.ProfileJSON
	for _, name := range source.FieldNames() {
		target.SetFieldPresence(name, source.FieldPresence(name))
	}
	for name, raw := range extensions {
		if err := target.SetExtension(name, raw); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

func consumerConfidence(t *testing.T, source *sdk.SeverityByConfidence) *sdk.SeverityByConfidence {
	t.Helper()
	if source == nil {
		return nil
	}
	target := *source
	target.ProfileJSON = consumerState(t, *source, source.Extensions)
	return &target
}

func consumerDetectors(t *testing.T, source []sdk.ModelProtectionConfig) []sdk.ModelProtectionConfig {
	t.Helper()
	if source == nil {
		return nil
	}
	target := make([]sdk.ModelProtectionConfig, len(source))
	for i, detector := range source {
		target[i] = detector
		target[i].ProfileJSON = consumerState(t, detector, detector.Extensions)
		target[i].SeverityByConfidence = consumerConfidence(t, detector.SeverityByConfidence)
		if detector.ToxicCategoryList != nil {
			target[i].ToxicCategoryList = make([]sdk.ToxicCategoryConfig, len(detector.ToxicCategoryList))
			for j, category := range detector.ToxicCategoryList {
				target[i].ToxicCategoryList[j] = category
				target[i].ToxicCategoryList[j].ProfileJSON = consumerState(t, category, category.Extensions)
				target[i].ToxicCategoryList[j].SeverityByConfidence = consumerConfidence(t, category.SeverityByConfidence)
			}
		}
		if detector.TopicList != nil {
			target[i].TopicList = make([]sdk.TopicArrayConfig, len(detector.TopicList))
			for j, bucket := range detector.TopicList {
				target[i].TopicList[j] = bucket
				target[i].TopicList[j].ProfileJSON = consumerState(t, bucket, bucket.Extensions)
				if bucket.Topic != nil {
					target[i].TopicList[j].Topic = make([]sdk.TopicRef, len(bucket.Topic))
					for k, topic := range bucket.Topic {
						target[i].TopicList[j].Topic[k] = topic
						target[i].TopicList[j].Topic[k].ProfileJSON = consumerState(t, topic, topic.Extensions)
					}
				}
			}
		}
	}
	return target
}

func consumerAgents(t *testing.T, source []sdk.AgentProtectionConfig) []sdk.AgentProtectionConfig {
	t.Helper()
	if source == nil {
		return nil
	}
	target := make([]sdk.AgentProtectionConfig, len(source))
	for i, agent := range source {
		target[i] = agent
		target[i].ProfileJSON = consumerState(t, agent, agent.Extensions)
	}
	return target
}

func consumerData(t *testing.T, source *sdk.DataProtectionConfig) *sdk.DataProtectionConfig {
	t.Helper()
	if source == nil {
		return nil
	}
	target := *source
	target.ProfileJSON = consumerState(t, *source, source.Extensions)
	if source.DataLeakDetection != nil {
		dlp := *source.DataLeakDetection
		dlp.ProfileJSON = consumerState(t, *source.DataLeakDetection, dlp.Extensions)
		if dlp.Member != nil {
			dlp.Member = make([]sdk.DataLeakMember, len(source.DataLeakDetection.Member))
			for i, member := range source.DataLeakDetection.Member {
				dlp.Member[i] = member
				dlp.Member[i].ProfileJSON = consumerState(t, member, member.Extensions)
			}
		}
		target.DataLeakDetection = &dlp
	}
	if source.DatabaseSecurity != nil {
		target.DatabaseSecurity = make([]sdk.DatabaseSecurityConfig, len(source.DatabaseSecurity))
		for i, database := range source.DatabaseSecurity {
			target.DatabaseSecurity[i] = database
			target.DatabaseSecurity[i].ProfileJSON = consumerState(t, database, database.Extensions)
		}
	}
	if source.SourceCodeDetection != nil {
		code := *source.SourceCodeDetection
		code.ProfileJSON = consumerState(t, code, code.Extensions)
		target.SourceCodeDetection = &code
	}
	return &target
}

func consumerURLs(t *testing.T, source *sdk.URLCategoryMember) *sdk.URLCategoryMember {
	t.Helper()
	if source == nil {
		return nil
	}
	target := *source
	target.ProfileJSON = consumerState(t, *source, source.Extensions)
	return &target
}

func consumerApp(t *testing.T, source *sdk.AppProtectionConfig) *sdk.AppProtectionConfig {
	t.Helper()
	if source == nil {
		return nil
	}
	target := *source
	target.ProfileJSON = consumerState(t, *source, source.Extensions)
	target.AlertURLCategory = consumerURLs(t, source.AlertURLCategory)
	target.AllowURLCategory = consumerURLs(t, source.AllowURLCategory)
	target.BlockURLCategory = consumerURLs(t, source.BlockURLCategory)
	target.DefaultURLCategory = consumerURLs(t, source.DefaultURLCategory)
	if source.MaliciousCodeProtection != nil {
		code := *source.MaliciousCodeProtection
		code.ProfileJSON = consumerState(t, code, code.Extensions)
		target.MaliciousCodeProtection = &code
	}
	return &target
}

func consumerProtection(t *testing.T, source *sdk.ProtectionConfiguration) *sdk.ProtectionConfiguration {
	t.Helper()
	if source == nil {
		return nil
	}
	target := *source
	target.ProfileJSON = consumerState(t, *source, source.Extensions)
	target.DataProtection = consumerData(t, source.DataProtection)
	target.AppProtection = consumerApp(t, source.AppProtection)
	target.ModelProtection = consumerDetectors(t, source.ModelProtection)
	target.AgentProtection = consumerAgents(t, source.AgentProtection)
	return &target
}

// Rebuild every modeled policy branch from exported values and fresh public
// presence/extension state. Matching and field ownership belong to the consumer.
func consumerRebuild(t *testing.T, source sdk.ProfilePolicy) sdk.ProfilePolicy {
	t.Helper()
	target := source
	target.ProfileJSON = consumerState(t, source, source.Extensions)
	if source.DlpDataProfiles != nil {
		target.DlpDataProfiles = make([]sdk.DLPDataProfileConfig, len(source.DlpDataProfiles))
		for i, dlp := range source.DlpDataProfiles {
			target.DlpDataProfiles[i] = dlp
			target.DlpDataProfiles[i].ProfileJSON = consumerState(t, dlp, dlp.Extensions)
		}
	}
	if source.AiSecurityProfiles != nil {
		target.AiSecurityProfiles = make([]sdk.AiSecurityProfileConfig, len(source.AiSecurityProfiles))
		for i, ai := range source.AiSecurityProfiles {
			target.AiSecurityProfiles[i] = ai
			target.AiSecurityProfiles[i].ProfileJSON = consumerState(t, ai, ai.Extensions)
			if ai.ModelConfiguration != nil {
				model := *ai.ModelConfiguration
				model.ProfileJSON = consumerState(t, model, model.Extensions)
				model.DataProtection = consumerData(t, model.DataProtection)
				model.AppProtection = consumerApp(t, model.AppProtection)
				model.ModelProtection = consumerDetectors(t, model.ModelProtection)
				model.AgentProtection = consumerAgents(t, model.AgentProtection)
				if model.Latency != nil {
					latency := *model.Latency
					latency.ProfileJSON = consumerState(t, latency, latency.Extensions)
					model.Latency = &latency
				}
				target.AiSecurityProfiles[i].ModelConfiguration = &model
			}
			if ai.ContentTypeConfigurations != nil {
				dirs := *ai.ContentTypeConfigurations
				dirs.ProfileJSON = consumerState(t, dirs, dirs.Extensions)
				dirs.Prompt = consumerProtection(t, dirs.Prompt)
				dirs.Response = consumerProtection(t, dirs.Response)
				dirs.ToolCall = consumerProtection(t, dirs.ToolCall)
				dirs.ToolResponse = consumerProtection(t, dirs.ToolResponse)
				target.AiSecurityProfiles[i].ContentTypeConfigurations = &dirs
			}
		}
	}
	return target
}

func TestTerraformProfileConsumerPersistence(t *testing.T) {
	fixture, err := os.ReadFile("testdata/directional-security-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile sdk.SecurityProfile
	if err := json.Unmarshal(fixture, &profile); err != nil {
		t.Fatal(err)
	}
	policy := profile.Policy
	ai := &policy.AiSecurityProfiles[0]
	dirs := ai.ContentTypeConfigurations
	consumerExtension(t, &policy.ProfileJSON, "future-policy", `{"sequence":900719925474099312345}`)
	consumerExtension(t, &ai.ProfileJSON, "future-ai", `{"enabled":false}`)
	consumerExtension(t, &dirs.ProfileJSON, "future-direction", `{"raw-number":900719925474099312345,"config":{}}`)
	consumerExtension(t, &dirs.Response.ProfileJSON, "future-response", `[]`)
	detector := &dirs.Response.ModelProtection[0]
	consumerExtension(t, &detector.ProfileJSON, "future-detector", `{"number":900719925474099312345}`)
	consumerExtension(t, &detector.SeverityByConfidence.ProfileJSON, "future-confidence", `{"number":900719925474099312345}`)
	// Typed fields must dominate both present and omitted colliding extensions.
	consumerExtension(t, &detector.SeverityByConfidence.ProfileJSON, "high", `123`)
	consumerExtension(t, &dirs.ToolResponse.DataProtection.DataLeakDetection.ProfileJSON, "mask-data-inline", `true`)
	consumerExtension(t, &dirs.Prompt.DataProtection.DataLeakDetection.Member[0].ProfileJSON, "future-member", `{"number":900719925474099312345}`)
	consumerExtension(t, &dirs.Prompt.AppProtection.AlertURLCategory.ProfileJSON, "future-url", `{"enabled":false}`)
	consumerExtension(t, &dirs.Response.DataProtection.DatabaseSecurity[0].ProfileJSON, "future-database", `{"number":900719925474099312345}`)
	consumerExtension(t, &ai.ModelConfiguration.Latency.ProfileJSON, "future-latency", `{"empty":[]}`)
	// Exercise rebuilt branches absent from the sanitized fixture as well.
	category := sdk.ToxicCategoryConfig{Category: "hate", Action: "block", SeverityByConfidence: &sdk.SeverityByConfidence{High: "high", Moderate: ""}}
	category.SeverityByConfidence.SetFieldPresence("moderate", sdk.JSONPresent)
	consumerExtension(t, &category.ProfileJSON, "future-category", `{"number":900719925474099312345}`)
	topic := sdk.TopicRef{TopicName: "", TopicID: "consumer-topic", Revision: 2, Severity: ""}
	topic.SetFieldPresence("severity", sdk.JSONPresent)
	consumerExtension(t, &topic.ProfileJSON, "future-topic", `{"number":900719925474099312345}`)
	bucket := sdk.TopicArrayConfig{Action: sdk.ProfileActionBlock, Topic: []sdk.TopicRef{topic}}
	consumerExtension(t, &bucket.ProfileJSON, "future-bucket", `null`)
	dirs.Prompt.ModelProtection[1].ToxicCategoryList = []sdk.ToxicCategoryConfig{category}
	dirs.Prompt.ModelProtection[1].TopicList = []sdk.TopicArrayConfig{bucket, {Action: sdk.ProfileActionAllow, Topic: nil}}
	dirs.Prompt.ModelProtection[1].Options = []json.RawMessage{json.RawMessage(`900719925474099312345`)}
	dirs.ToolCall.DataProtection.SourceCodeDetection = &sdk.SourceCodeDetectionConfig{Action: sdk.ProfileActionBlock, Severity: ""}
	dirs.ToolCall.DataProtection.SourceCodeDetection.SetFieldPresence("severity", sdk.JSONPresent)
	consumerExtension(t, &dirs.ToolCall.DataProtection.SourceCodeDetection.ProfileJSON, "future-code", `{"empty":{}}`)
	agent := sdk.AgentProtectionConfig{Name: "consumer-agent", Action: sdk.ProfileActionAlert}
	consumerExtension(t, &agent.ProfileJSON, "future-agent", `{"number":900719925474099312345}`)
	dirs.ToolCall.AgentProtection = []sdk.AgentProtectionConfig{agent}
	dlp := sdk.DLPDataProfileConfig{Name: "consumer-dlp", Rule1: map[string]any{"number": json.Number("900719925474099312345")}}
	consumerExtension(t, &dlp.ProfileJSON, "future-dlp", `{"empty":[]}`)
	policy.DlpDataProfiles = []sdk.DLPDataProfileConfig{dlp}
	policy.AiSecurityProfiles = append(policy.AiSecurityProfiles, sdk.AiSecurityProfileConfig{
		ContentTypeConfigurations: &sdk.ContentTypeConfigurations{Response: &sdk.ProtectionConfiguration{}},
	})
	dirs.Response.ModelProtection = append(dirs.Response.ModelProtection, sdk.ModelProtectionConfig{
		Name: "consumer-unmanaged-detector", Action: sdk.ProfileActionAllow,
		ProfileJSON: sdk.ProfileJSON{Extensions: map[string]json.RawMessage{"future-unmanaged": json.RawMessage(`{"number":900719925474099312345}`)}},
	})
	baseline := consumerMarshal(t, policy)
	directory := t.TempDir()
	initial := filepath.Join(directory, "initial.json")
	if err := os.WriteFile(initial, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	rebuiltPath := filepath.Join(directory, "rebuilt.json")
	rebuilt := consumerProcess(t, initial, rebuiltPath, "rebuild")
	consumerEqual(t, baseline, rebuilt)
	reloaded := consumerPolicy(t, rebuilt)
	reloadedDirs := reloaded.AiSecurityProfiles[0].ContentTypeConfigurations
	if reloadedDirs.Prompt.DataProtection.FieldPresence("database-security") != sdk.JSONNull ||
		reloadedDirs.ToolResponse.DataProtection.DataLeakDetection.FieldPresence("mask-data-inline") != sdk.JSONOmitted ||
		reloadedDirs.Prompt.DataProtection.DataLeakDetection.Member[0].FieldPresence("id") != sdk.JSONPresent ||
		reloadedDirs.Prompt.AppProtection.AlertURLCategory.FieldPresence("member") != sdk.JSONOmitted ||
		reloaded.FieldPresence("dlp-data-profiles") != sdk.JSONPresent {
		t.Fatal("nested null/omitted/empty presence was not restored")
	}
	if reloadedDirs.Response.ModelProtection[0].SeverityByConfidence.High != "medium" ||
		!bytes.Contains(reloadedDirs.Extensions["future-direction"], []byte("900719925474099312345")) {
		t.Fatal("typed collision or raw precision lost")
	}
	expected := consumerTree(t, baseline).(map[string]any)
	expectedDirs := expected["ai-security-profiles"].([]any)[0].(map[string]any)["content-type-configurations"].(map[string]any)
	expectedResponse := expectedDirs["response"].(map[string]any)
	expectedDetector := expectedResponse["model-protection"].([]any)[0].(map[string]any)
	expectedDetector["action"] = string(sdk.ToxicContentHighBlockModerateBlock)
	expectedDetector["severity-by-confidence"].(map[string]any)["moderate"] = "medium"
	editedPath := filepath.Join(directory, "edited.json")
	edited := consumerProcess(t, rebuiltPath, editedPath, "toxicity")
	consumerEqual(t, consumerMarshal(t, expected), edited)
	expectedResponse["model-protection"] = expectedResponse["model-protection"].([]any)[1:]
	removedPath := filepath.Join(directory, "removed.json")
	removed := consumerProcess(t, editedPath, removedPath, "remove")
	consumerEqual(t, consumerMarshal(t, expected), removed)
	final := consumerProcess(t, removedPath, filepath.Join(directory, "reloaded.json"), "reload")
	consumerEqual(t, removed, final)
	finalPolicy := consumerPolicy(t, final)
	remaining := finalPolicy.AiSecurityProfiles[0].ContentTypeConfigurations.Response.ModelProtection
	if len(remaining) != 1 || remaining[0].Name != "consumer-unmanaged-detector" {
		t.Fatal("managed detector resurrected or unmanaged detector lost")
	}
}

func TestTerraformProfileConsumerProcess(t *testing.T) {
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		t.Skip("invoked only as a separate consumer process")
	}
	if len(args) != 3 {
		t.Fatal("expected input/output paths and operation")
	}
	body, err := os.ReadFile(args[0])
	if err != nil {
		t.Fatal(err)
	}
	policy := consumerPolicy(t, body)
	response := policy.AiSecurityProfiles[0].ContentTypeConfigurations.Response
	switch args[2] {
	case "rebuild":
		policy = consumerRebuild(t, policy)
	case "toxicity":
		matched := false
		for i := range response.ModelProtection {
			if response.ModelProtection[i].Name == "toxic-content" {
				response.ModelProtection[i].Action = sdk.ProfileAction(sdk.ToxicContentHighBlockModerateBlock)
				response.ModelProtection[i].SeverityByConfidence.Moderate = "medium"
				matched = true
			}
		}
		if !matched {
			t.Fatal("missing managed toxicity detector")
		}
	case "remove":
		kept := make([]sdk.ModelProtectionConfig, 0, len(response.ModelProtection))
		for _, detector := range response.ModelProtection {
			if detector.Name != "toxic-content" {
				kept = append(kept, detector)
			}
		}
		response.ModelProtection = kept
		response.SetFieldPresence("model-protection", sdk.JSONPresent)
	case "reload":
		// Removing an override on a freshly decoded field cannot revive discarded
		// values. No known raw-value cache exists in the persisted policy.
		response.ResetFieldPresence("model-protection")
	default:
		t.Fatalf("unknown operation %s", args[2])
	}
	if err := os.WriteFile(args[1], consumerMarshal(t, policy), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s%s", consumerSuccessPrefix, args[2])
}

func TestTerraformProfileConsumerFieldNames(t *testing.T) {
	member := sdk.DataLeakMember{Text: "sensitive"}
	consumerExtension(t, &member.ProfileJSON, "future", `null`)
	if !reflect.DeepEqual(member.FieldNames(), []string{"id", "text", "version"}) {
		t.Fatalf("expected sorted known wire names, got %v", member.FieldNames())
	}
	names := member.FieldNames()
	names[0] = "changed"
	if member.FieldNames()[0] != "id" {
		t.Fatal("consumer modified shared field metadata")
	}
	if !member.HasField("future") || member.FieldPresence("future") != sdk.JSONNull {
		t.Fatal("extension presence must remain available separately")
	}
}

func TestTerraformProfileConsumerRebuiltRemoval(t *testing.T) {
	source := consumerPolicy(t, []byte(`{"ai-security-profiles":[{"content-type-configurations":{"response":{"model-protection":[{"name":"toxic-content","severity-by-confidence":{}}]}}}]}`))
	target := consumerRebuild(t, source)
	detector := &target.AiSecurityProfiles[0].ContentTypeConfigurations.Response.ModelProtection[0]
	// Transferring an omitted field makes omission explicit, so updating its
	// typed value also requires updating/removing that override.
	detector.Action = sdk.ProfileActionBlock
	consumerEqual(t, consumerMarshal(t, source), consumerMarshal(t, target))
	detector.SetFieldPresence("action", sdk.JSONPresent)
	wantAction := []byte(`{"ai-security-profiles":[{"content-type-configurations":{"response":{"model-protection":[{"name":"toxic-content","action":"block","severity-by-confidence":{}}]}}}]}`)
	consumerEqual(t, wantAction, consumerMarshal(t, target))
	detector.SetFieldPresence("action", sdk.JSONOmitted)
	detector.ResetFieldPresence("action")
	consumerEqual(t, wantAction, consumerMarshal(t, target))
	detector.SeverityByConfidence = nil
	if _, err := json.Marshal(target); err == nil {
		t.Fatal("transferred explicit presence must reject a nil non-nullable object")
	}
	detector.SetFieldPresence("severity-by-confidence", sdk.JSONOmitted)
	expected := []byte(`{"ai-security-profiles":[{"content-type-configurations":{"response":{"model-protection":[{"name":"toxic-content","action":"block"}]}}}]}`)
	persisted := consumerMarshal(t, target)
	consumerEqual(t, expected, persisted)
	reload := consumerPolicy(t, persisted)
	reload.AiSecurityProfiles[0].ContentTypeConfigurations.Response.ModelProtection[0].ResetFieldPresence("severity-by-confidence")
	consumerEqual(t, expected, consumerMarshal(t, reload))
}

func TestTerraformProfileConsumerDecodedEdits(t *testing.T) {
	body := []byte(`{"content-type-mode":"per_content_type","model-configuration":{"mask-data-in-storage":true,"latency":{},"enable-full-conversation-inspection":true,"model-protection":[{"name":"old","action":"block","severity":"high"}]}}`)
	var ai sdk.AiSecurityProfileConfig
	if err := json.Unmarshal(body, &ai); err != nil {
		t.Fatal(err)
	}
	model := ai.ModelConfiguration
	model.MaskDataInStorage = false
	*model.EnableFullConversationInspection = false
	ai.ContentTypeMode = ""
	model.Latency = nil
	model.ModelProtection = []sdk.ModelProtectionConfig{{Name: "new", Action: sdk.ProfileActionAllow}}
	expected := []byte(`{"content-type-mode":"","model-configuration":{"mask-data-in-storage":false,"enable-full-conversation-inspection":false,"model-protection":[{"name":"new","action":"allow"}]}}`)
	consumerEqual(t, expected, consumerMarshal(t, ai))
	// Removing the optional list omits it; an empty slice explicitly clears it.
	model.ModelProtection = nil
	expected = []byte(`{"content-type-mode":"","model-configuration":{"mask-data-in-storage":false,"enable-full-conversation-inspection":false}}`)
	consumerEqual(t, expected, consumerMarshal(t, ai))
	model.SetFieldPresence("model-protection", sdk.JSONOmitted)
	persisted := consumerMarshal(t, ai)
	consumerEqual(t, expected, persisted)
	var reload sdk.AiSecurityProfileConfig
	if err := json.Unmarshal(persisted, &reload); err != nil {
		t.Fatal(err)
	}
	reload.ResetFieldPresence("content-type-mode") // Explicit empty remains in its typed value; reset infers omission.
	reload.SetFieldPresence("content-type-mode", sdk.JSONPresent)
	reload.ModelConfiguration.ResetFieldPresence("latency")
	reload.ModelConfiguration.ResetFieldPresence("model-protection")
	consumerEqual(t, expected, consumerMarshal(t, reload))
	reload.ModelConfiguration.ModelProtection = []sdk.ModelProtectionConfig{}
	expected = []byte(`{"content-type-mode":"","model-configuration":{"mask-data-in-storage":false,"enable-full-conversation-inspection":false,"model-protection":[]}}`)
	consumerEqual(t, expected, consumerMarshal(t, reload))
	// Clearing the value as well as omitting it makes removal survive reset and reload.
	reload.ContentTypeMode = ""
	reload.SetFieldPresence("content-type-mode", sdk.JSONOmitted)
	persisted = consumerMarshal(t, reload)
	if err := json.Unmarshal(persisted, &reload); err != nil {
		t.Fatal(err)
	}
	reload.ResetFieldPresence("content-type-mode")
	expected = []byte(`{"model-configuration":{"mask-data-in-storage":false,"enable-full-conversation-inspection":false,"model-protection":[]}}`)
	consumerEqual(t, expected, consumerMarshal(t, reload))
}

func TestTerraformProfileConsumerExplicitOverrides(t *testing.T) {
	model := sdk.ModelConfiguration{Latency: &sdk.LatencyConfig{}, ModelProtection: []sdk.ModelProtectionConfig{}}
	model.SetFieldPresence("latency", sdk.JSONPresent)
	model.Latency = nil
	if _, err := json.Marshal(model); err == nil {
		t.Fatal("explicit present nil object must fail rather than silently omit")
	}
	model.ResetFieldPresence("latency")
	consumerEqual(t, []byte(`{"mask-data-in-storage":false,"model-protection":[]}`), consumerMarshal(t, model))
	ai := sdk.AiSecurityProfileConfig{ContentTypeMode: "per_content_type"}
	ai.SetFieldPresence("content-type-mode", sdk.JSONOmitted)
	consumerEqual(t, []byte(`{}`), consumerMarshal(t, ai))
	if ai.ContentTypeMode != "per_content_type" {
		t.Fatal("presence setter must not mutate the exported typed value")
	}
	ai.ResetFieldPresence("content-type-mode")
	consumerEqual(t, []byte(`{"content-type-mode":"per_content_type"}`), consumerMarshal(t, ai))
}

func TestTerraformProfileConsumerConstructedRequests(t *testing.T) {
	member := sdk.DataLeakMember{Text: "sensitive", ID: ""}
	member.SetFieldPresence("id", sdk.JSONPresent)
	dlp := &sdk.DataLeakDetectionConfig{Action: sdk.ProfileActionBlock, Member: []sdk.DataLeakMember{member}}
	dlp.SetMaskDataInline(false)
	flag := false
	ai := sdk.AiSecurityProfileConfig{
		ContentTypeMode: "", ModelConfiguration: &sdk.ModelConfiguration{MaskDataInStorage: false, EnableFullConversationInspection: &flag},
		ContentTypeConfigurations: &sdk.ContentTypeConfigurations{
			Response: &sdk.ProtectionConfiguration{DataProtection: &sdk.DataProtectionConfig{DataLeakDetection: dlp}, AppProtection: &sdk.AppProtectionConfig{}, ModelProtection: []sdk.ModelProtectionConfig{}, AgentProtection: []sdk.AgentProtectionConfig{}},
		},
	}
	ai.SetFieldPresence("content-type-mode", sdk.JSONPresent)
	policy := &sdk.ProfilePolicy{DlpDataProfiles: []sdk.DLPDataProfileConfig{}, AiSecurityProfiles: []sdk.AiSecurityProfileConfig{ai}}
	create := sdk.CreateProfileRequest{ProfileName: "consumer", Active: &flag, Policy: policy}
	update := sdk.UpdateProfileRequest{ProfileName: "consumer", Active: &flag, Policy: policy}
	expected := []byte(`{"profile_name":"consumer","active":false,"policy":{"dlp-data-profiles":[],"ai-security-profiles":[{"content-type-mode":"","model-configuration":{"mask-data-in-storage":false,"enable-full-conversation-inspection":false},"content-type-configurations":{"response":{"data-protection":{"data-leak-detection":{"action":"block","mask-data-inline":false,"member":[{"text":"sensitive","id":""}]}},"app-protection":{},"model-protection":[],"agent-protection":[]}}}]}}`)
	for _, request := range []any{create, update} {
		consumerEqual(t, expected, consumerMarshal(t, request))
	}
	// Null is permitted for database-security, but never an optional object/bool.
	data := &ai.ContentTypeConfigurations.Response.DataProtection.ProfileJSON
	data.SetFieldPresence("database-security", sdk.JSONNull)
	if ai.ContentTypeConfigurations.Response.DataProtection.FieldPresence("database-security") != sdk.JSONNull {
		t.Fatal("nullable field lost null")
	}
	for _, field := range []string{"data-leak-detection", "source-code-detection"} {
		data.SetFieldPresence(field, sdk.JSONNull)
		if _, err := json.Marshal(ai); err == nil {
			t.Fatalf("accepted null for %s", field)
		}
		data.ResetFieldPresence(field)
	}
	ai.ModelConfiguration.SetFieldPresence("mask-data-in-storage", sdk.JSONNull)
	if _, err := json.Marshal(ai); err == nil {
		t.Fatal("accepted null for a boolean")
	}
}
