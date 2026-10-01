package schema_test

import (
	"encoding/json"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"testing"
)

func TestChannelStatusUsesReferencedStringEnum(t *testing.T) {
	var c schema.Channel
	if err := json.Unmarshal([]byte(`{"uuid":"channel","status":"OFFLINE"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Status == nil || *c.Status != schema.ChannelStatusOffline {
		t.Fatalf("status=%v", c.Status)
	}
}
func TestJobProgressPreservesDiscriminatedVariants(t *testing.T) {
	for _, body := range []string{`{"kind":"standard","rows":[]}`, `{"kind":"agentic","stages":[]}`} {
		var p schema.JobResponseProgress
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			t.Fatal(err)
		}
		if body == `{"kind":"standard","rows":[]}` {
			got, err := p.AsStandardProgress()
			if err != nil || got.Rows == nil || len(*got.Rows) != 0 {
				t.Fatalf("progress=%v error=%v", got, err)
			}
			if _, err := p.AsAgenticProgress(); err == nil {
				t.Fatal("wrong tagged alternative accepted")
			}
		} else {
			got, err := p.AsAgenticProgress()
			if err != nil || got.Stages == nil || len(*got.Stages) != 0 {
				t.Fatalf("progress=%v error=%v", got, err)
			}
			if _, err := p.AsStandardProgress(); err == nil {
				t.Fatal("wrong tagged alternative accepted")
			}
		}
	}
	var p schema.JobResponseProgress
	if err := json.Unmarshal([]byte(`{"kind":"invalid"}`), &p); err == nil {
		t.Fatal("unknown progress tag accepted")
	}
}
func TestAdapterSecretNullIsExplicit(t *testing.T) {
	var value schema.AdapterVarResponse
	if err := json.Unmarshal([]byte(`{"key":"api_key","type":"SECRET","value":null,"is_redacted":true}`), &value); err != nil {
		t.Fatal(err)
	}
	if !value.Value.IsNull() || value.IsRedacted == nil || !*value.IsRedacted {
		t.Fatal("redaction or null lost")
	}
	req := schema.AdapterVarBase{Key: "api_key", Type: "SECRET", Value: aisec.Null[string]()}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"key":"api_key","type":"SECRET","value":null}` {
		t.Fatalf("request=%s", b)
	}
}
