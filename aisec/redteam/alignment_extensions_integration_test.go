//go:build integration

package redteam

import (
	"context"
	"fmt"
	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/redteam/schema"
	"testing"
	"time"
)

func TestIntegration_Adapters_DraftCRUD(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	config, err := c.Adapters.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	inactive := false
	name := fmt.Sprintf("sdk-draft-%d", time.Now().UnixNano())
	created, err := c.Adapters.Create(ctx, schema.CustomTargetAdapterCreateRequest{Name: name, ScriptB64: config.DefaultScriptB64, Prompt: config.DefaultTestPrompt, Description: aisec.Value("SDK contract test")}, AdapterWriteOpts{Validate: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := c.Adapters.Delete(clean, created.UUID); err != nil {
			t.Errorf("adapter cleanup: %v", err)
		}
	})
	if created.UUID == "" || created.Status != "DRAFT" {
		t.Fatal("draft identity or status missing")
	}
	got, err := c.Adapters.Get(ctx, created.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != name {
		t.Fatal("read name mismatch")
	}
	list, err := c.Adapters.List(ctx, AdapterListOpts{ListOpts: ListOpts{Limit: 10}, Search: name, IncludeTargetCount: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	if list.Data != nil {
		for _, a := range *list.Data {
			if a.UUID == created.UUID {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("draft missing from listing")
	}
	updated, err := c.Adapters.Update(ctx, created.UUID, schema.CustomTargetAdapterUpdateRequest{Name: name, ScriptB64: config.DefaultScriptB64, Prompt: config.DefaultTestPrompt, Description: aisec.Value("")}, AdapterWriteOpts{Validate: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	// Live service canonicalizes an empty description to null.
	assertClearedAdapterDescription(t, updated.Description)
	read, err := c.Adapters.Get(ctx, created.UUID)
	if err != nil {
		t.Fatal(err)
	}
	assertClearedAdapterDescription(t, read.Description)
}

func TestIntegration_NetworkBroker_Read(t *testing.T) {
	c := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stats, err := c.NetworkBroker.GetStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.TotalChannels != nil {
		t.Logf("channel_count=%d", *stats.TotalChannels)
	}
	inactive := false
	list, err := c.NetworkBroker.List(ctx, ChannelListOpts{ListOpts: ListOpts{Limit: 2}, IncludeAllIfEmpty: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	if list.Data != nil && len(*list.Data) > 0 && (*list.Data)[0].UUID != nil {
		if _, err := c.NetworkBroker.Get(ctx, *(*list.Data)[0].UUID); err != nil {
			t.Fatal(err)
		}
	}
}

func assertClearedAdapterDescription(t *testing.T, description aisec.Optional[string]) {
	t.Helper()
	if description.IsNull() {
		return
	}
	value, ok := description.Get()
	if !ok || value != "" {
		t.Fatalf("description was not cleared: set=%t null=%t value=%q", description.IsSet(), description.IsNull(), value)
	}
}
