package scan

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdot65/prisma-airs-go/aisec"
)

func TestNewContent_Valid(t *testing.T) {
	c, err := NewContent(ContentOpts{Prompt: "hello", Response: "world"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Prompt() != "hello" {
		t.Errorf("Prompt() = %q", c.Prompt())
	}
	if c.Response() != "world" {
		t.Errorf("Response() = %q", c.Response())
	}
}

func TestNewContent_RequiresAtLeastOneField(t *testing.T) {
	_, err := NewContent(ContentOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	var sdkErr *aisec.AISecSDKError
	if !errors.As(err, &sdkErr) {
		t.Fatal("expected AISecSDKError")
	}
	if sdkErr.ErrorType != aisec.UserRequestPayloadError {
		t.Errorf("ErrorType = %v", sdkErr.ErrorType)
	}
}

func TestNewContent_PromptExceedsMaxLength(t *testing.T) {
	bigStr := strings.Repeat("x", aisec.MaxContentPromptLength+1)
	_, err := NewContent(ContentOpts{Prompt: bigStr})
	if err == nil {
		t.Fatal("expected error for oversized prompt")
	}
}

func TestNewContent_ResponseExceedsMaxLength(t *testing.T) {
	bigStr := strings.Repeat("x", aisec.MaxContentResponseLength+1)
	_, err := NewContent(ContentOpts{Response: bigStr})
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
}

func TestNewContent_ContextExceedsMaxLength(t *testing.T) {
	bigStr := strings.Repeat("x", aisec.MaxContentContextLength+1)
	_, err := NewContent(ContentOpts{Prompt: "p", Context: bigStr})
	if err == nil {
		t.Fatal("expected error for oversized context")
	}
}

func TestContent_ByteLength(t *testing.T) {
	c, _ := NewContent(ContentOpts{Prompt: "hello", Response: "world"})
	if c.ByteLength() != 10 {
		t.Errorf("ByteLength() = %d, want 10", c.ByteLength())
	}
}

func TestContent_ToJSON(t *testing.T) {
	c, _ := NewContent(ContentOpts{Prompt: "p", Response: "r", Context: "c"})
	j := c.ToJSON()
	if j.Prompt != "p" || j.Response != "r" || j.Context != "c" {
		t.Errorf("ToJSON = %+v", j)
	}
}

func TestContent_WithToolEvent(t *testing.T) {
	te := &ToolEvent{
		Input:  "test input",
		Output: "test output",
	}
	c, err := NewContent(ContentOpts{ToolEvent: te})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ToolEvent() != te {
		t.Error("ToolEvent not set")
	}
	j := c.ToJSON()
	if j.ToolEvent == nil {
		t.Error("ToolEvent not in JSON")
	}
}

func TestContentFromJSON(t *testing.T) {
	ci := ContentInner{Prompt: "hello", Response: "world"}
	c, err := ContentFromJSON(ci)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Prompt() != "hello" || c.Response() != "world" {
		t.Error("ContentFromJSON mismatch")
	}
}
