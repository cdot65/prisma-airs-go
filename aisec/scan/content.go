package scan

import (
	"github.com/cdot65/prisma-airs-go/aisec"
)

// ContentOpts are options for creating a Content instance.
type ContentOpts struct {
	Prompt       string
	Response     string
	Context      string
	CodePrompt   string
	CodeResponse string
	ToolEvent    *ToolEvent
}

// Content represents content to be scanned by AIRS.
// Validates byte-length limits on construction.
type Content struct {
	prompt       string
	response     string
	context      string
	codePrompt   string
	codeResponse string
	toolEvent    *ToolEvent
}

// NewContent creates a new Content with byte-length validation.
func NewContent(opts ContentOpts) (*Content, error) {
	if opts.Prompt == "" && opts.Response == "" && opts.CodePrompt == "" &&
		opts.CodeResponse == "" && opts.ToolEvent == nil {
		return nil, aisec.NewAISecSDKError(
			"at least one of Prompt, Response, CodePrompt, CodeResponse, or ToolEvent must be provided",
			aisec.UserRequestPayloadError,
		)
	}

	c := &Content{}

	if opts.Prompt != "" {
		if len(opts.Prompt) > aisec.MaxContentPromptLength {
			return nil, aisec.NewAISecSDKError("prompt exceeds max length", aisec.UserRequestPayloadError)
		}
		c.prompt = opts.Prompt
	}
	if opts.Response != "" {
		if len(opts.Response) > aisec.MaxContentResponseLength {
			return nil, aisec.NewAISecSDKError("response exceeds max length", aisec.UserRequestPayloadError)
		}
		c.response = opts.Response
	}
	if opts.Context != "" {
		if len(opts.Context) > aisec.MaxContentContextLength {
			return nil, aisec.NewAISecSDKError("context exceeds max length", aisec.UserRequestPayloadError)
		}
		c.context = opts.Context
	}
	if opts.CodePrompt != "" {
		if len(opts.CodePrompt) > aisec.MaxContentPromptLength {
			return nil, aisec.NewAISecSDKError("codePrompt exceeds max length", aisec.UserRequestPayloadError)
		}
		c.codePrompt = opts.CodePrompt
	}
	if opts.CodeResponse != "" {
		if len(opts.CodeResponse) > aisec.MaxContentResponseLength {
			return nil, aisec.NewAISecSDKError("codeResponse exceeds max length", aisec.UserRequestPayloadError)
		}
		c.codeResponse = opts.CodeResponse
	}
	c.toolEvent = opts.ToolEvent

	return c, nil
}

// Prompt returns the prompt text.
func (c *Content) Prompt() string { return c.prompt }

// Response returns the response text.
func (c *Content) Response() string { return c.response }

// Context returns the context text.
func (c *Content) Context() string { return c.context }

// CodePrompt returns the code prompt text.
func (c *Content) CodePrompt() string { return c.codePrompt }

// CodeResponse returns the code response text.
func (c *Content) CodeResponse() string { return c.codeResponse }

// ToolEvent returns the tool event.
func (c *Content) ToolEvent() *ToolEvent { return c.toolEvent }

// ByteLength returns the total byte length of all text content fields.
func (c *Content) ByteLength() int {
	return len(c.prompt) + len(c.response) + len(c.context) + len(c.codePrompt) + len(c.codeResponse)
}

// ToJSON serializes to the API request format.
func (c *Content) ToJSON() ContentInner {
	ci := ContentInner{}
	if c.prompt != "" {
		ci.Prompt = c.prompt
	}
	if c.response != "" {
		ci.Response = c.response
	}
	if c.context != "" {
		ci.Context = c.context
	}
	if c.codePrompt != "" {
		ci.CodePrompt = c.codePrompt
	}
	if c.codeResponse != "" {
		ci.CodeResponse = c.codeResponse
	}
	if c.toolEvent != nil {
		ci.ToolEvent = c.toolEvent
	}
	return ci
}

// ContentFromJSON creates a Content from an API response object.
func ContentFromJSON(ci ContentInner) (*Content, error) {
	return NewContent(ContentOpts{
		Prompt:       ci.Prompt,
		Response:     ci.Response,
		Context:      ci.Context,
		CodePrompt:   ci.CodePrompt,
		CodeResponse: ci.CodeResponse,
		ToolEvent:    ci.ToolEvent,
	})
}
