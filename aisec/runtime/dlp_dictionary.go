package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
	"github.com/cdot65/prisma-airs-go/aisec/internal"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

func dlpInvalid(message string) error {
	return aisec.NewAISecSDKError(message, aisec.UserRequestPayloadError)
}

// DictionaryUpload contains typed metadata and the keyword file bytes; no JSON-string input is needed.
type DictionaryUpload struct {
	Metadata        parity.DictionaryRequest
	File            []byte
	IncludeKeywords *bool
}

// DictionaryGetOptions controls whether keyword content is included.
type DictionaryGetOptions struct{ IncludeKeywords *bool }

const dlpDictionariesPath = aisec.RuntimeV2ApiDictionariesPath

// Create uploads metadata.json and a keyword file through the shared management OAuth pipeline.
func (c *DictionariesClient) Create(ctx context.Context, input DictionaryUpload) (*parity.DictionaryResponse, error) {
	return c.upload(ctx, http.MethodPost, dlpDictionariesPath, input)
}

// Replace replaces the dictionary; a valid 204 returns nil, nil, rather than inventing a record.
func (c *DictionariesClient) Replace(ctx context.Context, id string, input DictionaryUpload) (*parity.DictionaryResponse, error) {
	if id == "" {
		return nil, dlpInvalid("dictionary ID is required")
	}
	return c.upload(ctx, http.MethodPut, dlpDictionariesPath+"/"+seg(id), input)
}
func (c *DictionariesClient) upload(ctx context.Context, method, path string, input DictionaryUpload) (*parity.DictionaryResponse, error) {
	if err := parity.Validate("DictionaryRequestSchema", input.Metadata); err != nil {
		return nil, aisec.WrapError("invalid dictionary metadata", aisec.UserRequestPayloadError, err)
	}
	if strings.TrimSpace(input.Metadata.OriginalFileName) == "" {
		return nil, dlpInvalid("dictionary filename is required")
	}
	metadata, err := json.Marshal(input.Metadata)
	if err != nil {
		return nil, aisec.WrapError("invalid dictionary metadata", aisec.UserRequestPayloadError, err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, part := range []struct {
		name, filename, kind string
		data                 []byte
	}{{"json", "metadata.json", "application/json", metadata}, {"file", input.Metadata.OriginalFileName, "text/plain", input.File}} {
		header := textproto.MIMEHeader{}
		header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": part.name, "filename": part.filename}))
		header.Set("Content-Type", part.kind)
		writer, err := form.CreatePart(header)
		if err != nil {
			return nil, err
		}
		if _, err = writer.Write(part.data); err != nil {
			return nil, err
		}
	}
	if err := form.Close(); err != nil {
		return nil, err
	}
	query := url.Values{}
	if input.IncludeKeywords != nil {
		query.Set("keywords", fmt.Sprint(*input.IncludeKeywords))
	}
	raw, err := internal.DoMgmtRaw(ctx, c.cfg, internal.RawMgmtRequestOptions{Method: method, Path: path, Query: query, Body: body.Bytes(), ContentType: form.FormDataContentType()})
	if err != nil {
		return nil, dlpSafeError(err)
	}
	if len(bytes.TrimSpace(raw.Body)) == 0 {
		if method == http.MethodPut && raw.Status == 204 {
			return nil, nil
		}
		return nil, aisec.NewHTTPError("expected dictionary response", aisec.AISecSDKInternalError, raw.Status)
	}
	if err := parity.ValidateJSON("DictionaryResponseSchema", raw.Body); err != nil {
		return nil, aisec.WrapError("invalid dictionary response", aisec.AISecSDKInternalError, err)
	}
	r, err := internal.DecodeMgmtResponse[parity.DictionaryResponse](raw, internal.RequireJSON)
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

// Get reads a dictionary, optionally with its keyword content.
func (c *DictionariesClient) Get(ctx context.Context, id string, opts DictionaryGetOptions) (*parity.DictionaryResponse, error) {
	if id == "" {
		return nil, dlpInvalid("dictionary ID is required")
	}
	query := url.Values{}
	if opts.IncludeKeywords != nil {
		query.Set("keywords", fmt.Sprint(*opts.IncludeKeywords))
	}
	raw, err := internal.DoMgmtRaw(ctx, c.cfg, internal.RawMgmtRequestOptions{Method: http.MethodGet, Path: dlpDictionariesPath + "/" + seg(id), Query: query})
	if err != nil {
		return nil, dlpSafeError(err)
	}
	if err := parity.ValidateJSON("DictionaryResponseSchema", raw.Body); err != nil {
		return nil, aisec.WrapError("invalid dictionary response", aisec.AISecSDKInternalError, err)
	}
	r, err := internal.DecodeMgmtResponse[parity.DictionaryResponse](raw, internal.RequireJSON)
	if err != nil {
		return nil, err
	}
	return &r.Data, nil
}

func dlpSafeError(err error) error {
	wrapped := aisec.WrapError("dictionary request failed", aisec.ClientSideError, err)
	var sdk *aisec.AISecSDKError
	if errors.As(err, &sdk) {
		wrapped.StatusCode = sdk.StatusCode
		wrapped.ErrorType = sdk.ErrorType
	}
	return wrapped
}
