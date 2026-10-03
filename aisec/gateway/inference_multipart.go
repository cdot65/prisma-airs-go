package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"reflect"
	"strconv"
	"strings"

	"github.com/cdot65/prisma-airs-go/aisec"
	parity "github.com/cdot65/prisma-airs-go/aisec/parity/schema"
)

// BinaryResponse preserves binary download bytes and response headers.
type BinaryResponse struct {
	Body       []byte
	Headers    http.Header
	StatusCode int
}

// AudioResponse returns the requested format without treating text as JSON.
// Exactly one of Text, JSON, or VerboseJSON is populated according to ResponseFormat.
type AudioResponse struct {
	ResponseFormat string
	Text           string
	JSON           json.RawMessage
	VerboseJSON    json.RawMessage
}

func inferenceBinary(ctx context.Context, c *InferenceClient, method, path string, body any, requestSchema string, opts InferenceRequestOptions) (*BinaryResponse, error) {
	var encoded []byte
	if body != nil {
		if requestSchema != "" {
			if err := parity.Validate(requestSchema, body); err != nil {
				return nil, aisec.WrapError("invalid binary request", aisec.UserRequestPayloadError, err)
			}
		}
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	r, cancel, err := c.open(ctx, method, path, nil, encoded, "application/json", opts)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = r.Body.Close() }()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, aisec.WrapError("binary response read failed", aisec.ClientSideError, err)
	}
	return &BinaryResponse{Body: data, Headers: r.Header.Clone(), StatusCode: r.StatusCode}, nil
}
func runtimeMultipart(body any) ([]byte, string, error) {
	var encoded bytes.Buffer
	writer := multipart.NewWriter(&encoded)
	var add func(string, reflect.Value) error
	add = func(key string, v reflect.Value) error {
		for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
			if v.IsNil() {
				return nil
			}
			v = v.Elem()
		}
		if !v.IsValid() {
			return nil
		}
		if file, ok := v.Interface().(RuntimeFile); ok {
			if file.Filename == "" {
				return invalidInput("multipart file requires a filename")
			}
			kind := file.ContentType
			if kind == "" {
				kind = "application/octet-stream"
			}
			header := textproto.MIMEHeader{}
			header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": key, "filename": file.Filename}))
			header.Set("Content-Type", kind)
			part, err := writer.CreatePart(header)
			if err != nil {
				return err
			}
			_, err = part.Write(file.Data)
			return err
		}
		if v.Kind() == reflect.Slice {
			if v.Type().Elem().Kind() == reflect.Uint8 {
				return invalidInput("binary multipart content requires RuntimeFile")
			}
			if !strings.HasSuffix(key, "[]") {
				key += "[]"
			}
			for i := 0; i < v.Len(); i++ {
				if err := add(key, v.Index(i)); err != nil {
					return err
				}
			}
			return nil
		}
		if key == "file" || key == "image" || key == "image[]" || key == "mask" {
			return invalidInput("multipart binary fields require RuntimeFile values")
		}
		var str string
		switch v.Kind() {
		case reflect.String:
			str = v.String()
		case reflect.Bool:
			str = fmt.Sprint(v.Bool())
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			str = fmt.Sprint(v.Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			str = strconv.FormatUint(v.Uint(), 10)
		case reflect.Float32, reflect.Float64:
			str = strconv.FormatFloat(v.Float(), 'f', -1, v.Type().Bits())
		default:
			b, err := json.Marshal(v.Interface())
			if err != nil {
				return err
			}
			if string(b) == "null" {
				return nil
			}
			str = string(b)
		}
		return writer.WriteField(key, str)
	}
	v := reflect.ValueOf(body)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, "", invalidInput("multipart request must be typed")
	}
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		key := strings.Split(field.Tag.Get("json"), ",")[0]
		if key == "" || key == "-" {
			continue
		}
		value := v.Field(i)
		if key == "file" || key == "image" {
			test := value
			for test.IsValid() && (test.Kind() == reflect.Pointer || test.Kind() == reflect.Interface) {
				if test.IsNil() {
					return nil, "", invalidInput("required multipart file is missing")
				}
				test = test.Elem()
			}
			if !test.IsValid() || (test.Kind() == reflect.Slice && test.Len() == 0) {
				return nil, "", invalidInput("required multipart file is missing")
			}
		}
		// Read the Optional's native value, preserving int64 precision and explicit zero.
		if strings.HasPrefix(value.Type().Name(), "Optional[") {
			values := value.MethodByName("Get").Call(nil)
			if !values[1].Bool() {
				continue
			}
			value = values[0]
		}

		if err := add(key, value); err != nil {
			return nil, "", err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return encoded.Bytes(), writer.FormDataContentType(), nil
}
func inferenceMultipart[T any](ctx context.Context, c *InferenceClient, method, path string, body any, requestSchema, responseSchema string, opts InferenceRequestOptions) (*T, error) {
	if err := parity.Validate(requestSchema, body); err != nil {
		return nil, aisec.WrapError("invalid multipart request", aisec.UserRequestPayloadError, err)
	}
	data, kind, err := runtimeMultipart(body)
	if err != nil {
		return nil, err
	}
	r, cancel, err := c.open(ctx, method, path, nil, data, kind, opts)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = r.Body.Close() }()
	reply, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, aisec.WrapError("multipart response read failed", aisec.ClientSideError, err)
	}
	if responseSchema != "" {
		if err := parity.ValidateJSON(responseSchema, reply); err != nil {
			return nil, aisec.WrapError("invalid multipart response", aisec.AISecSDKInternalError, err)
		}
	}
	var output T
	if err := json.Unmarshal(reply, &output); err != nil {
		return nil, aisec.WrapError("invalid multipart JSON response", aisec.AISecSDKInternalError, err)
	}
	return &output, nil
}
func inferenceAudio(ctx context.Context, c *InferenceClient, path string, body any, requestSchema string, format *string, opts InferenceRequestOptions) (*AudioResponse, error) {
	if err := parity.Validate(requestSchema, body); err != nil {
		return nil, aisec.WrapError("invalid audio request", aisec.UserRequestPayloadError, err)
	}
	kind := "json"
	if format != nil {
		kind = *format
	}
	if kind != "json" && kind != "verbose_json" && kind != "text" && kind != "srt" && kind != "vtt" {
		return nil, invalidInput("unsupported audio response format")
	}
	data, contentType, err := runtimeMultipart(body)
	if err != nil {
		return nil, err
	}
	r, cancel, err := c.open(ctx, "POST", path, nil, data, contentType, opts)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = r.Body.Close() }()
	reply, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, aisec.WrapError("audio response read failed", aisec.ClientSideError, err)
	}
	result := &AudioResponse{ResponseFormat: kind}
	if kind == "text" || kind == "srt" || kind == "vtt" {
		result.Text = string(reply)
		return result, nil
	}
	schemaName := "GatewayInferenceCreateTranscriptionResponseJsonSchema"
	if strings.HasSuffix(path, "translations") {
		schemaName = "GatewayInferenceCreateTranslationResponseJsonSchema"
	}
	if kind == "verbose_json" {
		schemaName = strings.Replace(schemaName, "JsonSchema", "VerboseJsonSchema", 1)
	}
	if err := parity.ValidateJSON(schemaName, reply); err != nil {
		return nil, aisec.WrapError("invalid audio JSON response", aisec.AISecSDKInternalError, err)
	}
	if kind == "verbose_json" {
		result.VerboseJSON = append(json.RawMessage(nil), reply...)
	} else {
		result.JSON = append(json.RawMessage(nil), reply...)
	}
	return result, nil
}
func inferenceText(ctx context.Context, c *InferenceClient, method, path string, body any, requestSchema string, opts InferenceRequestOptions) (*string, error) {
	r, err := inferenceBinary(ctx, c, method, path, body, requestSchema, opts)
	if err != nil {
		return nil, err
	}
	text := string(r.Body)
	return &text, nil
}
