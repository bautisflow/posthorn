package gateway

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/craigmccaskill/posthorn/config"
	"github.com/craigmccaskill/posthorn/spam"
	"github.com/craigmccaskill/posthorn/transport"
)

// Attachment ingestion (FR90/FR91, ADR-25). Both HTTP doors normalize
// to []transport.Attachment through the same sniff-and-enforce gate:
// form-mode multipart file parts, api-mode base64 entries. The SMTP
// listener does not ingest attachments in v2.0 (demand-gated).

// attachmentPolicy is the parsed, enforceable form of
// config.AttachmentsConfig.
type attachmentPolicy struct {
	allowed  []string // lowercase "type/subtype" or "type/*"
	maxCount int
	maxTotal int64
}

func newAttachmentPolicy(cfg *config.AttachmentsConfig) (*attachmentPolicy, error) {
	if cfg == nil {
		return nil, nil
	}
	total, err := spam.ParseSize(cfg.EffectiveMaxTotalSize())
	if err != nil {
		return nil, fmt.Errorf("attachments: max_total_size: %w", err)
	}
	return &attachmentPolicy{
		allowed:  cfg.AllowedTypes,
		maxCount: cfg.EffectiveMaxCount(),
		maxTotal: total,
	}, nil
}

// sniffType returns the detected media type of data with parameters
// stripped ("text/plain; charset=utf-8" → "text/plain"). Detection uses
// the actual bytes (http.DetectContentType) — the client's declared
// type is never consulted for authorization (ADR-25).
func sniffType(data []byte) string {
	detected := http.DetectContentType(data)
	mediaType, _, err := mime.ParseMediaType(detected)
	if err != nil {
		return "application/octet-stream"
	}
	return mediaType
}

// permitted reports whether sniffed matches the allowlist.
func (p *attachmentPolicy) permitted(sniffed string) bool {
	family := sniffed[:strings.IndexByte(sniffed, '/')+1] + "*"
	for _, pat := range p.allowed {
		if pat == sniffed || pat == family {
			return true
		}
	}
	return false
}

// attachmentError is a per-file 422 reason, keyed for the validation
// response's field-error map.
type attachmentError struct {
	Name   string
	Reason string
}

// vet enforces count, total size, and the sniffed-type allowlist over
// candidate files. Returns the accepted attachments (content types
// rewritten to the sniffed value) or the violations.
func (p *attachmentPolicy) vet(files []transport.Attachment) ([]transport.Attachment, []attachmentError) {
	var errs []attachmentError
	if len(files) > p.maxCount {
		errs = append(errs, attachmentError{
			Name:   "attachments",
			Reason: fmt.Sprintf("too many files: %d exceeds max_count %d", len(files), p.maxCount),
		})
		return nil, errs
	}
	var total int64
	out := make([]transport.Attachment, 0, len(files))
	for _, f := range files {
		total += int64(len(f.Data))
		sniffed := sniffType(f.Data)
		if !p.permitted(sniffed) {
			errs = append(errs, attachmentError{
				Name:   f.Filename,
				Reason: fmt.Sprintf("content type %q not in allowed_types", sniffed),
			})
			continue
		}
		f.ContentType = sniffed
		out = append(out, f)
	}
	if total > p.maxTotal {
		errs = append(errs, attachmentError{
			Name:   "attachments",
			Reason: fmt.Sprintf("total size %d bytes exceeds max_total_size %d", total, p.maxTotal),
		})
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return out, nil
}

// collectMultipartFiles reads every file part of a parsed multipart
// form into candidate attachments. Caller has already bounded the
// request body (MaxBytesReader), so reads here are bounded too.
func collectMultipartFiles(r *http.Request) ([]transport.Attachment, error) {
	if r.MultipartForm == nil {
		return nil, nil
	}
	var out []transport.Attachment
	for _, headers := range r.MultipartForm.File {
		for _, fh := range headers {
			f, err := fh.Open()
			if err != nil {
				return nil, fmt.Errorf("open uploaded file %q: %w", fh.Filename, err)
			}
			data, err := io.ReadAll(f)
			_ = f.Close()
			if err != nil {
				return nil, fmt.Errorf("read uploaded file %q: %w", fh.Filename, err)
			}
			out = append(out, transport.Attachment{
				Filename: sanitizeFilename(fh.Filename),
				Data:     data,
			})
		}
	}
	return out, nil
}

// apiAttachment is the api-mode JSON shape (FR90):
// {"filename": ..., "content_type": ..., "data": "<base64>"}.
// content_type is accepted for caller convenience but ignored — the
// sniffed type is authoritative (ADR-25).
type apiAttachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Data        string `json:"data"`
}

// decodeAPIAttachments converts the raw "attachments" JSON value into
// candidate attachments. Returns a client-visible error on shape or
// base64 problems.
func decodeAPIAttachments(entries []apiAttachment) ([]transport.Attachment, error) {
	out := make([]transport.Attachment, 0, len(entries))
	for i, e := range entries {
		if e.Filename == "" {
			return nil, &clientVisibleError{fmt.Sprintf("attachments[%d]: filename is required", i)}
		}
		if e.Data == "" {
			return nil, &clientVisibleError{fmt.Sprintf("attachments[%d]: data is required", i)}
		}
		raw, err := base64.StdEncoding.DecodeString(e.Data)
		if err != nil {
			return nil, &clientVisibleError{fmt.Sprintf("attachments[%d]: data is not valid base64", i)}
		}
		out = append(out, transport.Attachment{
			Filename: sanitizeFilename(e.Filename),
			Data:     raw,
		})
	}
	return out, nil
}

// sanitizeFilename strips path separators and control characters from a
// submitter-supplied filename — it is display/parameter material only,
// never a filesystem path and never raw header bytes (NFR1).
func sanitizeFilename(name string) string {
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if clean == "" {
		clean = "attachment"
	}
	return clean
}
