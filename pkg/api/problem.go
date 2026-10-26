// SPDX-License-Identifier: 0BSD

package api

import (
	"encoding/json"
	"net/http"
)

// Problem codes carried in the stable code member of problem responses.
const (
	CodeConflict           = "conflict"
	CodeEncrypted          = "encrypted"
	CodeEncryptionRequired = "encryption_required"
	CodeQuotaExceeded      = "quota_exceeded"
	CodeRateLimited        = "rate_limited"
	CodeBandwidthExceeded  = "bandwidth_exceeded"
	CodeMaintenance        = "maintenance"
	CodeIPBlocked          = "ip_blocked"
	CodeInvalidManifest    = "invalid_manifest"
	CodeNotFound           = "not_found"
	CodeUnauthorized       = "unauthorized"
	CodeForbidden          = "forbidden"
	CodeTooLarge           = "too_large"
	CodeBadRequest         = "bad_request"
	CodeInternal           = "internal"
)

// Problem is an RFC 9457 application/problem+json body with a stable
// machine readable code member.
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     string `json:"code"`
}

// NewProblem builds a problem with status, code, and detail.
func NewProblem(status int, code, detail string) *Problem {
	return &Problem{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Code:   code,
	}
}

// Error implements error.
func (p *Problem) Error() string {
	return p.Code + ": " + p.Detail
}

// Write encodes the problem as application/problem+json.
func (p *Problem) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// Range is a parsed HTTP byte range.
type Range struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"` // inclusive
}

// Len returns the number of bytes covered.
func (r Range) Len() int64 { return r.End - r.Start + 1 }
