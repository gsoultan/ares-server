// Copyright © 2026 Gembit Soultan Shirazi. All rights reserved.
//
// This file is part of Ares and is proprietary and confidential. Unauthorized
// copying, modification, distribution, or use of this file, in whole or in
// part, via any medium, is strictly prohibited without the prior written
// permission of the copyright holder.

package report

import (
	"fmt"
	"strings"
)

// Format MIME types.
const (
	MIMEPDF      = "application/pdf"
	MIMEDOCX     = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	MIMEMarkdown = "text/markdown; charset=utf-8"
)

// Render produces the report in the named format (pdf when empty), returning
// the bytes, the MIME content type and the file extension.
func (r Report) Render(format string) (data []byte, contentType, ext string, err error) {
	switch strings.ToLower(format) {
	case "", "pdf":
		return r.PDF(), MIMEPDF, "pdf", nil
	case "docx":
		d, derr := r.DOCX()
		if derr != nil {
			return nil, "", "", derr
		}
		return d, MIMEDOCX, "docx", nil
	case "md", "markdown":
		return r.Markdown(), MIMEMarkdown, "md", nil
	default:
		return nil, "", "", fmt.Errorf("unknown report format %q (want pdf, docx or md)", format)
	}
}

// Filename builds a human, filesystem-safe download name from an engagement
// name: "ares-report-<slug>.<ext>".
func Filename(name, ext string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "engagement"
	}
	return "ares-report-" + slug + "." + ext
}
