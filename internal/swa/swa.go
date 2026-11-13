// Package swa implements the MIME canonicalization of the OASIS WS-Security
// SOAP Messages with Attachments profile 1.1.1, section 5.4, which the SwA
// signature transforms in dsig and Attachment-Complete encryption in xenc
// share.
//
// Where the profile leaves a choice open, or Apache WSS4J, the implementation
// WS-Security peers run, reads it differently for common input, the choice
// follows WSS4J so that signatures verify there; each such place says so.
// Three such departures from section 5.4.1 remain, each required by WSS4J
// as the interop suite shows: no space after the colon of
// Content-Description (rule 8), the trailing whitespace a removed comment
// leaves there (rule 18), and a lowercased filename parameter (rule 15).
package swa

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"maps"
	"mime"
	"slices"
	"strings"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
)

// Headers are the MIME headers Attachment-Complete covers (section 5.3.2),
// spelled as the profile spells them and in the ascending lexicographic
// order in which they are canonicalized (section 5.4.1, rule 3).
var Headers = []string{"Content-Description", "Content-Disposition", "Content-ID", "Content-Location", "Content-Type"}

// defaultContentType stands in for an absent Content-Type (rule 2).
const defaultContentType = "text/plain; charset=us-ascii"

// lowerParams are the parameters whose values are case-insensitive and so
// lowercased (rule 15). The set is WSS4J's; it includes filename, which
// RFC 2183 does not make case-insensitive, so rule 15 would keep its case.
// WSS4J lowercases it, signing and verifying: the interop suite
// (tests/interop/swa_test.go, filename="Invoice.XML") fails both ways when
// the case is kept.
var lowerParams = map[string]bool{
	"charset": true, "creation-date": true, "filename": true, "modification-date": true,
	"padding": true, "read-date": true, "size": true, "type": true,
}

var quoteEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// unfolder removes the line breaks of folded header lines.
var unfolder = strings.NewReplacer("\r\n ", " ", "\r\n\t", "\t")

// Selected returns the headers of h that the profile lists, keyed by their
// names in Headers, each value unfolded. A listed header present more than
// once is refused, since which one a peer would take is undefined, and so is
// a value with a line break left after unfolding.
func Selected(h map[string][]string) (map[string]string, error) {
	sel := make(map[string]string, len(Headers))
	for k, vs := range h {
		i := slices.IndexFunc(Headers, func(n string) bool { return strings.EqualFold(n, k) })
		if i < 0 {
			continue
		}
		name := Headers[i]
		if _, dup := sel[name]; dup || len(vs) != 1 {
			return nil, fmt.Errorf("%w: MIME header %s must appear once", xmlsec.ErrMalformed, name)
		}
		v := unfolder.Replace(vs[0])
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%w: MIME header %s has a line break", xmlsec.ErrMalformed, name)
		}
		sel[name] = v
	}
	return sel, nil
}

// Content returns the attachment content canonicalized for a signature
// reference (section 5.4.2): an XML media type by Exclusive XML
// Canonicalization without comments, any other text type by normalizing
// line endings to CRLF, anything else unchanged.
func Content(att *xmlsec.Attachment) ([]byte, error) {
	return collect(WriteContent, att)
}

// WriteContent writes what Content returns to w as it is produced, so the
// canonical form is never held: digesting an XML attachment then costs its
// parsed tree, not the tree and its canonical form in a growing buffer.
func WriteContent(w io.Writer, att *xmlsec.Attachment) error {
	sel, err := selected(att)
	if err != nil {
		return err
	}
	mt, _, err := mediaType(sel["Content-Type"])
	if err != nil {
		return fmt.Errorf("%w: Content-Type: %v", xmlsec.ErrMalformed, err)
	}
	return writeContent(w, mt, att.Body)
}

// Complete returns what the Attachment-Complete signature transform digests:
// the canonical MIME headers (section 5.4.1), each "Name:value" and CRLF,
// then the canonical content. No empty line separates them: rules 18 and 19
// read as one CRLF per header, which is how WSS4J reads them.
func Complete(att *xmlsec.Attachment) ([]byte, error) {
	return collect(WriteComplete, att)
}

// WriteComplete writes what Complete returns to w as it is produced, as
// WriteContent does. The headers are all canonicalized before anything is
// written, so a malformed header writes nothing.
func WriteComplete(w io.Writer, att *xmlsec.Attachment) error {
	sel, err := selected(att)
	if err != nil {
		return err
	}
	var headers []byte
	var mt string
	for _, name := range Headers {
		v, ok := sel[name]
		if !ok {
			continue
		}
		c, err := canonicalValue(name, v)
		if err != nil {
			return err
		}
		// Selected refuses a line break in the received value, but an RFC
		// 2047 word or RFC 2231 parameter can decode to one. Written here it
		// would end the line, so a header folded into another's value would
		// digest as the header itself.
		if strings.ContainsAny(c, "\r\n") {
			return fmt.Errorf("%w: MIME header %s has a line break once decoded", xmlsec.ErrMalformed, name)
		}
		headers = append(headers, name+":"+c+"\r\n"...)
		if name == "Content-Type" {
			// The canonical value starts with the media type, which has no ";".
			mt, _, _ = strings.Cut(c, ";")
		}
	}
	if _, err := w.Write(headers); err != nil {
		return err
	}
	return writeContent(w, mt, att.Body)
}

// collect runs write into memory, for a caller that needs the octets
// themselves: an SwA transform followed by another transform.
func collect(write func(io.Writer, *xmlsec.Attachment) error, att *xmlsec.Attachment) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, att); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// selected is Selected with the default Content-Type filled in.
func selected(att *xmlsec.Attachment) (map[string]string, error) {
	sel, err := Selected(att.MIMEHeaders)
	if _, ok := sel["Content-Type"]; err == nil && !ok {
		sel["Content-Type"] = defaultContentType
	}
	return sel, err
}

// canonicalValue applies rules 5 to 17 to one unfolded header value.
//
// Two departures from section 5.4.1 follow WSS4J, which the interop suite
// (tests/interop/swa_test.go) shows signs and verifies only this way; each
// fails against WSS4J in both directions when "fixed":
//
//   - rule 8: the value arrives without the whitespace after the colon, as
//     MIME parsers return it and as WSS4J receives it, so an unstructured
//     Content-Description is written "Content-Description:value", where
//     rule 8 would keep the space;
//   - rule 18: the whitespace a removed comment leaves in a
//     Content-Description stays, trailing or not ("a (b)" becomes "a "),
//     where rule 18 forbids trailing whitespace.
//
// The third, rule 15's lowercasing of filename, is in lowerParams.
func canonicalValue(name, v string) (string, error) {
	switch name {
	case "Content-Description":
		d, err := new(mime.WordDecoder).DecodeHeader(v)
		if err != nil {
			return "", fmt.Errorf("%w: Content-Description: %v", xmlsec.ErrMalformed, err)
		}
		return uncomment(d), nil
	case "Content-ID", "Content-Location":
		return structured(uncomment(v)), nil
	}
	mt, params, err := mediaType(v)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", xmlsec.ErrMalformed, name, err)
	}
	var b strings.Builder
	b.WriteString(mt)
	for _, k := range slices.Sorted(maps.Keys(params)) {
		p := params[k]
		if lowerParams[k] {
			p = strings.ToLower(p)
		}
		b.WriteString(";" + k + `="` + quoteEscaper.Replace(p) + `"`)
	}
	return b.String(), nil
}

// mediaType parses a Content-Type or Content-Disposition value with its
// comments removed. mime.ParseMediaType lowercases the type and the
// parameter names and decodes RFC 2231 parameters (rules 10, 13, 14).
func mediaType(v string) (string, map[string]string, error) {
	return mime.ParseMediaType(uncomment(v))
}

// writeContent writes body to w canonicalized by the media type mt, as
// mediaType returns it.
func writeContent(w io.Writer, mt string, body []byte) error {
	// Into a buffer, as from collect, the output is sized up front: the body
	// as it is, or one byte more per CR and LF for text; for XML the body's
	// length is a first estimate, about the canonical form's size.
	buf, _ := w.(*bytes.Buffer)
	switch {
	case mt == "text/xml", mt == "application/xml", strings.HasSuffix(mt, "+xml"):
		if buf != nil {
			buf.Grow(len(body))
		}
		tree, err := xmlsec.Parse(body)
		if err != nil {
			return fmt.Errorf("%w: XML attachment: %w", xmlsec.ErrMalformed, err)
		}
		// c14n.Write buffers its own output, 64 KiB, and holds no more.
		return c14n.Write(w, tree.Root, c14n.Options{Algorithm: c14n.Exclusive10})
	case strings.HasPrefix(mt, "text/"):
		if buf != nil {
			buf.Grow(len(body) + bytes.Count(body, []byte("\r")) + bytes.Count(body, []byte("\n")))
		}
		return writeCRLF(w, body)
	}
	_, err := w.Write(body)
	return err
}

// writeCRLF writes body with every line ending, CRLF, lone CR or lone LF,
// written as CRLF.
func writeCRLF(w io.Writer, body []byte) error {
	// A bufio.Writer keeps its first error, which Flush returns.
	b := bufio.NewWriterSize(w, 64<<10)
	for len(body) > 0 {
		i := bytes.IndexAny(body, "\r\n")
		if i < 0 {
			_, _ = b.Write(body)
			break
		}
		_, _ = b.Write(body[:i])
		_, _ = b.WriteString("\r\n")
		if body[i] == '\r' && i+1 < len(body) && body[i+1] == '\n' {
			i++
		}
		body = body[i+1:]
	}
	return b.Flush()
}

// uncomment removes RFC 5322 comments outside quoted strings (rule 9).
func uncomment(s string) string {
	var b strings.Builder
	depth, quoted := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			if depth == 0 {
				b.WriteString(s[i : i+2])
			}
			i++
		case quoted:
			quoted = c != '"'
			b.WriteByte(c)
		case c == '(':
			depth++
		case depth > 0:
			if c == ')' {
				depth--
			}
		default:
			quoted = c == '"'
			b.WriteByte(c)
		}
	}
	return b.String()
}

// structured removes whitespace outside quoted strings (rule 8) and unquotes
// quoted characters other than a double quote and a backslash (rule 11).
func structured(s string) string {
	var b strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quoted && c == '\\' && i+1 < len(s):
			i++
			if s[i] == '"' || s[i] == '\\' {
				b.WriteByte('\\')
			}
			b.WriteByte(s[i])
		case c == '"':
			quoted = !quoted
			b.WriteByte(c)
		case quoted || c != ' ' && c != '\t':
			b.WriteByte(c)
		}
	}
	return b.String()
}
