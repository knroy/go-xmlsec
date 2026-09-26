package swa_test

import (
	"errors"
	"testing"

	"github.com/knroy/go-xmlsec"
	"github.com/knroy/go-xmlsec/internal/swa"
)

// The headers of WSS4J's own AttachmentTest, and what its
// AttachmentUtils.canonizeMimeHeaders makes of them.
func TestCompleteWSS4JHeaders(t *testing.T) {
	att := &xmlsec.Attachment{Body: []byte("<?xml version='1.0'?>\n<a  b='1'><!-- c --><b/></a>\n"), MIMEHeaders: map[string][]string{
		"Content-Description": {"Attachment"},
		"Content-Disposition": {`attachment; filename="fname.ext"`},
		"Content-ID":          {"<attachment=1>"},
		"Content-Location":    {"http://ws.apache.org"},
		"Content-Type":        {"text/xml; charset=UTF-8"},
		"TestHeader":          {"testHeaderValue"},
	}}
	want := "Content-Description:Attachment\r\n" +
		"Content-Disposition:attachment;filename=\"fname.ext\"\r\n" +
		"Content-ID:<attachment=1>\r\n" +
		"Content-Location:http://ws.apache.org\r\n" +
		"Content-Type:text/xml;charset=\"utf-8\"\r\n" +
		`<a b="1"><b></b></a>`
	got, err := swa.Complete(att)
	if err != nil || string(got) != want {
		t.Fatalf("got %q, %v\nwant %q", got, err, want)
	}
}

func TestCompleteHeaderRules(t *testing.T) {
	cases := []struct {
		name, header, value, want string
	}{
		{"absent Content-Type", "X-Other", "x", "Content-Type:text/plain;charset=\"us-ascii\"\r\n"},
		{"folded, comment, RFC 2047", "content-description", "=?UTF-8?Q?caf=C3=A9?= (note)\r\n  menu (x)", "Content-Description:café   menu \r\n"},
		{"structured whitespace and quoting", "Content-ID", ` < a "q \" \\ \a" (c\)) @x > `, `Content-ID:<a"q \" \\ a"@x>` + "\r\n"},
		{"trailing backslash", "Content-Location", `http://x/\`, `Content-Location:http://x/\` + "\r\n"},
		{"nested comment", "Content-Location", `http://x/(a(b)c)y`, "Content-Location:http://x/y\r\n"},
		{"parameters", "Content-Disposition", `ATTACHMENT; Size=10; FileName*=UTF-8''A%20B; Name="x\"y\\z"`,
			`Content-Disposition:attachment;filename="a b";name="x\"y\\z";size="10"` + "\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := map[string][]string{c.header: {c.value}}
			if c.header != "Content-Type" {
				h["Content-Type"] = []string{"application/octet-stream"}
			}
			got, err := swa.Complete(&xmlsec.Attachment{MIMEHeaders: h})
			want := c.want + "Content-Type:application/octet-stream\r\n"
			if c.header == "X-Other" {
				got, err = swa.Complete(&xmlsec.Attachment{MIMEHeaders: map[string][]string{c.header: {c.value}}})
				want = c.want
			}
			if err != nil || string(got) != want {
				t.Fatalf("got %q, %v\nwant %q", got, err, want)
			}
		})
	}
}

func TestContent(t *testing.T) {
	cases := []struct {
		contentType []string // nil: no Content-Type
		body, want  string
	}{
		{nil, "a\nb\rc\r\nd\r\r\n", "a\r\nb\r\nc\r\nd\r\n\r\n"},
		{[]string{"TEXT/Plain"}, "a\n", "a\r\n"},
		{[]string{"application/xml"}, "<a xmlns:u='urn:u'>\r\n</a>", "<a>\n</a>"},
		{[]string{"application/soap+xml; charset=utf-8"}, "<a/>", "<a></a>"},
		{[]string{"application/octet-stream"}, "a\n", "a\n"},
	}
	for _, c := range cases {
		h := map[string][]string{}
		if c.contentType != nil {
			h["Content-Type"] = c.contentType
		}
		got, err := swa.Content(&xmlsec.Attachment{MIMEHeaders: h, Body: []byte(c.body)})
		if err != nil || string(got) != c.want {
			t.Errorf("%v: got %q, %v, want %q", c.contentType, got, err, c.want)
		}
	}
}

func TestRefused(t *testing.T) {
	cases := map[string]map[string][]string{
		"header twice":               {"Content-Type": {"text/plain"}, "content-type": {"text/plain"}},
		"header with two values":     {"Content-ID": {"<a>", "<b>"}},
		"header with no value":       {"Content-ID": {}},
		"line break left":            {"Content-ID": {"<a>\r\nX: y"}},
		"bad Content-Type":           {"Content-Type": {"text/plain; charset"}},
		"bad Content-Disposition":    {"Content-Disposition": {"attachment; filename"}},
		"unknown RFC 2047 charset":   {"Content-Description": {"=?x-unknown?Q?a?="}},
		"XML that does not parse":    {"Content-Type": {"text/xml"}},
		"XML with a DOCTYPE refused": {"Content-Type": {"application/xml"}, "X": {"doctype"}},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			body := []byte("<a>")
			if h["X"] != nil {
				body = []byte("<!DOCTYPE a><a/>")
			}
			att := &xmlsec.Attachment{MIMEHeaders: h, Body: body}
			if _, err := swa.Complete(att); !errors.Is(err, xmlsec.ErrMalformed) {
				t.Fatalf("Complete: %v", err)
			}
			if _, err := swa.Content(att); h["Content-Description"] == nil && h["Content-Disposition"] == nil && !errors.Is(err, xmlsec.ErrMalformed) {
				t.Fatalf("Content: %v", err)
			}
		})
	}
}
