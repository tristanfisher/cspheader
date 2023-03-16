package cspheader

import (
	"bytes"
	"text/template"
)

// CSPSourceOptions represent CSP source values.
// Definition here:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/Sources#sources
type CSPSourceOptions struct {
	Allow     bool // Overrides all other settings! set 'none'?
	AllowSelf bool // 'self'?
	// <host-source>, <scheme-source>, etc
	Values         []string
	UnsafeEval     bool // 'unsafe-eval'?
	WasmUnsafeEval bool // 'wasm-unsafe-eval'?
	UnsafeHashes   bool // 'unsafe-hashes'?
	UnsafeInline   bool // 'unsafe-inline'?
	// https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/nonce
	NonceBase64Value         string // If not empty, 'nonce-<base64-value>'? (set unique each time!)
	HashAlgorithmBase64Value string // If not empty, '<hash-algorithm>-<base64-value>'?
	StrictDynamic            bool   // 'strict-dynamic'?
	ReportSample             bool   // 'report-sample'?
}

func (cso CSPSourceOptions) Parse(tmpl *template.Template) (string, error) {
	var cspBytes bytes.Buffer
	err := tmpl.Execute(&cspBytes, cso)
	if err != nil {
		return "", err
	}
	return cspBytes.String(), nil
}

// UnquotedOption is an unquoted singular value
type UnquotedOption struct {
	Value string // unquoted
}

func (uv UnquotedOption) Parse(tmpl *template.Template) (string, error) {
	var cspBytes bytes.Buffer
	err := tmpl.Execute(&cspBytes, uv)
	if err != nil {
		return "", err
	}
	return cspBytes.String(), nil
}

// UnquotedOptions is for one or more unquoted values
type UnquotedOptions struct {
	Values []string
}

func (uvs UnquotedOptions) Parse(tmpl *template.Template) (string, error) {
	var cspBytes bytes.Buffer
	err := tmpl.Execute(&cspBytes, uvs)
	if err != nil {
		return "", err
	}
	return cspBytes.String(), nil
}

type SandboxOptions struct {
	AllowDownloads                      bool // allow-downloads
	AllowForms                          bool // allow-forms
	AllowModals                         bool // allow-modals
	AllowOrientationLock                bool // allow-orientation-lock
	AllowPointerLock                    bool // allow-pointer-lock
	AllowPopups                         bool // allow-popups
	AllowPopupsToEscapeSandbox          bool // allow-popups-to-escape-sandbox
	AllowPresentation                   bool // allow-presentation
	AllowSameOrigin                     bool // allow-same-origin
	AllowScripts                        bool // allow-scripts
	AllowTopNavigation                  bool // allow-top-navigation
	AllowTopNavigationByUserActivation  bool // allow-top-navigation-by-user-activation
	AllowTopNavigationToCustomProtocols bool // allow-top-navigation-to-custom-protocols

}

func (so SandboxOptions) Parse(tmpl *template.Template) (string, error) {
	var cspBytes bytes.Buffer
	err := tmpl.Execute(&cspBytes, so)
	if err != nil {
		return "", err
	}
	return cspBytes.String(), nil
}

// FrameAncestorOptions is for one or more unquoted values
type FrameAncestorOptions struct {
	Allow         bool // Overrides all other settings! should we set 'none'?
	AllowSelf     bool // should we put in 'self'?
	HostSources   []string
	SchemeSources []string
}

func (fao FrameAncestorOptions) Parse(tmpl *template.Template) (string, error) {
	var cspBytes bytes.Buffer
	err := tmpl.Execute(&cspBytes, fao)
	if err != nil {
		return "", err
	}
	return cspBytes.String(), nil
}
