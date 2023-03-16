package cspheader

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
)

/*
This code helps in configuring Content Security Policies.  Content Security Policies are communications from the
server to CSP-aware browser to cooperating in helping keep users safe from exploits and malicious actors.

The default expectation is the policy in a header, but a <meta> element is supported by browsers as well.

The general syntax is a semicolon separated list of policy-directives:

	Content-Security-Policy: <policy-directive>; <policy-directive>

where `<policy-directive>` consists of: `<directive> <value>` with no internal punctuation.  multiple values are space separated.

e.g.:  default-src 'self' *.tristanfisher.com;object-src 'none';

https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#syntax

A full list of directives can be found here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#directives

Resources:
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
- https://csp.withgoogle.com/docs/strict-csp.html
- https://report-uri.com/home/generate
*/

// Policy is a list of the directives that make up our CSP.
type Policy struct {
	SourceOptionTemplateText string
	SourceOptionTemplate     *template.Template

	SandboxOptionTemplateText string
	SandboxOptionTemplate     *template.Template

	FrameAncestorOptionsTemplateText string
	FrameAncestorOptionsTemplate     *template.Template

	UnquotedOptionsTextTemplateText string
	UnquotedOptionsTemplate         *template.Template

	UnquotedOptionTextTemplateText string
	UnquotedOptionTemplate         *template.Template

	// parsed csp and report-to are stored separately for future usage
	// in per-page generation without having to parse an entire CSP
	cspString      string
	reportToString string

	cspStaticDirectives map[string]string
	// cspDynamicDirectives is for per-page
	cspDynamicDirectives map[string]string

	CSP struct {
		// Fetch directives

		// DefaultSrc is used when a fetch directive is absent
		// note that 'self' includes the scheme (e.g. https://)
		DefaultSrc CSPSourceOptions

		// ChildSrc controls web workers and embedded frames, such as
		// embedding videos from other domains
		ChildSrc    CSPSourceOptions
		ConnectSrc  CSPSourceOptions
		FontSrc     CSPSourceOptions
		FrameSrc    CSPSourceOptions
		ImgSrc      CSPSourceOptions
		ManifestSrc CSPSourceOptions
		MediaSrc    CSPSourceOptions
		ObjectSrc   CSPSourceOptions
		PrefetchSrc CSPSourceOptions
		// ScriptSrc is likely of specific interest
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#examples
		ScriptSrc     CSPSourceOptions
		ScriptSrcElem CSPSourceOptions
		ScriptSrcAttr CSPSourceOptions
		StyleSrc      CSPSourceOptions
		StyleSrcElem  CSPSourceOptions
		StyleSrcAttr  CSPSourceOptions
		WorkerSrc     CSPSourceOptions

		// Document directives
		BaseURI CSPSourceOptions
		Sandbox SandboxOptions

		// Navigation directives
		FormAction     CSPSourceOptions
		FrameAncestors FrameAncestorOptions
		// NavigateTo (CSPSourceOptions) is experimental and doesn't look like it will be supported, so don't bother

		// Reporting directives
		// ReportURI is deprecated, but still required for firefox
		ReportURI UnquotedOptions
		// ReportTo is the more modern reporting option for SecurityPolicyViolationEvent: https://w3c.github.io/reporting/
		// it requires and references a ReportTo keyed header value
		ReportTo UnquotedOption

		// 'Other' directives
		UpgradeInsecureRequests bool
	}

	// ReportTo are sent at the browser's leisure; reports may not be sent immediately
	ReportTo struct {
		// Report-To is the configuration for report-to in the Content-Security-Policy header (604800 is a week)
		// example: Report-To: {"group": "catchAll-endpoint", "max-age": 604800, "endpoints: [ {"url": "https://localhost.localdomain/csp-reports"} ]}
		ReportTo string
	}
}

// Load parses, roughly error-checks, and converts a Policy object into a map of headers that can be set
// CSP steps across a single header key boundary when using 'report-to'
func (pol Policy) Load() (map[string]string, error) {
	var err error

	// Default templates

	if len(pol.SourceOptionTemplateText) == 0 {
		pol.SourceOptionTemplateText = TemplateTextSourceOption
	}

	if len(pol.SandboxOptionTemplateText) == 0 {
		pol.SandboxOptionTemplateText = TemplateTextSandbox
	}

	if len(pol.FrameAncestorOptionsTemplateText) == 0 {
		pol.FrameAncestorOptionsTemplateText = TemplateTextFrameAncestorOptions
	}

	if len(pol.UnquotedOptionsTextTemplateText) == 0 {
		pol.UnquotedOptionsTextTemplateText = TemplateTextUnquotedOptions
	}

	if len(pol.UnquotedOptionTextTemplateText) == 0 {
		pol.UnquotedOptionTextTemplateText = TemplateTextUnquotedOption
	}

	// Whether we used our default template texts or not, parse onto a *Template

	pol.SourceOptionTemplate, err = template.New("SourceOption").Parse(pol.SourceOptionTemplateText)
	if err != nil {
		return nil, err
	}

	pol.SandboxOptionTemplate, err = template.New("Sandbox").Parse(pol.SandboxOptionTemplateText)
	if err != nil {
		return nil, err
	}

	pol.FrameAncestorOptionsTemplate, err = template.New("FrameAncestorOptions").Parse(pol.FrameAncestorOptionsTemplateText)
	if err != nil {
		return nil, err
	}

	pol.UnquotedOptionsTemplate, err = template.New("UnquotedOptions").Parse(pol.UnquotedOptionsTextTemplateText)
	if err != nil {
		return nil, err
	}

	pol.UnquotedOptionTemplate, err = template.New("UnquotedOption").Parse(pol.UnquotedOptionTextTemplateText)
	if err != nil {
		return nil, err
	}

	// pre-flight

	// compound checks
	if len(pol.CSP.ReportTo.Value) != 0 {
		if len(pol.ReportTo.ReportTo) == 0 {
			// a strong argument could be made that we do not want check this as a user could be configuring this
			// external to CSP
			return nil, errors.New("report-to is required if Content-Security-Policy: report-to <value> is set")
		}

		// look into pol.ReportTo.ReportTo for a matching csp.report-to
		if !strings.Contains(pol.ReportTo.ReportTo, pol.CSP.ReportTo.Value) {
			return nil, errors.New("report-to target not found")
		}
	}

	pol.cspDynamicDirectives = map[string]string{}
	pol.cspStaticDirectives = map[string]string{}

	// tracked separately for comparison down to default-src
	// default-src is handled explicitly outside of a loop
	sourceOptFetchDirectives := map[string]CSPSourceOptions{
		// Fetch directives
		"child-src":       pol.CSP.ChildSrc,
		"connect-src":     pol.CSP.ConnectSrc,
		"font-src":        pol.CSP.FontSrc,
		"frame-src":       pol.CSP.FrameSrc,
		"img-src":         pol.CSP.ImgSrc,
		"manifest-src":    pol.CSP.ManifestSrc,
		"media-src":       pol.CSP.MediaSrc,
		"object-src":      pol.CSP.ObjectSrc,
		"prefetch-src":    pol.CSP.PrefetchSrc,
		"script-src":      pol.CSP.ScriptSrc,
		"script-src-elem": pol.CSP.ScriptSrcElem,
		"script-src-attr": pol.CSP.ScriptSrcAttr,
		"style-src":       pol.CSP.StyleSrc,
		"style-src-elem":  pol.CSP.StyleSrcElem,
		"style-src-attr":  pol.CSP.StyleSrcAttr,
		"worker-src":      pol.CSP.WorkerSrc,
	}
	sourceOptNonFetchDirectives := map[string]CSPSourceOptions{
		// Document directives
		"base-uri": pol.CSP.BaseURI,

		// Navigation directives
		"form-action": pol.CSP.FormAction,
	}

	pol.cspStaticDirectives["default-src"], err = pol.CSP.DefaultSrc.Parse(pol.SourceOptionTemplate)
	if err != nil {
		return nil, err
	}

	// range over our fetch directives and remove any settings that match our default exactly.
	// this prevents a bunch 'none' from being a repeat value for a directive on secure policies
	for k, v := range sourceOptFetchDirectives {

		policyDirectiveText, err := v.Parse(pol.SourceOptionTemplate)
		if err != nil {
			return nil, err
		}
		// if the policy would be redundant...
		if pol.cspStaticDirectives["default-src"] == policyDirectiveText {
			continue
		}

		// these options are unique per page load or script tag.  set aside for efficient
		// generation when the user wants to do a per-page load.  this allows for generation of a total
		// CSP and then swapping out only the string portion that includes hashes or nonces.
		if len(v.NonceBase64Value) > 0 || len(v.HashAlgorithmBase64Value) > 0 {
			pol.cspDynamicDirectives[k] = policyDirectiveText
			continue
		}
		pol.cspStaticDirectives[k] = policyDirectiveText
	}

	for k, v := range sourceOptNonFetchDirectives {
		// these options are unique per page load or script tag.  set aside for efficient
		// generation when the user wants to do a per-page load.  this allows for generation of a total
		// CSP and then swapping out only the string portion that includes hashes or nonces.
		if len(v.NonceBase64Value) > 0 || len(v.HashAlgorithmBase64Value) > 0 {
			pol.cspDynamicDirectives[k], err = v.Parse(pol.SourceOptionTemplate)
			if err != nil {
				return nil, err
			}
			continue
		}
		pol.cspStaticDirectives[k], err = v.Parse(pol.SourceOptionTemplate)
		if err != nil {
			return nil, err
		}
	}

	// Document directives
	pol.cspStaticDirectives["sandbox"], err = pol.CSP.Sandbox.Parse(pol.SandboxOptionTemplate)
	if err != nil {
		return nil, err
	}

	// Navigation directives
	pol.cspStaticDirectives["frame-ancestors"], err = pol.CSP.FrameAncestors.Parse(pol.FrameAncestorOptionsTemplate)
	if err != nil {
		return nil, err
	}

	//Reporting directives
	pol.cspStaticDirectives["report-uri"], err = pol.CSP.ReportURI.Parse(pol.UnquotedOptionsTemplate)
	if err != nil {
		return nil, err
	}

	pol.cspStaticDirectives["report-to"], err = pol.CSP.ReportTo.Parse(pol.UnquotedOptionTemplate)
	if err != nil {
		return nil, err
	}

	//
	// 'Other' directives
	pol.cspStaticDirectives["upgrade-insecure-requests"] = ""
	if pol.CSP.UpgradeInsecureRequests {
		pol.cspStaticDirectives["upgrade-insecure-requests"] = "upgrade-insecure-requests"
	}

	// probably a way to do this without this allocation.  we just don't want a trailing space.
	activeCSPs := make([]string, 0)
	// flatten out static and dynamic directives into resultantCSP.  only include keys where there is a value.
	for k, v := range pol.cspStaticDirectives {
		if len(v) == 0 {
			continue
		}
		activeCSPs = append(activeCSPs, fmt.Sprintf("%s %s;", k, v))
	}
	for k, v := range pol.cspDynamicDirectives {
		if len(v) == 0 {
			continue
		}
		activeCSPs = append(activeCSPs, fmt.Sprintf("%s %s;", k, v))
	}
	resultantCSP := strings.Join(activeCSPs, " ")

	cspTable := make(map[string]string, 0)
	cspTable["Content-Security-Policy"] = resultantCSP
	if len(pol.ReportTo.ReportTo) > 0 {
		cspTable["Report-To"] = pol.ReportTo.ReportTo
	}

	return cspTable, nil
}
