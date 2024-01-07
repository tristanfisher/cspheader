package cspheader

// SecurityOptionsReactJS returns a Policy set generally agreeable for React applications
func SecurityOptionsReactJS() Policy {
	securityOptions := Policy{}

	// Fetch directives
	// default-src to none intentionally.  default even of self opens a door for many elements.
	securityOptions.CSP.DefaultSrc = CSPSourceOptions{Allow: false}

	// strict-dynamic allows scripts to be dynamically added to the page as long as loaded by an already trusted script
	// unsafe-inline required for react unless the follow are set in the "build":
	// - INLINE_RUNTIME_CHUNK=false
	// - IMAGE_INLINE_SIZE_LIMIT=false
	securityOptions.CSP.ScriptSrc = CSPSourceOptions{Allow: true, AllowSelf: true}
	// unsafe-inline required for react
	securityOptions.CSP.StyleSrcAttr = CSPSourceOptions{Allow: true, AllowSelf: true, UnsafeInline: true}

	// Document directives
	securityOptions.CSP.BaseURI = CSPSourceOptions{Allow: false} // disabled

	// Navigation directives
	securityOptions.CSP.FormAction = CSPSourceOptions{Allow: true, AllowSelf: true} // don't allow submitting forms to other domains

	// Reporting directives
	securityOptions.CSP.ReportTo = UnquotedOption{Value: "default"}
	// Report-to header key
	// /_/csp_reports means self+/_/csp_reports
	securityOptions.ReportTo.ReportTo = `{"group":"default","max_age": 86400, "endpoints": [{"url":"/_/csp-reports" }]}`
	return securityOptions
}
