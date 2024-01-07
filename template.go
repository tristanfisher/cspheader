package cspheader

// TemplateTextSourceOption is the default parsing of CSP source options.  Note the intentional whitespace and single quotes.
const TemplateTextSourceOption = "" +
	"{{ if not .Allow }}'none'{{ else }}" +
	"{{ if .AllowSelf }}'self'{{ end }}" +
	"{{ range $v := .Values }} {{$v}}{{ end }}" +
	"{{ if .UnsafeEval }} 'unsafe-eval'{{ end }}" +
	"{{ if .WasmUnsafeEval }} 'wasm-unsafe-eval'{{ end }}" +
	"{{ if .UnsafeHashes }} 'unsafe-hashes'{{ end }}" +
	"{{ if .UnsafeInline }} 'unsafe-inline'{{ end }}" +
	"{{ if gt (len .NonceBase64Value) 0 }}{{ .NonceBase64Value}}{{ end }}" +
	"{{ if gt (len .HashAlgorithmBase64Value) 0 }}{{ .HashAlgorithmBase64Value}}{{ end }}" +
	"{{ if .StrictDynamic }} 'strict-dynamic'{{ end }}" +
	"{{ if .ReportSample }} 'report-sample'{{ end }}" +
	"{{ end }}" // if not .Allow

// TemplateTextSandbox is the default parsing of Sandbox options.  Note the intentional whitespace and no single quotes.
const TemplateTextSandbox = "" +
	"{{ if .AllowDownloads }}allow-downloads{{ end }}" +
	"{{ if .AllowForms }} allow-forms{{ end }}" +
	"{{ if .AllowModals }} allow-modals{{ end }}" +
	"{{ if .AllowOrientationLock }} allow-orientation-lock{{ end }}" +
	"{{ if .AllowPointerLock }} allow-pointer-lock{{ end }}" +
	"{{ if .AllowPopups }} allow-popups{{ end }}" +
	"{{ if .AllowPopupsToEscapeSandbox }} allow-popups-to-escape-sandbox{{ end }}" +
	"{{ if .AllowPresentation }} allow-presentation{{ end }}" +
	"{{ if .AllowSameOrigin }} allow-same-origin{{ end }}" +
	"{{ if .AllowScripts }} allow-scripts{{ end }}" +
	"{{ if .AllowTopNavigation }} allow-top-navigation{{ end }}" +
	"{{ if .AllowTopNavigationByUserActivation }} allow-top-navigation-by-user-activation{{ end }}" +
	"{{ if .AllowTopNavigationToCustomProtocols }} allow-top-navigation-to-custom-protocols{{ end }}"

const TemplateTextFrameAncestorOptions = "" +
	"{{ if not .Allow }}'none'{{ else }}" +
	"{{ if .AllowSelf }}'self'{{ end }}" +
	"{{ range $v := .HostSources }} {{$v}}{{ end }}" +
	"{{ range $v := .SchemeSources }} {{$v}}{{ end }}" +
	"{{ end }}" // if not .Allow

const TemplateTextUnquotedOptions = "{{ range $v := .Values }}{{$v}} {{ end }}"

const TemplateTextUnquotedOption = "{{ .Value }}"
