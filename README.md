# cspheader

This library aims to be a quality of life improvement when dealing with 
setting [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) headers in the Go programming language.

## Usage 

For a quick demo, import cspheader and output a default configuration:

```
...
headerMap, _ := cspheaders.SecurityOptionsReactJS().Load()
fmt.Println(headerMap)
...

/*
// don't mind the formatting, please:
map[
    Content-Security-Policy:
        script-src 'self' 'strict-dynamic'; 
        base-uri 'none'; 
        form-action 'self'; 
        frame-ancestors 'none'; 
        report-to default; 
        default-src 'none'; 
        style-src-attr 'self' 'unsafe-inline'; 
    Report-To:{"group":"default","max_age": 86400, "endpoints": [{"url":"/_/csp-reports" }]}
]
*/
```

From there, you can simply provide the key/value mappings to `http.ResponseWriter's Header().Set()`'s functionality.

## development / contribution

Pull requests or GitHub issues are welcomed.

If you are creating a pull request, please include tests as well as a description of the problem being solved.

If you are opening a GitHub issue, please include any error messages steps to reproduce the issue you encountered.