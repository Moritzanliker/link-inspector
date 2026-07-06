// Package api holds the OpenAPI spec and the vendored Scalar reference
// viewer (version pinned in scalar.version), embedded so the compiled
// binary serves its own documentation without CDN or filesystem access.
package api

import _ "embed"

// OpenAPISpec is the OpenAPI 3.0 description of the LinkCheck API.
//
//go:embed openapi.yaml
var OpenAPISpec []byte

// ScalarJS is the standalone browser bundle of @scalar/api-reference.
//
//go:embed scalar.standalone.min.js
var ScalarJS []byte
