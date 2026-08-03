package authzgen

import "strings"

// initialisms are rendered fully upper-case, matching the convention the Go
// style checkers enforce on hand-written code.
var initialisms = map[string]string{
	"acl":  "ACL",
	"api":  "API",
	"cidr": "CIDR",
	"cpu":  "CPU",
	"db":   "DB",
	"http": "HTTP",
	"id":   "ID",
	"ip":   "IP",
	"json": "JSON",
	"jwt":  "JWT",
	"rpc":  "RPC",
	"sql":  "SQL",
	"ttl":  "TTL",
	"uri":  "URI",
	"url":  "URL",
	"uuid": "UUID",
}

// exportedName converts a snake_case or kebab-case model identifier into an
// exported Go identifier.
func exportedName(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '_' || r == '-' })
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		if up, ok := initialisms[strings.ToLower(p)]; ok {
			b.WriteString(up)
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}
