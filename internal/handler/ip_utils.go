package handler

import (
	"net"
	"strings"
)

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	ip = strings.Trim(ip, "[]") // remove bracket

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // return as is if not parsed, let DB handle validation
	}

	return parsed.String()
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return normalizeIP(addr)
	}
	return normalizeIP(host)
}
