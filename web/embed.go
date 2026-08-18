// Package web 前端靜態資源 embed。
package web

import "embed"

// Static 嵌入式前端文件（index.html 單頁）。
//
//go:embed index.html
var Static embed.FS
