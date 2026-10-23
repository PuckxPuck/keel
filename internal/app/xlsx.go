//go:build !noxlsx

package app

import "github.com/PuckxPuck/keel/internal/kit/xlsx"

// XLSXConfig is APP_XLSX_*: the limits spreadsheets are read and written within.
type XLSXConfig = xlsx.Config
