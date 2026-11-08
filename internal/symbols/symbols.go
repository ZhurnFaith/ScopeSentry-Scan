// symbols-------------------------------------
// @file      : symbols.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/10/17 19:03
// -------------------------------------------

//go:generate go install github.com/traefik/yaegi/cmd/yaegi@v0.15.0
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/options
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/bigcache
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/config
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/contextmanager
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/global
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/interfaces
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/notification
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/pool
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/results
//go:generate yaegi extract github.com/ZhurnFaith/ScopeSentry-Scan/internal/types
package symbols

import (
	"github.com/traefik/yaegi/stdlib"
	"reflect"
	"strings"
)

var Symbols = map[string]map[string]reflect.Value{}

func init() {
	// Register common standard library
	for pkg, symbols := range map[string]string{
		"os/exec": "os/exec",
	} {
		Symbols[pkg] = stdlib.Symbols[symbols]
	}
}

const (
	modulePath       = "github.com/ZhurnFaith/ScopeSentry-Scan/"
	legacyModulePath = "github.com/Autumn-27/ScopeSentry-Scan/"
)

// WithLegacyAliases returns the symbol table plus aliases under the old module path,
// so existing plugins importing github.com/Autumn-27/ScopeSentry-Scan/... still load.
func WithLegacyAliases() map[string]map[string]reflect.Value {
	out := make(map[string]map[string]reflect.Value, len(Symbols)*2)
	for k, v := range Symbols {
		out[k] = v
		if strings.HasPrefix(k, modulePath) {
			out[legacyModulePath+strings.TrimPrefix(k, modulePath)] = v
		}
	}
	return out
}
