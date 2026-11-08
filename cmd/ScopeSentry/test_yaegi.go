// main-------------------------------------
// @file      : test_yaegi.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/10/17 19:04
// -------------------------------------------

package main

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/symbols"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"os"
	"path/filepath"
)

const src = `package foo

import "github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"

func Bar(s string) string {
	logger.SlogInfoLocal("system config load begin")
	return s + "-Foo"
}
`

func main() {
	logger.NewLogger()
	// Get executable directory
	execPath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	execDir := filepath.Dir(execPath)
	fmt.Printf("Executable directory: %s\n", execDir)

	// Set GOPATH environment variable
	goPath := execDir

	// Initialize yaegi interpreter
	interp := interp.New(interp.Options{
		GoPath: goPath, // Set GoPath to the one from the environment variables GOPATH
	})

	// Load standard library and symbols
	interp.Use(stdlib.Symbols)
	interp.Use(symbols.Symbols)

	// Load plugin
	pluginPath := filepath.Join(execDir, "plugins", "demo.go")
	fmt.Printf("Loading plugin from: %s\n", pluginPath) // Print plugin path to confirm
	_, err = interp.EvalPath(pluginPath)
	if err != nil {
		panic(err)
	}

	// Get foo.Bar function
	v, err := interp.Eval("foo.Bar")
	if err != nil {
		panic(err)
	}

	// Convert value to function
	bar := v.Interface().(func(interface{}) string)

	// Call Bar function
	r := bar("ddddd")
	fmt.Println(r) // Output: Kung-Foo
}
