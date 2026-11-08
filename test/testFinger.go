// main-------------------------------------
// @file      : testFinger.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2026/1/16 21:31
// -------------------------------------------

package main

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/configupdater"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"gopkg.in/yaml.v3"
)

func main() {
	var fingers []*types.Fingerprint
	var tmpFinger types.FingerprintYaml
	err := yaml.Unmarshal([]byte(`fingerprint:
  name: sky-Router
  category: Router
  parent_category: Network Device
  company: Sky UK
  rules:
  - logic: AND
    conditions:
    - location: header
      match_type: contains
      pattern: realm="SKY Router
  - logic: OR
    conditions:
    - location: header
      match_type: contains
      pattern: realm="SKY Router
    - logic: AND
      conditions:
      - logic: AND
        conditions:
        - location: header
          match_type: contains
          pattern: 'Server: bbdddb'
        - logic: AND
          conditions:
          - location: header
            match_type: not_contains
            pattern: couchdb
          - location: header
            match_type: not_contains
            pattern: drupal
      - logic: AND
        conditions:
        - location: header
          match_type: contains
          pattern: 'Server: aaa'
        - logic: AND
          conditions:
          - location: header
            match_type: not_contains
            pattern: couchdb
          - location: header
            match_type: not_contains
            pattern: drupal
`), &tmpFinger)
	if err != nil {
		fmt.Println(err)
	}
	fingers = append(fingers, &tmpFinger.Fingerprint)
	fmt.Printf("✓ loaded %d fingerprint files successfully\n", len(fingers))
	fmt.Println("\n start building Aho-Corasick automaton...")
	matcher := configupdater.BuildACMatcher(fingers)
	fmt.Printf("<UNK> <UNK> %d <UNK>\n", len(matcher.NonACFingerprints))
}
