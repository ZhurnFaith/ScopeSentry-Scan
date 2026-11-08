// types-------------------------------------
// @file      : finger.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/28 23:11
// -------------------------------------------

package types

import goahocorasick "github.com/anknown/ahocorasick"

// Fingerprint fingerprint definition
type Fingerprint struct {
	Name           string   `yaml:"name"`
	ID             string   `yaml:"id"`
	Tags           []string `yaml:"tags"` // Associate POC
	Category       string   `yaml:"category"`
	ParentCategory string   `yaml:"parent_category"`
	Company        string   `yaml:"company"`
	Rules          []Rule   `yaml:"rules"`
}

type FingerprintYaml struct {
	Fingerprint Fingerprint `yaml:"fingerprint"`
}

// Rule rule definition
type Rule struct {
	Logic      string      `yaml:"logic"` // AND or OR
	Conditions []Condition `yaml:"conditions"`
}

// Condition condition definition (supports regular conditions and nested condition groups)
type Condition struct {
	// Regular condition field
	Location    string `yaml:"location,omitempty"`   // body, header, title, request
	MatchType   string `yaml:"match_type,omitempty"` // regex, contains, extract, active
	Pattern     string `yaml:"pattern,omitempty"`
	Group       int    `yaml:"group,omitempty"`
	SaveAs      string `yaml:"save_as,omitempty"`
	Path        string `yaml:"path,omitempty"`
	DynamicPath string `yaml:"dynamic_path,omitempty"`
	Method      string `yaml:"method,omitempty"`

	// Nested condition group field
	Logic      string      `yaml:"logic,omitempty"`      // AND or OR (for nested groups)
	Conditions []Condition `yaml:"conditions,omitempty"` // Sub-condition or nested group
}

type PatternInfo struct {
	Pattern       string // pattern string
	Location      string // title, header, body
	FingerprintID string // Associated fingerprint ID (saves memory, avoids storing Fingerprint pointers repeatedly)
	RuleIndex     int    // Associated rule index
}

type WebFingerCore struct {
	ACMatcher *ACMatcher
}

type ACMatcher struct {
	TitleMatcher   *goahocorasick.Machine
	HeaderMatcher  *goahocorasick.Machine
	BodyMatcher    *goahocorasick.Machine
	TitlePatterns  []PatternInfo
	HeaderPatterns []PatternInfo
	BodyPatterns   []PatternInfo
	// Pattern to index mapping (to find PatternInfo from match results)
	TitlePatternMap  map[string]int // pattern string -> PatternInfo index
	HeaderPatternMap map[string]int
	BodyPatternMap   map[string]int
	// Fingerprint ID to Fingerprint mapping (saves memory, avoids storing it repeatedly in PatternInfo)
	FingerprintMap map[string]*Fingerprint // fingerprintID -> Fingerprint
	// List of fingerprints that cannot use Aho-Corasick
	NonACFingerprints []*Fingerprint
}
