// configupdater-------------------------------------
// @file      : webfinger.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/29 20:58
// -------------------------------------------

package configupdater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"

	goahocorasick "github.com/anknown/ahocorasick"
	"gopkg.in/yaml.v3"
)

// NewACMatcher create new Aho-Corasick matcher
func NewACMatcher() *types.ACMatcher {
	return &types.ACMatcher{
		TitlePatterns:     make([]types.PatternInfo, 0),
		HeaderPatterns:    make([]types.PatternInfo, 0),
		BodyPatterns:      make([]types.PatternInfo, 0),
		TitlePatternMap:   make(map[string]int),
		HeaderPatternMap:  make(map[string]int),
		BodyPatternMap:    make(map[string]int),
		FingerprintMap:    make(map[string]*types.Fingerprint),
		NonACFingerprints: make([]*types.Fingerprint, 0),
	}
}

// LoadFingerprintsFromDir load all fingerprint files from directory
func LoadFingerprintsFromDir(dirPath string) ([]*types.Fingerprint, error) {
	var fingerprints []*types.Fingerprint

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".yaml") {
			fp, err := LoadFingerprintWithID(path)
			if err != nil {
				// Ignore files that fail to load, continue with others
				return nil
			}
			fingerprints = append(fingerprints, fp)
		}

		return nil
	})

	return fingerprints, err
}

// LoadFingerprintWithID load fingerprint file with IDs
func LoadFingerprintWithID(filepath string) (*types.Fingerprint, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read fingerprint file: %w", err)
	}

	var fingerprint types.Fingerprint
	if err := yaml.Unmarshal(data, &fingerprint); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &fingerprint, nil
}

// extractPatternsFromRule extract from rule patterns
// Return the extracted pattern info list, or an empty list if nothing can be extracted
// For OR condition groups, collects all matching items in the group pattern
// For AND rules, keep all patterns of any OR group; otherwise choose the best one pattern
func extractPatternsFromRule(rule types.Rule, fingerprint *types.Fingerprint, ruleIndex int) []types.PatternInfo {
	// Extract from the rule's conditions patterns
	patterns := extractPatternsFromConditionGroup(rule.Conditions, rule.Logic, fingerprint, ruleIndex)

	if len(patterns) == 0 {
		return nil
	}

	return patterns
}

func isConditionGroup(condition types.Condition) bool {
	return condition.Logic != "" && condition.Location == ""
}

// extractPatternsFromConditionGroup extract patterns from condition groups (recursively handles unlimited nesting)
// logic: logic of the current condition group (AND or OR)
func extractPatternsFromConditionGroup(conditions []types.Condition, logic string, fingerprint *types.Fingerprint, ruleIndex int) []types.PatternInfo {
	var allPatterns []types.PatternInfo

	// Iterate over all conditions
	for _, condition := range conditions {
		// If it is a nested condition group
		if isConditionGroup(condition) {
			// Recursively extract from nested groups patterns
			nestedPatterns := extractPatternsFromConditionGroup(condition.Conditions, condition.Logic, fingerprint, ruleIndex)
			allPatterns = append(allPatterns, nestedPatterns...)
			continue
		}

		// Handle regular conditions: only contains type, with location title/header/body
		if condition.MatchType == "contains" &&
			(condition.Location == "title" || condition.Location == "header" || condition.Location == "body") &&
			condition.Pattern != "" {
			allPatterns = append(allPatterns, types.PatternInfo{
				Pattern:       condition.Pattern,
				Location:      condition.Location,
				FingerprintID: fingerprint.ID,
				RuleIndex:     ruleIndex,
			})
		}
	}

	if len(allPatterns) == 0 {
		return nil
	}

	// Handle by logic type patterns
	if logic == "OR" {
		// OR logic: return all patterns (all patterns in an OR group need matching)
		// Deduplicate: keep only one of identical patterns (by pattern string and location)
		return deduplicatePatterns(allPatterns)
	} else {
		// AND logic: need to check whether it contains items from the OR group patterns
		// If all patterns come from the same OR group (collected recursively), keep them all
		// Otherwise select only the best one pattern

		// Check for OR groups (by checking for multiple patterns with the same priority)
		// Simpler approach: if patterns come from different condition group levels, the best one may need to be chosen
		// But in fact, if an AND group contains an OR group, all patterns of the OR group should be kept
		// If an AND group contains only AND subgroups or regular conditions, choose only the best one

		// Simplified handling: for AND logic, if there is more than one pattern, check whether they come from an OR group
		// Since we cannot tell directly where patterns came from, use a conservative strategy:
		// If an AND group directly or indirectly contains an OR group, keep all patterns
		// Otherwise select only the best one

		// Check whether conditions contain an OR group (recursively)
		hasORGroup := hasORGroupInConditions(conditions)

		if hasORGroup {
			// If it contains an OR group, keep all patterns (all patterns in an OR group need matching)
			return allPatterns
		} else {
			// Otherwise select only the best one pattern
			best := selectBestPattern(allPatterns)
			if best != nil {
				return []types.PatternInfo{*best}
			}
			return nil
		}
	}
}

// hasORGroupInConditions recursively check whether conditions contain an OR condition group
func hasORGroupInConditions(conditions []types.Condition) bool {
	for _, condition := range conditions {
		if isConditionGroup(condition) {
			if condition.Logic == "OR" {
				return true
			}
			// Recursively check nested groups
			if hasORGroupInConditions(condition.Conditions) {
				return true
			}
		}
	}
	return false
}

// hasRequestConditionInConditions recursively check whether conditions contain request conditions
func hasRequestConditionInConditions(conditions []types.Condition) bool {
	for _, condition := range conditions {
		if isConditionGroup(condition) {
			if hasRequestConditionInConditions(condition.Conditions) {
				return true
			}
			continue
		}
		if condition.Location == "request" {
			return true
		}
	}
	return false
}

// deduplicatePatterns deduplicate patterns (by pattern string and location)
func deduplicatePatterns(patterns []types.PatternInfo) []types.PatternInfo {
	if len(patterns) <= 1 {
		return patterns
	}

	seen := make(map[string]bool)
	result := make([]types.PatternInfo, 0, len(patterns))

	for _, p := range patterns {
		key := p.Location + ":" + p.Pattern
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}

	return result
}

// selectBestPattern choose the best pattern by priority and length (for AND logic)
// Priority: title > header > body
// For the same priority, choose the longest
func selectBestPattern(candidates []types.PatternInfo) *types.PatternInfo {
	if len(candidates) == 0 {
		return nil
	}

	// Define priority
	priority := map[string]int{
		"title":  3,
		"header": 2,
		"body":   1,
	}

	var best *types.PatternInfo
	bestPriority := 0
	bestLength := 0

	for i := range candidates {
		candidate := &candidates[i]
		p := priority[candidate.Location]
		length := len(candidate.Pattern)

		// Higher priority, or same priority but longer
		if p > bestPriority || (p == bestPriority && length > bestLength) {
			best = candidate
			bestPriority = p
			bestLength = length
		}
	}

	return best
}

// BuildACMatcher build Aho-Corasick matcher
func BuildACMatcher(fingerprints []*types.Fingerprint) *types.ACMatcher {
	matcher := NewACMatcher()

	// Deduplicate globally with a map, key is location:pattern, value is PatternInfo
	// This avoids adding duplicate patterns to the Aho-Corasick automaton (does not affect match accuracy)
	titlePatternMap := make(map[string]types.PatternInfo)
	headerPatternMap := make(map[string]types.PatternInfo)
	bodyPatternMap := make(map[string]types.PatternInfo)

	// Iterate over all fingerprints to build FingerprintMap (saves memory, avoids storing them repeatedly in PatternInfo)
	for _, fingerprint := range fingerprints {
		matcher.FingerprintMap[fingerprint.ID] = fingerprint
	}

	// Iterate over all fingerprint
	for _, fingerprint := range fingerprints {
		// request the condition depends on active requests and cannot be reliably covered by Aho-Corasick prefiltering on title/header/body alone
		// Once a request condition exists, the whole fingerprint falls back to the non-Aho-Corasick path to avoid misses
		hasRequestCondition := false
		for _, rule := range fingerprint.Rules {
			if hasRequestConditionInConditions(rule.Conditions) {
				hasRequestCondition = true
				break
			}
		}
		if hasRequestCondition {
			matcher.NonACFingerprints = append(matcher.NonACFingerprints, fingerprint)
			continue
		}

		// First check whether all rules can be extracted pattern
		allRulesHavePattern := true
		allRulePatterns := make([][]types.PatternInfo, 0, len(fingerprint.Rules))

		// Iterate over each rule, try to extract patterns
		for ruleIndex, rule := range fingerprint.Rules {
			patterns := extractPatternsFromRule(rule, fingerprint, ruleIndex)
			if len(patterns) == 0 {
				// If any rule cannot extract a pattern, mark it as false
				allRulesHavePattern = false
				// Do not break immediately, keep checking other rules for debugging
				break
			} else {
				allRulePatterns = append(allRulePatterns, patterns)
			}
		}

		// Add to the Aho-Corasick automaton only if all rules yield a pattern
		if !allRulesHavePattern {
			// If any rule cannot yield a pattern, put the whole fingerprint in the non-Aho-Corasick list
			matcher.NonACFingerprints = append(matcher.NonACFingerprints, fingerprint)
			continue
		}

		// Add to the Aho-Corasick automaton only if all rules yield a pattern
		if allRulesHavePattern && len(allRulePatterns) > 0 {
			// Add every rule's patterns to the corresponding map (deduplicate only, no length filtering, to avoid misses)
			for _, rulePatterns := range allRulePatterns {
				for _, patternInfo := range rulePatterns {
					key := patternInfo.Location + ":" + patternInfo.Pattern

					switch patternInfo.Location {
					case "title":
						// Global deduplication: if it already exists, keep the first (each pattern kept once, does not affect matching)
						if _, exists := titlePatternMap[key]; !exists {
							titlePatternMap[key] = patternInfo
						}
					case "header":
						if _, exists := headerPatternMap[key]; !exists {
							headerPatternMap[key] = patternInfo
						}
					case "body":
						if _, exists := bodyPatternMap[key]; !exists {
							bodyPatternMap[key] = patternInfo
						}
					}
				}
			}
		} else {
			// If any rule cannot yield a pattern, put the whole fingerprint in the non-Aho-Corasick list
			matcher.NonACFingerprints = append(matcher.NonACFingerprints, fingerprint)
		}
	}

	// Convert the map to a slice and build the patterns list for the Aho-Corasick automaton
	titlePatterns := make([]string, 0, len(titlePatternMap))
	headerPatterns := make([]string, 0, len(headerPatternMap))
	bodyPatterns := make([]string, 0, len(bodyPatternMap))

	for _, patternInfo := range titlePatternMap {
		matcher.TitlePatterns = append(matcher.TitlePatterns, patternInfo)
		titlePatterns = append(titlePatterns, patternInfo.Pattern)
	}

	for _, patternInfo := range headerPatternMap {
		matcher.HeaderPatterns = append(matcher.HeaderPatterns, patternInfo)
		headerPatterns = append(headerPatterns, patternInfo.Pattern)
	}

	for _, patternInfo := range bodyPatternMap {
		matcher.BodyPatterns = append(matcher.BodyPatterns, patternInfo)
		bodyPatterns = append(bodyPatterns, patternInfo.Pattern)
	}

	// Clean up temporary map
	titlePatternMap = nil
	headerPatternMap = nil
	bodyPatternMap = nil

	// Build the Aho-Corasick automaton (Double-Array Trie implementation, very low memory)

	// Convert string patterns to [][]rune and build the pattern-to-index map
	if len(titlePatterns) > 0 {
		// Build mapping from pattern to index
		for i, pattern := range titlePatterns {
			matcher.TitlePatternMap[pattern] = i
		}

		// Convert to [][]rune
		titlePatternsRune := make([][]rune, len(titlePatterns))
		for i, pattern := range titlePatterns {
			titlePatternsRune[i] = []rune(pattern)
		}

		// Build Double-Array Trie Aho-Corasick automaton
		matcher.TitleMatcher = &goahocorasick.Machine{}
		if err := matcher.TitleMatcher.Build(titlePatternsRune); err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("Failed to build Title Aho-Corasick automaton: %v", err))
		}

		titlePatternsRune = nil
	}

	if len(headerPatterns) > 0 {
		// Build mapping from pattern to index
		for i, pattern := range headerPatterns {
			matcher.HeaderPatternMap[pattern] = i
		}

		// Convert to [][]rune
		headerPatternsRune := make([][]rune, len(headerPatterns))
		for i, pattern := range headerPatterns {
			headerPatternsRune[i] = []rune(pattern)
		}

		// Build Double-Array Trie Aho-Corasick automaton
		matcher.HeaderMatcher = &goahocorasick.Machine{}
		if err := matcher.HeaderMatcher.Build(headerPatternsRune); err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("Failed to build Header Aho-Corasick automaton: %v", err))
		}

		headerPatternsRune = nil
	}

	if len(bodyPatterns) > 0 {
		// Build mapping from pattern to index
		for i, pattern := range bodyPatterns {
			matcher.BodyPatternMap[pattern] = i
		}

		// Convert to [][]rune
		bodyPatternsRune := make([][]rune, len(bodyPatterns))
		for i, pattern := range bodyPatterns {
			bodyPatternsRune[i] = []rune(pattern)
		}

		// Build Double-Array Trie Aho-Corasick automaton
		matcher.BodyMatcher = &goahocorasick.Machine{}
		if err := matcher.BodyMatcher.Build(bodyPatternsRune); err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("Failed to build Body Aho-Corasick automaton: %v", err))
		}

		bodyPatternsRune = nil
	}

	// Clean up temporary data
	titlePatterns = nil
	headerPatterns = nil
	bodyPatterns = nil

	return matcher
}

//
//func main() {
//	//test_main()
//	// Load all fingerprint files from the fingers folder
//	fmt.Println("Start loading fingerprint file...")
//	fingerprints, err := LoadFingerprintsFromDir("fingers")
//	if err != nil {
//		log.Fatalf("Failed to load fingerprint file: %v", err)
//	}
//	fmt.Printf("✓ loaded %d fingerprint files successfully\n", len(fingerprints))
//
//	// Build Aho-Corasick automaton
//	fmt.Println("\n start building Aho-Corasick automaton...")
//	matcher := BuildACMatcher(fingerprints)
//	//
//	//// Statistics
//	//totalFingerprints := len(fingerprints)
//	//acFingerprints := totalFingerprints - len(matcher.NonACFingerprints)
//	//nonACFingerprints := len(matcher.NonACFingerprints)
//	//
//	//// Output statistics
//	//fmt.Println("\n" + strings.Repeat("=", 60))
//	//fmt.Println("AC automaton built - statistics")
//	//fmt.Println(strings.Repeat("=", 60))
//	//fmt.Printf("Total fingerprints:        %d\n", totalFingerprints)
//	//fmt.Printf("Fingerprints that can use Aho-Corasick:   %d (%.2f%%)\n", acFingerprints, float64(acFingerprints)/float64(totalFingerprints)*100)
//	//fmt.Printf("Fingerprints that cannot use Aho-Corasick:   %d (%.2f%%)\n", nonACFingerprints, float64(nonACFingerprints)/float64(totalFingerprints)*100)
//	//fmt.Println(strings.Repeat("=", 60))
//	//
//	//// Pattern statistics
//	//fmt.Printf("\nPattern statistics:\n")
//	//fmt.Printf("  Title patterns:  %d\n", len(matcher.TitlePatterns))
//	//fmt.Printf("  Header patterns: %d\n", len(matcher.HeaderPatterns))
//	//fmt.Printf("  Body patterns:   %d\n", len(matcher.BodyPatterns))
//	//fmt.Printf("  total patterns:      %d\n", len(matcher.TitlePatterns)+len(matcher.HeaderPatterns)+len(matcher.BodyPatterns))
//
//	// Optionally output the list of fingerprints that cannot use Aho-Corasick
//	//if nonACFingerprints > 0 && nonACFingerprints <= 20 {
//	//	fmt.Printf("\n fingerprints that cannot use Aho-Corasick (first %d):\n", nonACFingerprints)
//	//	for i, fp := range matcher.NonACFingerprints {
//	//		if i >= 20 {
//	//			break
//	//		}
//	//		fmt.Printf("  [%d] %s (ID: %s)\n", i+1, fp.Name, fp.ID)
//	//	}
//	//} else if nonACFingerprints > 20 {
//	//	fmt.Printf("\n fingerprints that cannot use Aho-Corasick (first 20):\n")
//	//	for i := 0; i < 20 && i < len(matcher.NonACFingerprints); i++ {
//	//		fp := matcher.NonACFingerprints[i]
//	//		fmt.Printf("  [%d] %s (ID: %s)\n", i+1, fp.Name, fp.ID)
//	//	}
//	//	fmt.Printf("  ... %d fingerprints still cannot be used AC\n", nonACFingerprints-20)
//	//}
//
//	// Match test
//	fmt.Println("\n" + strings.Repeat("=", 60))
//	fmt.Println("AC automaton match test")
//	fmt.Println(strings.Repeat("=", 60))
//
//	// Test data (change these values to test)
//	testTitle := "D-Link DSL-2640B next-generation firewall security gateway"
//	testHeader := "Server: mini_httpd\nContent-Type: text/html Server: AvigilonGateway"
//	testBody := "Product : DSL-2640B"
//
//	fmt.Printf("Test data:\n")
//	fmt.Printf("  Title:  %q\n", testTitle)
//	fmt.Printf("  Header: %q\n", testHeader)
//	fmt.Printf("  Body:   %q\n", testBody)
//
//	// Collect matched fingerprints (deduplicated by ID)
//	type MatchedFingerprint struct {
//		FingerprintID   string
//		FingerprintName string
//		MatchedRules    []int // List of matched rule indexes
//	}
//
//	matchedFingerprintsMap := make(map[string]*MatchedFingerprint) // key: fingerprintID
//
//	// Match title and collect fingerprints
//	if matcher.TitleMatcher != nil {
//		titleMatches := matcher.TitleMatcher.Match([]byte(testTitle))
//		for _, patternIndex := range titleMatches {
//			if patternIndex < len(matcher.TitlePatterns) {
//				p := matcher.TitlePatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// Check whether ruleIndex already exists
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// Match header and collect fingerprints
//	if matcher.HeaderMatcher != nil {
//		headerMatches := matcher.HeaderMatcher.Match([]byte(testHeader))
//		for _, patternIndex := range headerMatches {
//			if patternIndex < len(matcher.HeaderPatterns) {
//				p := matcher.HeaderPatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// Check whether ruleIndex already exists
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// Match body and collect fingerprints
//	if matcher.BodyMatcher != nil {
//		bodyMatches := matcher.BodyMatcher.Match([]byte(testBody))
//		for _, patternIndex := range bodyMatches {
//			if patternIndex < len(matcher.BodyPatterns) {
//				p := matcher.BodyPatterns[patternIndex]
//				if fp, exists := matchedFingerprintsMap[p.Fingerprint.ID]; exists {
//					// Check whether ruleIndex already exists
//					ruleExists := false
//					for _, ruleIdx := range fp.MatchedRules {
//						if ruleIdx == p.RuleIndex {
//							ruleExists = true
//							break
//						}
//					}
//					if !ruleExists {
//						fp.MatchedRules = append(fp.MatchedRules, p.RuleIndex)
//					}
//				} else {
//					matchedFingerprintsMap[p.Fingerprint.ID] = &MatchedFingerprint{
//						FingerprintID:   p.Fingerprint.ID,
//						FingerprintName: p.Fingerprint.Name,
//						MatchedRules:    []int{p.RuleIndex},
//					}
//				}
//			}
//		}
//	}
//
//	// Output match results
//	fmt.Printf("\n match result:\n")
//	fmt.Printf("  matched fingerprints: %d (after deduplication by ID)\n", len(matchedFingerprintsMap))
//
//	if len(matchedFingerprintsMap) > 0 {
//		fmt.Println("\n list of matched fingerprint IDs:")
//		// Only output deduplicated ID
//		for _, fp := range matchedFingerprintsMap {
//			fmt.Printf("  %s\n", fp.FingerprintID)
//		}
//	} else {
//		fmt.Println("  no fingerprint matched")
//	}
//}
