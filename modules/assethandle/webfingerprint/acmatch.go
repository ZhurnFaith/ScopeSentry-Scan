// webfingerprint-------------------------------------
// @file      : acmatch.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2025/12/29 22:25
// -------------------------------------------

package webfingerprint

import (
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
)

func AcRun(testTitle, testHeader, testBody string) []*types.Fingerprint {
	// Collect matched fingerprints (deduplicated by ID)
	matchedFingerprintsMap := make(map[string]*types.Fingerprint) // key: fingerprintID

	// Get the matcher reference so global.WebFingers is not modified while the function runs
	var matcher *types.ACMatcher
	if global.WebFingers == nil || global.WebFingers.ACMatcher == nil {
		return []*types.Fingerprint{}
	}
	matcher = global.WebFingers.ACMatcher

	// Match title and collect fingerprints
	if matcher.TitleMatcher != nil {
		titleRune := []rune(testTitle)
		titleMatches := matcher.TitleMatcher.MultiPatternSearch(titleRune, false)
		for _, term := range titleMatches {
			// Find the pattern index for the matched Word ([]rune)
			matchedPattern := string(term.Word)
			if patternIndex, exists := matcher.TitlePatternMap[matchedPattern]; exists {
				if patternIndex >= 0 && patternIndex < len(matcher.TitlePatterns) {
					p := matcher.TitlePatterns[patternIndex]
					if fp, exists := matcher.FingerprintMap[p.FingerprintID]; exists {
						matchedFingerprintsMap[p.FingerprintID] = fp
					}
				}
			}
		}
	}

	// Match header and collect fingerprints
	if matcher.HeaderMatcher != nil {
		headerRune := []rune(testHeader)
		headerMatches := matcher.HeaderMatcher.MultiPatternSearch(headerRune, false)
		for _, term := range headerMatches {
			matchedPattern := string(term.Word)
			if patternIndex, exists := matcher.HeaderPatternMap[matchedPattern]; exists {
				if patternIndex >= 0 && patternIndex < len(matcher.HeaderPatterns) {
					p := matcher.HeaderPatterns[patternIndex]
					if fp, exists := matcher.FingerprintMap[p.FingerprintID]; exists {
						matchedFingerprintsMap[p.FingerprintID] = fp
					}
				}
			}
		}
	}

	// Match body and collect fingerprints
	if matcher.BodyMatcher != nil {
		bodyRune := []rune(testBody)
		bodyMatches := matcher.BodyMatcher.MultiPatternSearch(bodyRune, false)
		for _, term := range bodyMatches {
			matchedPattern := string(term.Word)
			if patternIndex, exists := matcher.BodyPatternMap[matchedPattern]; exists {
				if patternIndex >= 0 && patternIndex < len(matcher.BodyPatterns) {
					p := matcher.BodyPatterns[patternIndex]
					if fp, exists := matcher.FingerprintMap[p.FingerprintID]; exists {
						matchedFingerprintsMap[p.FingerprintID] = fp
					}
				}
			}
		}
	}

	// Convert to slice and return
	result := make([]*types.Fingerprint, 0, len(matchedFingerprintsMap))
	for _, fp := range matchedFingerprintsMap {
		result = append(result, fp)
	}
	return result
}
