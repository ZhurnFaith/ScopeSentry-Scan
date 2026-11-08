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
	// 收集命中的指纹（按ID去重）
	matchedFingerprintsMap := make(map[string]*types.Fingerprint) // key: fingerprintID

	// 获取 matcher 引用，避免在函数执行过程中 global.WebFingers 被修改
	var matcher *types.ACMatcher
	if global.WebFingers == nil || global.WebFingers.ACMatcher == nil {
		return []*types.Fingerprint{}
	}
	matcher = global.WebFingers.ACMatcher

	// 匹配title并收集指纹
	if matcher.TitleMatcher != nil {
		titleRune := []rune(testTitle)
		titleMatches := matcher.TitleMatcher.MultiPatternSearch(titleRune, false)
		for _, term := range titleMatches {
			// 根据匹配到的Word（[]rune）找到对应的pattern索引
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

	// 匹配header并收集指纹
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

	// 匹配body并收集指纹
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

	// 转换为切片并返回
	result := make([]*types.Fingerprint, 0, len(matchedFingerprintsMap))
	for _, fp := range matchedFingerprintsMap {
		result = append(result, fp)
	}
	return result
}
