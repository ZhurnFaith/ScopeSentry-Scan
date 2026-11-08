// results-------------------------------------
// @file      : duplicates.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/18 20:04
// -------------------------------------------

package results

import (
	"context"
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/bigcache"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

type duplicate struct {
}

var Duplicate *duplicate

func InitializeDuplicate() {
	Duplicate = &duplicate{}
}

// SubdomainInTask check whether taskid:subdomain is in the local cache; if not, store it, check redis for duplicates, and if subdomain deduplication is enabled, check whether the subdomain exists in mongodb.
func (d *duplicate) SubdomainInTask(taskId string, host string, isRestart bool) bool {
	key := "duplicates:" + taskId + ":subdomain:" + host
	flag := d.DuplicateLocalCache(key)
	if isRestart {
		return flag
	} else {
		if flag {
			keyRedis := "duplicates:" + taskId + ":domain"
			valueRedis := host
			flag = d.DuplicateRedisCache(keyRedis, valueRedis)
			return flag
		}
	}
	// Exists in local cache, return false
	return false
}

func (d *duplicate) SubdomainInMongoDb(result *types.SubdomainResult) bool {
	var resultDoc bson.M
	err := mongodb.MongodbClient.FindOne("subdomain", bson.M{"host": result.Host}, bson.M{"_id": 1}, &resultDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Subdomain not found in mongodb, return true to start scanning it
			return true
		}
		// mongodb query error, ignore it and start scanning the domain
		logger.SlogErrorLocal(fmt.Sprintf("SubdomainInMongoDb error :%s\n", err))
		return true
	}
	// Found the domain in mongodb, deduplicate and return false so the subdomain is not scanned
	return false
}

func (d *duplicate) PortIntask(taskId string, host string, port string, isRestart bool) bool {
	key := "duplicates:" + taskId + ":port:" + host + ":" + port
	flag := d.DuplicateLocalCache(key)
	if isRestart {
		return flag
	}
	if flag {
		// Not in local cache, look it up in redis
		keyRedis := "duplicates:" + taskId + ":port"
		valueRedis := host + "-" + port
		flag = d.DuplicateRedisCache(keyRedis, valueRedis)
		return flag
	}
	return false
}

// True means not in memory; false means it exists (duplicate)
func (d *duplicate) DuplicateLocalCache(key string) bool {
	_, err := bigcache.BigCache.Get(key)
	if err != nil {
		// bigcache does not exist, set cache
		err := bigcache.BigCache.Set(key, []byte{})
		if err != nil {
			logger.SlogError(fmt.Sprintf("Set BigCache error: %v - %v", key, err))
		}
		return true
	}
	// Exists in local cache, so it is a duplicate
	return false
}

// DuplicateRedisCache deduplicate by checking whether value exists under key; true means not present (not a duplicate), false means it already exists (duplicate)
func (d *duplicate) DuplicateRedisCache(key string, value string) bool {
	ctx := context.Background()
	exists, err := redis.RedisClient.SIsMember(ctx, key, value)
	if err != nil {
		logger.SlogError(fmt.Sprintf("PortIntask Deduplication error %v", err))
		// If querying redis fails, assume there are no duplicates
		return true
	}
	if exists {
		// If it already exists in redis, this or another node is already scanning this port, return false to skip the domain
		return false
	} else {
		_, err = redis.RedisClient.SAdd(ctx, key, value)
		if err != nil {
			logger.SlogError(fmt.Sprintf("PortIntask Deduplication sadd error %v", err))
		}
		// The subdomain is not in redis, meaning this domain-port has not been scanned, return true to start scanning
		return true
	}
}

func (d *duplicate) AssetInMongodb(host string, port string) (bool, string, bson.M) {
	var result bson.M
	err := mongodb.MongodbClient.FindOne("asset", bson.M{"host": host, "port": port}, nil, &result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// Means it does not exist in mongodb
			return false, "", nil
		}
		// Other errors are also treated as not existing in mongodb
		logger.SlogErrorLocal(fmt.Sprintf("AssetInMongodb error :%s\n", err))
		return false, "", nil
	} else {
		// Get and remove the _id field, convert to string
		var id string
		if objId, ok := result["_id"].(primitive.ObjectID); ok {
			id = objId.Hex()      // Convert ObjectID to string
			delete(result, "_id") // Remove the _id field from result
		}
		// Found this asset record in mongodb
		return true, id, result
	}
}

func (d *duplicate) URL(rawUrl string, taskId string) bool {
	dupKey := d.URLParams(rawUrl)
	key := "duplicates:" + taskId + ":url:" + dupKey
	return d.DuplicateLocalCache(key)
}

func (d *duplicate) Crawler(value string, taskId string) bool {
	key := "duplicates:" + taskId + ":crawler:" + value
	return d.DuplicateLocalCache(key)
}

func (d *duplicate) URLParams(rawUrl string) string {
	parsedURL, err := url.Parse(rawUrl)
	dupKey := utils.Tools.HashXX64String(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(rawUrl, "/"), "http://"), "https://"))
	if err != nil {
	} else {
		queryParams := parsedURL.Query()
		if len(queryParams) > 0 {
			paramskey := fmt.Sprintf("%s%s", parsedURL.Host, strings.TrimSuffix(parsedURL.Path, "/"))
			for key, _ := range queryParams {
				paramskey += key
			}
			dupKey = utils.Tools.HashXX64String(paramskey)
		}
	}
	return dupKey
}

func (d *duplicate) SensitiveBody(md5 string, taskId string, tp string) bool {
	key := "duplicates:" + taskId + fmt.Sprintf(":%v", tp) + ":SensitiveBody:" + md5
	return d.DuplicateLocalCache(key)
}

func (d *duplicate) DuplicateUrlFileKey(filename string, taskId string) bool {
	key := "duplicates:" + taskId + ":urlfile:" + filename
	if d.DuplicateLocalCache(key) {
		keyRedis := "duplicates:" + taskId + ":urlfile"
		valueRedis := filename
		return d.DuplicateRedisCache(keyRedis, valueRedis)
	} else {
		return false
	}
}

func (d *duplicate) RootDomain(domain string, taskId string) bool {
	key := "duplicates:" + taskId + ":rootdomain:" + domain
	if d.DuplicateLocalCache(key) {
		keyRedis := "duplicates:" + taskId + ":rootdomain"
		valueRedis := domain
		return d.DuplicateRedisCache(keyRedis, valueRedis)
	} else {
		return false
	}
}

func (d *duplicate) Custom(locakKey string, redisKey string, redisValue string) bool {
	if d.DuplicateLocalCache(locakKey) {
		return d.DuplicateRedisCache(redisKey, redisValue)
	} else {
		return false
	}
}

var PathInt = `/\d+`
var PathIntReg = regexp.MustCompile(PathInt)

func (d *duplicate) UrlDuplicate(urlRaw string) (bool, []string, string) {
	parsedURL, err := url.Parse(urlRaw)
	if err != nil {
		return false, []string{}, ""
	}
	newPath := PathIntReg.ReplaceAllString(parsedURL.Path, "")
	queryParams := parsedURL.Query()
	keys := make([]string, 0, len(queryParams))
	for key := range queryParams {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var sb string
	for _, key := range keys {
		sb += key
	}
	key := "ssrf:" + utils.Tools.HashXX64String(parsedURL.Scheme+parsedURL.Host+newPath+sb)
	flag := d.DuplicateLocalCache(key)
	if flag {
		// Unique
		return flag, keys, parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
	}
	return false, []string{}, ""
}
