// utils-------------------------------------
// @file      : utils.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/6 22:34
// -------------------------------------------

package utils

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/cespare/xxhash/v2"
	"github.com/hbollon/go-edlib"
	"github.com/ledongthuc/pdf"
	"github.com/nfnt/resize"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

type UtilTools struct {
	CdnCheckClient *cdncheck.Client
	fileLocks      map[string]*sync.Mutex
	fileMu         sync.Mutex
}

var Tools *UtilTools

func InitializeTools() {
	client := cdncheck.New()
	Tools = &UtilTools{
		CdnCheckClient: client,
		fileLocks:      make(map[string]*sync.Mutex),
	}
}

// ReadYAMLFile read a YAML file and parse it into the target struct
func (t *UtilTools) ReadYAMLFile(filePath string, target interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(byteValue, target)
	if err != nil {
		return err
	}

	return nil
}

// WriteYAMLFile serialize the target struct to YAML and write it to a file
func (t *UtilTools) WriteYAMLFile(filePath string, data interface{}) error {
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, yamlData, 0644)
	if err != nil {
		return err
	}

	return nil
}

// GenerateRandomString generate a random string of the specified length
func (t *UtilTools) GenerateRandomString(length int) string {
	// Define charset
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Build random string
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// Convert integer to base62 string
func (t *UtilTools) ToBase62(num int64) string {
	chars := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	if num == 0 {
		return string(chars[0])
	}

	var result string
	for num > 0 {
		result = string(chars[num%62]) + result
		num /= 62
	}
	return result
}

// GenerateHash generate unique hash
func (t *UtilTools) GenerateHash() string {
	timestamp := time.Now().Unix()
	secondsSince2000 := timestamp - 1747958400
	base62Timestamp := t.ToBase62(secondsSince2000)

	randoms := t.GenerateRandomString(4)
	hash := base62Timestamp + randoms
	return hash
}

// GetSystemUsage get system usage
func (t *UtilTools) GetSystemUsage() (int, float64) {
	// Get CPU usage
	percent, err := cpu.Percent(3*time.Second, false)
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("Failed to get CPU usage:", err))
		return 0, 0
	}
	cpuNum := 0
	if len(percent) > 0 {
		cpuNum = int(percent[0])
	}
	// Get memory usage
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println("Failed to get memory usage:", err)
		logger.SlogErrorLocal(fmt.Sprintf("Failed to get memory usage:", err))
		return 0, 0
	}
	return cpuNum, memInfo.UsedPercent
}

// WriteContentFile write string to the specified file
func (t *UtilTools) WriteContentFile(filPath string, fileContent string) error {
	// Write string to file
	return t.WriteByteContentFile(filPath, []byte(fileContent))
}

// WriteByteContentFile write bytes to the specified file, overwriting
func (t *UtilTools) WriteByteContentFile(filPath string, fileContent []byte) error {
	// Write string to file
	err := t.EnsureFilePathExists(filPath)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filPath, fileContent, 0666); err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("Failed to create filPath: %s - %s", filPath, err))
		return err
	}
	return nil
}

// WriteContentFileAppend write string to the specified file
func (t *UtilTools) WriteContentFileAppend(filPath string, fileContent string) error {
	// Write string to file
	return t.AppendOrCreateFile(filPath, []byte(fileContent))
}

// getFileLock acquire file lock
func (t *UtilTools) GetFileLock(filePath string) *sync.Mutex {
	t.fileMu.Lock()
	defer t.fileMu.Unlock()

	if _, exists := t.fileLocks[filePath]; !exists {
		t.fileLocks[filePath] = &sync.Mutex{}
	}
	return t.fileLocks[filePath]
}

// ClearAllLocks clear all file locks
func (t *UtilTools) ClearAllLocks() {
	t.fileMu.Lock()
	defer t.fileMu.Unlock()

	t.fileLocks = make(map[string]*sync.Mutex) // Create a new empty map, the old one will be garbage collected
}

// AppendOrCreateFile append to file, create it if it does not exist
func (t *UtilTools) AppendOrCreateFile(filePath string, fileContent []byte) error {
	lock := t.GetFileLock(filePath)
	lock.Lock()
	defer lock.Unlock()

	// Ensure file path exists
	err := t.EnsureFilePathExists(filePath)
	if err != nil {
		return err
	}

	// Open file, supports appending or creating a new file
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("Failed to open or create file: %s - %s", filePath, err))
		return err
	}
	defer file.Close()

	// Write content
	if _, err := file.Write(fileContent); err != nil {
		logger.SlogErrorLocal(fmt.Sprintf("Failed to write to file: %s - %s", filePath, err))
		return err
	}
	return nil
}

// MarshalYAMLToString serialize the target struct to a YAML string
func (t *UtilTools) MarshalYAMLToString(data interface{}) (string, error) {
	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(yamlData), nil
}

// StructToJSON serialize struct to json
func (t *UtilTools) StructToJSON(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}

// JSONToStruct deserialize JSON string into struct
func (t *UtilTools) JSONToStruct(jsonStr []byte, result interface{}) error {
	return json.Unmarshal(jsonStr, result)
}

// ParseArgs parse parameters from string
// Parameters:
// - args: input parameter string to parse, e.g. "--name John --age 30".
// - keys: list of key names to parse, i.e. which key-value pairs are parsed, e.g. passing "name" and "age".
//
// Returns:
// - map[string]string: returns a map of key-value pairs where keys are the parameters in keys and values are the parsed strings.
// - error: returns an error if parsing fails.
func (t *UtilTools) ParseArgs(args string, keys ...string) (map[string]string, error) {
	// Split parameter string into slice
	argsSlice := strings.Fields(args)

	// Create a FlagSet to parse the arguments
	fs := flag.NewFlagSet("ParseArgs", flag.ContinueOnError)

	// Create a map to store flag values
	values := make(map[string]*string)

	// Iterate over keys, add one for each key flag
	for _, key := range keys {
		value := ""
		values[key] = &value
		fs.StringVar(values[key], key, "", "a placeholder for "+key)
	}

	// Redirect stdout to avoid printing error messages
	originalStderr := os.Stderr
	_, w, _ := os.Pipe()
	os.Stderr = w
	// Parse parameters
	err := fs.Parse(argsSlice)

	// Restore stdout
	w.Close()
	os.Stderr = originalStderr

	// Read stderr
	if err != nil {
		// If there is an error, optionally log it
		// fmt.Println("Ignored extra arguments:", err)
	}

	// Get the value for key and fill it into the result map
	result := make(map[string]string)
	for _, key := range keys {
		if valuePtr, ok := values[key]; ok {
			result[key] = *valuePtr
		} else {
			result[key] = ""
		}
	}

	return result, nil
}

// DeleteFile delete the specified file
func (t *UtilTools) DeleteFile(filePath string) {
	// Check whether file exists
	if filePath == "" {
		return
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return
	} else if err != nil {
		return
	}

	// File exists, deleting
	err := os.Remove(filePath)
	if err != nil {
		return
	}
}

func (t *UtilTools) DeleteFolder(folderPath string) error {
	err := os.RemoveAll(folderPath)
	if err != nil {
		return fmt.Errorf("Failed to delete folder: %v", err)
	}
	return nil
}

// GetParameter get parameters of the specified plugin in the specified module
func (t *UtilTools) GetParameter(Parameters map[string]map[string]string, module string, plugin string) (string, bool) {
	// Check whether module exists
	if plugins, modOk := Parameters[module]; modOk {
		// Check whether plugin exists
		if param, plugOk := plugins[plugin]; plugOk {
			return param, true
		}
	}
	// No matching parameter found, return false
	return "", false
}

//// GetRootDomain get the root domain of a domain
//func (t *UtilTools) GetRootDomain(input string) (string, error) {
//	input = strings.TrimPrefix(input, "http://")
//	input = strings.TrimPrefix(input, "https://")
//	input = strings.Trim(input, "/")
//	ip := net.ParseIP(input)
//	if ip != nil {
//		return ip.String(), nil
//	}
//	input = "https://" + input
//
//	// Try to parse as URL
//	u, err := url.Parse(input)
//	if err == nil && u.Hostname() != "" {
//		ipHost := net.ParseIP(u.Hostname())
//		if ipHost != nil {
//			return ipHost.String(), nil
//		}
//		eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(u.Hostname())
//		if err != nil {
//			return input, fmt.Errorf("Root domain parse error")
//		}
//		return eTLDPlusOne, nil
//		//hostParts := strings.Split(u.Hostname(), ".")
//		//if len(hostParts) < 2 {
//		//	return "", fmt.Errorf("Invalid domain format")
//		//}
//		//if len(hostParts) == 2 {
//		//	return u.Hostname(), nil
//		//}
//		//// Check whether it is a compound domain
//		//if _, ok := compoundDomains[hostParts[len(hostParts)-2]+"."+hostParts[len(hostParts)-1]]; ok {
//		//	return hostParts[len(hostParts)-3] + "." + hostParts[len(hostParts)-2] + "." + hostParts[len(hostParts)-1], nil
//		//}
//		//
//		//// If the domain starts with www, handle specially
//		//if hostParts[0] == "www" {
//		//	return hostParts[len(hostParts)-2] + "." + hostParts[len(hostParts)-1], nil
//		//}
//		//
//		//return hostParts[len(hostParts)-2] + "." + hostParts[len(hostParts)-1], nil
//	}
//	return input, fmt.Errorf("Input is neither a valid URL nor a valid IP address: %v", input)
//}

// GetRootDomain extract root domain or IP address from input
func (t *UtilTools) GetRootDomain(input string) (string, error) {
	u, err := t.SafeParseURL(input)
	if err != nil {
		return input, fmt.Errorf("URL parse failed: %w", err)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return input, fmt.Errorf("Unable to get Hostname")
	}

	// If it is an IP, return directly
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.String(), nil
	}

	// Extract valid root domains
	rootDomain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return input, fmt.Errorf("Root domain parse error: %w", err)
	}

	return rootDomain, nil
}

// SafeParseURL safely parse URLs, handling invalid %, Chinese domain names, spaces, etc.
func (t *UtilTools) SafeParseURL(input string) (*url.URL, error) {
	if input == "" {
		return nil, fmt.Errorf("Input is empty")
	}

	input = strings.TrimSpace(input)
	input = sanitizePercent(input)
	input = strings.ReplaceAll(input, " ", "%20")

	// Add protocol prefix
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("URL parse failed: %w", err)
	}

	// IDNA handle Chinese domain names
	asciiHost, err := idna.ToASCII(u.Hostname())
	if err != nil {
		return nil, fmt.Errorf("Domain IDNA conversion failed: %w", err)
	}

	// Append port (if any)
	u.Host = asciiHost + portSuffix(u.Host)

	return u, nil
}

// sanitizePercent fix invalid % encoding
func sanitizePercent(input string) string {
	var builder strings.Builder
	for i := 0; i < len(input); i++ {
		if input[i] == '%' {
			if i+2 >= len(input) || !isHexDigit(input[i+1]) || !isHexDigit(input[i+2]) {
				builder.WriteString("%25")
			} else {
				builder.WriteByte('%')
			}
		} else {
			builder.WriteByte(input[i])
		}
	}
	return builder.String()
}

// Check whether it is a valid hex character
func isHexDigit(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}

// Extract the original host's port (if any)
func portSuffix(host string) string {
	if colon := strings.LastIndex(host, ":"); colon != -1 && colon < len(host)-1 {
		port := host[colon+1:]
		if _, err := fmt.Sscanf(port, "%d", new(int)); err == nil {
			return ":" + port
		}
	}
	return ""
}

var compoundDomains = map[string]bool{
	"ac.uk":  true,
	"co.uk":  true,
	"gov.uk": true,
	"ltd.uk": true,
	"me.uk":  true,
	"net.au": true,
	"org.au": true,
	"com.au": true,
	"edu.au": true,
	"gov.au": true,
	"asn.au": true,
	"id.au":  true,
	"com.cn": true,
	"net.cn": true,
	"org.cn": true,
	"gov.cn": true,
	"edu.cn": true,
	"mil.cn": true,
	"ac.cn":  true,
	"ah.cn":  true,
	"bj.cn":  true,
	"cq.cn":  true,
	"fj.cn":  true,
	"gd.cn":  true,
	"gs.cn":  true,
	"gx.cn":  true,
	"gz.cn":  true,
	"ha.cn":  true,
	"hb.cn":  true,
	"he.cn":  true,
	"hi.cn":  true,
	"hl.cn":  true,
	"hn.cn":  true,
	"jl.cn":  true,
	"js.cn":  true,
	"jx.cn":  true,
	"ln.cn":  true,
	"nm.cn":  true,
	"nx.cn":  true,
	"qh.cn":  true,
	"sc.cn":  true,
	"sd.cn":  true,
	"sh.cn":  true,
	"sn.cn":  true,
	"sx.cn":  true,
	"tj.cn":  true,
	"xj.cn":  true,
	"xz.cn":  true,
	"yn.cn":  true,
	"zj.cn":  true,
}

// HttpGetDownloadFile download file over http to the specified path
func (t *UtilTools) HttpGetDownloadFile(url, filePath string) (bool, error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, fmt.Errorf("http.Get failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("ioutil.ReadAll failed: %w", err)
	}

	// Get the directory path of the file
	dir := filepath.Dir(filePath)
	// Create the file's directory (if it does not exist)
	err = os.MkdirAll(dir, 0777) // MkdirAll creates directories recursively
	if err != nil {
		return false, fmt.Errorf("os.MkdirAll failed: %w", err)
	}
	// Write file content to a local file
	err = ioutil.WriteFile(filePath, body, 0777)
	if err != nil {
		return false, fmt.Errorf("ioutil.WriteFile failed: %w", err)
	}

	return true, nil
}

func (t *UtilTools) ExecuteCommandWithTimeout(command string, args []string, timeout time.Duration, externalCtx context.Context) error {
	logger.SlogInfo(fmt.Sprintf("ExecuteCommandWithTimeout cmd: %v args %v", command, args))
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel() // Ensure the context is canceled after the function ends to prevent resource leaks
	// Use select to watch two contexts: the timeout context and the passed-in context
	// Create a new context that is canceled when either context is canceled
	mergedCtx, mergedCancel := context.WithCancel(ctx)
	go func() {
		// Listen for external context cancellation
		select {
		case <-externalCtx.Done():
			mergedCancel() // When the external context is canceled, cancel the merged context
			return
		case <-ctx.Done():
			// When the timeout context is canceled, the merged context is canceled too
			mergedCancel()
			return
		}
	}()
	// Create command object, using context-aware exec.CommandContext
	cmd := exec.CommandContext(mergedCtx, command, args...)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	go io.Copy(io.Discard, stdout)
	go io.Copy(io.Discard, stderr)
	//stderrPipe, err := cmd.StderrPipe()
	//if err != nil {
	//	return fmt.Errorf("failed to get stderr: %w", err)
	//}

	// Start command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %w", err)
	}
	//
	//go func() {
	//	scanner := bufio.NewScanner(stderrPipe)
	//	for scanner.Scan() {
	//		logger.SlogWarnLocal(fmt.Sprintf("%v stderr: %s", command, scanner.Text()))
	//	}
	//	if err := scanner.Err(); err != nil {
	//		logger.SlogWarnLocal(fmt.Sprintf("%v stderr scan error: %v", command, err))
	//	}
	//}()

	// Wait for command to complete
	err := cmd.Wait()

	if err != nil {
		// If it is a context canceled error
		if errors.Is(mergedCtx.Err(), context.Canceled) {
			// Context canceled
			logger.SlogWarnLocal(fmt.Sprintf("command execution canceled: %v", command))
			return nil
		}

		// If it is a timeout error
		if errors.Is(mergedCtx.Err(), context.DeadlineExceeded) {
			// Context timeout
			logger.SlogWarnLocal(fmt.Sprintf("command execution timed out: %v", command))
			return nil
		}
		return err
	}
	// If there is no error, the command ran successfully
	return nil
}

// ExecuteCommandToChanWithTimeout run the specified command; each output line is sent to the result channel, with context and timeout support.
func (t *UtilTools) ExecuteCommandToChanWithTimeout(cmdName string, args []string, result chan<- string, timeout time.Duration, ctx context.Context) {
	logger.SlogInfo(fmt.Sprintf("ExecuteCommandToChanWithTimeout cmd: %v args %v", cmdName, args))
	// Wrap context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer close(result)
	// Create command
	cmd := exec.CommandContext(ctxWithTimeout, cmdName, args...)
	var wg sync.WaitGroup
	// Get command output pipe (stdout)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.SlogWarnLocal(fmt.Sprintf("Error getting stdout pipe: %v", err))
		return
	}

	// Get command error output pipe (stderr)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		logger.SlogWarnLocal(fmt.Sprintf("Error getting stderr pipe: %v", err))
		return
	}

	// Start command
	if err := cmd.Start(); err != nil {
		logger.SlogWarnLocal(fmt.Sprintf("Error getting starting command: %v", err))
		return
	}
	wg.Add(1)
	// Read the command's stdout in a goroutine
	go func() {
		defer wg.Done()
		reader := bufio.NewReaderSize(stdout, 7340032)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				logger.SlogWarnLocal(fmt.Sprintf("Error reading stdout: %v", err))
				break
			}
			select {
			case result <- strings.TrimRight(line, "\n"):
			case <-ctxWithTimeout.Done():
				return
			}
		}
	}()
	wg.Add(1)
	// Read the command's stderr in a goroutine
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			txt := scanner.Text()
			select {
			case <-ctxWithTimeout.Done():
				return
			default:
				result <- txt
				logger.SlogWarnLocal(fmt.Sprintf("Error getting stderr: %s", txt))
			}
		}
		if err := scanner.Err(); err != nil {
			logger.SlogWarnLocal(fmt.Sprintf("Error reading stderr: %v", err))
		}
	}()

	// Wait for command to finish
	err = cmd.Wait()
	if err != nil {
		select {
		case <-ctxWithTimeout.Done():
			return
		default:
			logger.SlogWarnLocal(fmt.Sprintf("Error waiting for command: %v", err))
		}
	}
	wg.Wait()
}

// ExecuteCommandToChan run the specified command, each output line is sent to the result channel.
func (t *UtilTools) ExecuteCommandToChan(cmdName string, args []string, result chan<- string) {
	logger.SlogInfo(fmt.Sprintf("ExecuteCommandToChan cmd: %v args %v", cmdName, args))
	// Create command
	cmd := exec.Command(cmdName, args...)

	// Get command output pipe (stdout)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result <- fmt.Sprintf("Error getting stdout pipe: %v", err)
		close(result)
		return
	}

	// Start command
	if err := cmd.Start(); err != nil {
		result <- fmt.Sprintf("Error starting command: %v", err)
		close(result)
		return
	}

	// Read the command's stdout with bufio
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		// Send each output line to the result channel
		result <- scanner.Text()
	}

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		result <- fmt.Sprintf("Error waiting for command: %v", err)
	}

	// Close the result channel to signal that sending is done
	close(result)
}

// CalculateMD5 calculate md5 of string
func (t *UtilTools) CalculateMD5(input string) string {
	// Convert the input string to bytes
	data := []byte(input)

	// Calculate the MD5 hash
	hash := md5.Sum(data)

	// Convert the hash to a hex string
	hashString := hex.EncodeToString(hash[:])

	return hashString
}

// WriteLinesToFile write each line of the string array to the specified file
func (t *UtilTools) WriteLinesToFile(filePath string, lines *[]string) error {

	// Get the directory path of the file
	dir := filepath.Dir(filePath)
	// Create the file's directory (if it does not exist)
	err := os.MkdirAll(dir, 0777) // MkdirAll creates directories recursively
	if err != nil {
		return fmt.Errorf("os.MkdirAll failed: %w", err)
	}

	// Open file, create it if it does not exist
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("Unable to open file: %v", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	// Create a buffered writer
	writer := bufio.NewWriter(file)

	// Write each line of the array to file
	for _, line := range *lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("Error writing file: %v", err)
		}
	}

	// Flush buffer to ensure all data is written to file
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("Error flushing buffer: %v", err)
	}

	return nil
}

var timeZoneOffsets = map[string]int{
	"UTC":                 0,
	"Asia/Shanghai":       8 * 60 * 60,
	"Asia/Tokyo":          9 * 60 * 60,
	"Asia/Kolkata":        5*60*60 + 30*60,
	"Europe/London":       0,
	"Europe/Berlin":       1 * 60 * 60,
	"Europe/Paris":        1 * 60 * 60,
	"America/New_York":    -5 * 60 * 60,
	"America/Chicago":     -6 * 60 * 60,
	"America/Denver":      -7 * 60 * 60,
	"America/Los_Angeles": -8 * 60 * 60,
	"Australia/Sydney":    10 * 60 * 60,
	"Australia/Perth":     8 * 60 * 60,
	"Asia/Singapore":      8 * 60 * 60,
	"Asia/Hong_Kong":      8 * 60 * 60,
	"Europe/Moscow":       3 * 60 * 60,
	"America/Sao_Paulo":   -3 * 60 * 60,
	"Africa/Johannesburg": 2 * 60 * 60,
	"Asia/Dubai":          4 * 60 * 60,
	"Pacific/Auckland":    12 * 60 * 60,
}

func (t *UtilTools) GetTimeNow() string {
	// Get current time
	timeZoneName := global.AppConfig.TimeZoneName

	var location *time.Location
	var err error

	// Find the offset for the time zone name
	offset, exists := timeZoneOffsets[timeZoneName]
	if exists {
		// If a mapping exists, use the fixed time zone
		location = time.FixedZone(timeZoneName, offset)
	} else {
		// If no mapping exists, try loading the time zone name directly
		location, err = time.LoadLocation(timeZoneName)
		if err != nil {
			// If loading fails, use the system default time zone
			fmt.Printf("Time zone not found: %s, using system default time zone\n", timeZoneName)
			location = time.Local
		}
	}
	currentTime := time.Now()
	var easternTime = currentTime.In(location)
	return easternTime.Format("2006-01-02 15:04:05")
}

// EnsureDir check whether directory exists, create it if not
func (t *UtilTools) EnsureDir(dirPath string) error {
	// Check whether directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// If directory does not exist, create it
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Failed to create directory: %w", err)
		}
		return nil
	} else {
		return nil
	}
}

// EnsureFilePathExists check the given file path, create the folder if it does not exist
func (t *UtilTools) EnsureFilePathExists(filePath string) error {
	// Get the file's directory path
	dir := filepath.Dir(filePath)

	err := t.EnsureDir(dir)
	if err != nil {
		return err
	}
	return nil
}

// ReadFileLineByLine function reads the file line by line and sends each line to the channel
func (t *UtilTools) ReadFileLineByLine(filePath string, lineChan chan<- string, ctx context.Context) error {
	defer close(lineChan)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close() // Close file when function ends
	// Read the file line by line with bufio.Scanner
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
			lineChan <- scanner.Text() // Send read lines to the channel
		}
	}

	// Check whether an error occurred while reading
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// ReadFileLineReader read the file line by line, each line is a complete JSON object
func (t *UtilTools) ReadFileLineReader(filePath string, lineChan chan<- string, ctx context.Context) error {
	defer close(lineChan)

	// Check whether file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use a large buffer to improve read performance
	reader := bufio.NewReaderSize(file, 30*1024) // 30KB buffer

	// Read file line by line
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Read one line
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				return err
			}
			if err == io.EOF && len(line) == 0 {
				return nil // File read completed
			}

			// Trim trailing newlines and spaces
			line = strings.TrimSpace(line)

			// Send each line to lineChan
			select {
			case lineChan <- line:
			case <-ctx.Done():
				return nil
			}

			if err == io.EOF {
				return nil // Reached end of file, exit loop
			}
		}
	}
}

func (t *UtilTools) ReadFileLineReaderBytes(filePath string, lineChan chan<- []byte, ctx context.Context) error {
	defer close(lineChan)

	// Check whether file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use a large buffer to improve read performance
	reader := bufio.NewReaderSize(file, 30*1024) // 30KB buffer

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Read a line, ReadLine returns []byte
			lineBytes, isPrefix, err := reader.ReadLine()
			if err != nil && err != io.EOF {
				return err
			}
			if err == io.EOF && len(lineBytes) == 0 {
				return nil
			}

			// If line is too long and split, merge in a loop
			fullLine := append([]byte(nil), lineBytes...) // Optionally deep copy to avoid being overwritten on reuse
			for isPrefix {
				lineBytes, isPrefix, _ = reader.ReadLine()
				fullLine = append(fullLine, lineBytes...)
			}

			// Trim whitespace
			fullLine = bytes.TrimSpace(fullLine)

			// Send to channel
			select {
			case lineChan <- fullLine:
			case <-ctx.Done():
				return nil
			}

			if err == io.EOF {
				return nil
			}
		}
	}
}

var builderPool = sync.Pool{
	New: func() any {
		return new(strings.Builder)
	},
}

func (t *UtilTools) ReadFileToStringOptimized(filePath string, maxSizeMB int64) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// MB to bytes
	maxSize := maxSizeMB * 1024 * 1024

	// Only allow reading the first maxSizeMB MB
	r := io.LimitReader(f, maxSize)

	data, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (t *UtilTools) CdnCheck(host string) (bool, string) {
	ip := net.ParseIP(host)
	matched, val, err := t.CdnCheckClient.CheckCDN(ip)
	if err != nil {
		return false, ""
	}
	if matched {
		return true, val
	} else {
		return false, ""
	}
}

func (t *UtilTools) WafCheck(ipStr string) (bool, string) {
	ip := net.ParseIP(ipStr)
	waf, s, err := t.CdnCheckClient.CheckWAF(ip)
	if err != nil {
		return false, ""
	}
	return waf, s
}

// GetDomain extract domain from URL
func (t *UtilTools) GetDomain(rawUrl string) string {
	// Parse URL
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return rawUrl
	}

	// Extract domain
	domain := parsedUrl.Host
	if domain == "" {
		return rawUrl
	}
	// Strip port number (if any)
	domain = strings.Split(domain, ":")[0]

	return domain
}

func removeDefaultPort(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	// Check port and remove
	if (parsedURL.Scheme == "http" && parsedURL.Port() == "80") ||
		(parsedURL.Scheme == "https" && parsedURL.Port() == "443") {
		parsedURL.Host = parsedURL.Hostname() // Strip port
	}

	return parsedURL.String()
}

var SizeThreshold = 500 * 1024 // 500 KB

func (t *UtilTools) HttpxResultToAssetHttp(r runner.Result) types.AssetHttp {
	//defer Tools.DeleteFile(r.ScreenshotPath)
	Screenshot := ""
	if r.ScreenshotBytes != nil {
		if len(r.ScreenshotBytes) <= SizeThreshold {
			Screenshot = base64.StdEncoding.EncodeToString(r.ScreenshotBytes)
		} else {
			Screenshot = Tools.CompressAndEncodeScreenshot(r.ScreenshotBytes, 0.5)
		}
	}
	var ah = types.AssetHttp{
		Time:         Tools.GetTimeNow(),
		TLSData:      r.TLSData, // You may need to set an appropriate default value based on the actual type.
		Hashes:       r.Hashes,
		CDNName:      r.CDNName,
		Port:         r.Port,
		URL:          removeDefaultPort(r.URL), //Strip default ports 80 and 443
		Title:        r.Title,
		Type:         "http",
		Error:        r.Error,
		ResponseBody: r.ResponseBody,
		Host:         t.GetDomain(r.URL),
		IP:           r.Host,
		FavIconMMH3:  r.FavIconMMH3,
		//FaviconPath:  r.FaviconPath,
		RawHeaders:   r.RawHeaders,
		Jarm:         r.JarmHash,
		Technologies: r.Technologies, // You may need to set an appropriate default value based on the actual type.
		StatusCode:   r.StatusCode,   // You may need to set an appropriate default value.
		Webcheck:     false,
		IconContent:  base64.StdEncoding.EncodeToString(r.FaviconData),
		CDN:          r.CDN,
		WebServer:    r.WebServer,
		Service:      r.Scheme,
		Screenshot:   Screenshot,
	}
	ah.LastScanTime = ah.Time
	return ah
}

func (t *UtilTools) IsMatchingFilter(fs []*regexp.Regexp, d []byte) bool {
	for _, r := range fs {
		if r.Match(d) {
			return true
		}
	}
	return false
}

//	func (t *UtilTools) AssetResultToAssetOther(r types.Asset) types.AssetOther {
//		var ao = types.AssetOther{
//
//		}
//		return ao
//	}
//
// generateIPRange generate IP range
func generateIPRange(start, end string) ([]string, error) {
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP addresses: %s, %s", start, end)
	}

	var ipList []string
	for ip := startIP; !ip.Equal(endIP); incrementIP(ip) {
		ipList = append(ipList, ip.String())
	}
	ipList = append(ipList, endIP.String()) // Add end IP

	return ipList, nil
}

// incrementIP add IP address
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// ipRangeToSlice convert IP network to string slice
func ipRangeToSlice(ipNet *net.IPNet) []string {
	var ipList []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ipList = append(ipList, ip.String())
	}
	return ipList
}

func (t *UtilTools) GenerateTarget(target string) ([]string, error) {
	if strings.Contains(target, "http://") || strings.Contains(target, "https://") {
		return []string{target}, nil
	}

	if strings.Contains(target, "-") {
		// Handle IP range
		parts := strings.Split(target, "-")
		if len(parts) != 2 {
			return []string{target}, nil
		}
		startIP := strings.TrimSpace(parts[0])
		endIP := strings.TrimSpace(parts[1])
		ipRange, err := generateIPRange(startIP, endIP)
		if err != nil {
			return []string{target}, nil
		}
		return ipRange, err
	}

	if strings.Contains(target, "/") {
		// Handle network
		_, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return []string{target}, nil
		}
		return ipRangeToSlice(ipNet), nil
	}

	// Return a single target
	return []string{target}, nil
}

func (t *UtilTools) GenerateIgnore(ignore string) ([]string, []*regexp.Regexp, error) {
	var ignoreList []string
	var regexList []*regexp.Regexp
	for _, ta := range strings.Split(ignore, "\n") {
		ta = strings.ReplaceAll(ta, "http://", "")
		ta = strings.ReplaceAll(ta, "https://", "")
		ta = strings.TrimSpace(ta)
		if !strings.Contains(ta, "*") {
			result, err := t.GenerateTarget(ta)
			if err != nil {
				return nil, nil, err
			}
			ignoreList = append(ignoreList, result...)
		} else {
			// Escape and replace with regular expression
			tEscaped := regexp.QuoteMeta(ta)
			tEscaped = strings.ReplaceAll(tEscaped, `\*`, `.*`)
			regex, err := regexp.Compile(tEscaped)
			if err != nil {
				return nil, nil, err
			}
			regexList = append(regexList, regex)
		}
	}
	return ignoreList, regexList, nil
}

func (t *UtilTools) IsSuffixURL(rawURL string, suffix string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Println("URL parse error:", err)
		return false
	}

	// Get path part, strip query parameters
	path := parsedURL.Path

	// Check whether path starts with ".js" end
	return strings.HasSuffix(path, suffix)
}

// CompareContentSimilarity calculate edit distance similarity
func (t *UtilTools) CompareContentSimilarity(content1, content2 string) (float64, error) {
	// Calculate similarity with edit distance
	similarity, err := edlib.StringsSimilarity(content1, content2, edlib.Levenshtein)
	if err != nil {
		return 0, fmt.Errorf("error calculating similarity: %v", err)
	}
	percentage := similarity * 100
	result := math.Round(float64(percentage*100)) / 100
	return result, nil
}

// UnzipSrcToDest extract file src to dest
func (t *UtilTools) UnzipSrcToDest(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
		if err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

func (t *UtilTools) UntarGz(src, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dest, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.ModePerm); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), os.ModePerm); err != nil {
				return err
			}

			outFile, err := os.Create(targetPath)
			if err != nil {
				return err
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return err
			}
			outFile.Close()
		}
	}

	return nil
}

func (t *UtilTools) UnzipFile(src, dest string) error {
	if strings.HasSuffix(src, ".zip") {
		return t.UnzipSrcToDest(src, dest)
	} else if strings.HasSuffix(src, ".tar.gz") {
		return t.UntarGz(src, dest)
	}
	return fmt.Errorf("unsupported file format: %s", src)
}

// RemoveStringDuplicates array deduplication
func (t *UtilTools) RemoveStringDuplicates(arr []string) []string {
	unique := make(map[string]bool)
	result := []string{}

	for _, value := range arr {
		if !unique[value] {
			unique[value] = true
			result = append(result, value)
		}
	}

	return result
}

func (t *UtilTools) HandleLinuxTemp() {
	tempDir := "/tmp"

	// Define the Linux find command
	findCmd := fmt.Sprintf(
		`find %s -type d \( -regex '.*/[0-9]\{9\}' -o -name 'nuclei*' -o -name '.org.chromium.Chromium*' -o -name '*_badger' -o -name 'rod' \) -exec rm -rf {} +`,
		tempDir,
	)

	// Execute command
	cmd := exec.Command("bash", "-c", findCmd)
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running the Linux find command: %v\n", err)
		logger.SlogWarn("Error clearing temporary files, please clear the /tmp directory manually to avoid filling the disk")
		return
	}
}

// CompressAndEncodeScreenshot compress the image and return a Base64-encoded string.
// It takes the raw image bytes r.ScreenshotBytes and returns a Base64-encoded image string.
// This function losslessly compresses a PNG image and scales it to scaleFactor of its original size. 0.5 = 50%
func (t *UtilTools) CompressAndEncodeScreenshot(screenshotBytes []byte, scaleFactor float64) string {
	if screenshotBytes == nil {
		logger.SlogWarn("No screenshot data provided.")
		return ""
	}

	// Create a byte buffer to process image data directly
	var buf bytes.Buffer

	// Use image.DecodeConfig to get the image type and size without loading the whole image
	config, _, err := image.DecodeConfig(bytes.NewReader(screenshotBytes))
	if err != nil {
		logger.SlogWarn(fmt.Sprintf("Error getting image config:", err))
		return base64.StdEncoding.EncodeToString(screenshotBytes) // Return raw Base64 encoding
	}

	// Calculate new image size (by scale ratio)
	newWidth := uint(float64(config.Width) * scaleFactor)
	newHeight := uint(float64(config.Height) * scaleFactor)

	// Stream decode and process images
	img, imgType, err := image.Decode(bytes.NewReader(screenshotBytes))
	if err != nil {
		logger.SlogWarn(fmt.Sprintf("Error decoding image:", err))
		return base64.StdEncoding.EncodeToString(screenshotBytes) // Return raw Base64 encoding
	}

	// Compress image (lossless or lossy, resize)
	compressedImg := resize.Resize(newWidth, newHeight, img, resize.Lanczos3)

	// Encode differently based on image format
	switch imgType {
	case "jpeg":
		// Use lossy compression
		err = jpeg.Encode(&buf, compressedImg, nil)
		if err != nil {
			logger.SlogWarn(fmt.Sprintf("Error encoding JPEG image:", err))
			return base64.StdEncoding.EncodeToString(buf.Bytes()) // Return Base64 encoding on error
		}
	case "png":
		// Use lossless compression
		err = png.Encode(&buf, compressedImg)
		if err != nil {
			logger.SlogWarn(fmt.Sprintf("Error encoding PNG image:", err))
			return base64.StdEncoding.EncodeToString(buf.Bytes()) // Return Base64 encoding on error
		}
	default:
		logger.SlogWarn(fmt.Sprintf("Unsupported image format:", imgType))
		return base64.StdEncoding.EncodeToString(buf.Bytes()) // Return Base64 encoding by default
	}

	// Return the compressed and encoded Base64 string
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Command intro call exec.Command
func (t *UtilTools) Command(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}

func (t *UtilTools) GetPdfContent(filePath string) string {
	f, r, err := pdf.Open(filePath)
	// remember close file
	defer f.Close()
	if err != nil {
		logger.SlogWarn(fmt.Sprintf("GetPdfContent error: %v", err))
		return ""
	}
	var buf bytes.Buffer
	b, err := r.GetPlainText()
	if err != nil {
		logger.SlogWarn(fmt.Sprintf("GetPdfContent GetPlainText error: %v", err))
		return ""
	}
	buf.ReadFrom(b)

	return buf.String()
}

func (t *UtilTools) MoveContents(srcDir, dstDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignore root directory
		if path == srcDir {
			return nil
		}

		// Calculate target path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dstDir, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		} else {
			// Move if it is a file
			return t.MoveFile(path, dstPath)
		}
	})
}

func (t *UtilTools) MoveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
		return err
	}
	return os.Rename(src, dst) // You can also copy first and then delete the original, to avoid cross-disk failures
}

func (t *UtilTools) EqualStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (t *UtilTools) CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func (t *UtilTools) IsJson(str string) bool {
	// JSON strings usually start with `{` start, with `}` end
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return false
	}

	// Simple check whether it starts with `{` start, with `}` end
	if str[0] == '{' && str[len(str)-1] == '}' {
		var js map[string]interface{}
		// Try to parse the string as a JSON object
		if err := json.Unmarshal([]byte(str), &js); err == nil {
			return true
		}
	}
	return false
}

func (t *UtilTools) ModifyJSONValues(jsonStr string, value string) (string, error) {
	// Parse JSON into interface{}
	var data interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return "", err
	}

	// Replace all values with "test"
	updatedData := t.ReplaceValuesWithTest(data, value)

	// Re-encode the modified data as a JSON string
	updatedJSON, err := json.Marshal(updatedData)
	if err != nil {
		return "", err
	}

	return string(updatedJSON), nil
}

func (t *UtilTools) ReplaceValuesWithTest(data interface{}, value string) interface{} {
	// If it is a map (JSON object), iterate and replace each value
	if m, ok := data.(map[string]interface{}); ok {
		for key := range m {
			m[key] = value // Replace with "test"
		}
		return m
	}

	// If it is a slice (JSON array), iterate and replace each value
	if arr, ok := data.([]interface{}); ok {
		for i := range arr {
			arr[i] = value // Replace with "test"
		}
		return arr
	}

	// If it is another type (e.g. string), return directly "test"
	return value
}

func (t *UtilTools) HashXX64String(input string) string {
	hash := xxhash.Sum64String(input)
	return fmt.Sprintf("%x", hash)
}

func (t *UtilTools) EscapeInvisibleKeepUnicode(s string) string {
	hexChars := "0123456789abcdef"
	s = strings.TrimSpace(s)
	dst := make([]byte, 0, len(s)*2)

	for _, r := range s {
		// unicode.IsPrint: check whether a character is printable (CJK, emoji, letters and digits all return true)
		if unicode.IsPrint(r) && r != '\uFFFD' {
			dst = append(dst, string(r)...)
		} else {
			// rune -> UTF-8 bytes
			buf := make([]byte, 4)
			n := utf8.EncodeRune(buf, r)
			for _, b := range buf[:n] {
				dst = append(dst, '\\', 'x', hexChars[b>>4], hexChars[b&0x0F])
			}
		}
	}

	return string(dst)
}
