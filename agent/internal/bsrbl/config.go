package bsrbl

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const DefaultStateFile = "/var/lib/laravel-waf/bsrbl-report-outbox.json"

var keyPattern = regexp.MustCompile(`^bsai_[a-f0-9]{16}_[a-f0-9]{64}$`)
var reasonPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

type Settings struct {
	Enabled bool
	URL     string
	APIKey  string
}

// ReadSettings reads only BSRBL settings, without executing or interpolating .env.
// Missing configuration disables reporting. Values are re-read for hot updates.
func ReadSettings(path string) (Settings, error) {
	values := map[string]string{}
	if path != "" {
		body, err := readRegular(path, 1<<20)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Settings{}, errors.New("cannot read BSRBL configuration")
		}
		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(scanner.Text()), "export "))
			name, value, found := strings.Cut(line, "=")
			name = strings.TrimSpace(name)
			if !found || !settingName(name) {
				continue
			}
			parsed, err := literalValue(strings.TrimSpace(value))
			if err != nil {
				return Settings{}, errors.New("invalid quoted BSRBL configuration")
			}
			values[name] = parsed
		}
		if scanner.Err() != nil {
			return Settings{}, errors.New("invalid BSRBL configuration")
		}
	}
	prefix := "LARAVEL_WAF_BSABUSEIP_"
	for _, suffix := range []string{"URL", "API_KEY", "REPORT_ENABLED"} {
		name := "LARAVEL_WAF_BSRBL_" + suffix
		_, inFile := values[name]
		_, inEnvironment := os.LookupEnv(name)
		if inFile || inEnvironment {
			prefix = "LARAVEL_WAF_BSRBL_"
			break
		}
	}
	get := func(suffix string) string {
		if value, exists := os.LookupEnv(prefix + suffix); exists {
			return value
		}
		return values[prefix+suffix]
	}
	enabled := strings.ToLower(get("REPORT_ENABLED"))
	switch enabled {
	case "", "false", "(false)", "0", "off", "no", "null", "(null)":
		return Settings{}, nil
	case "true", "(true)", "1", "on", "yes":
	default:
		return Settings{}, errors.New("invalid BSRBL_REPORT_ENABLED")
	}
	settings := Settings{Enabled: true, URL: strings.TrimRight(get("URL"), "/"), APIKey: get("API_KEY")}
	return settings, settings.validate()
}

func (s Settings) validate() error {
	if !s.Enabled {
		return nil
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(s.URL, " \t\r\n") {
		return errors.New("BSRBL_URL must be an HTTPS origin")
	}
	if !keyPattern.MatchString(s.APIKey) {
		return errors.New("invalid BSRBL_API_KEY")
	}
	return nil
}

func settingName(name string) bool {
	for _, prefix := range []string{"LARAVEL_WAF_BSRBL_", "LARAVEL_WAF_BSABUSEIP_"} {
		for _, suffix := range []string{"URL", "API_KEY", "REPORT_ENABLED"} {
			if name == prefix+suffix {
				return true
			}
		}
	}
	return false
}

func literalValue(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if value[0] == '\'' || value[0] == '"' {
		quote := value[0]
		end := strings.IndexByte(value[1:], quote)
		if end < 0 {
			return "", errors.New("unterminated quote")
		}
		end++
		tail := strings.TrimSpace(value[end+1:])
		if tail != "" && !strings.HasPrefix(tail, "#") {
			return "", errors.New("unexpected value after quote")
		}
		if quote == '"' {
			return strconv.Unquote(value[:end+1])
		}
		return value[1:end], nil
	}
	value = strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
	if strings.ContainsAny(value, " \t") {
		return "", errors.New("unquoted whitespace")
	}
	return value, nil
}

func readRegular(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("file must be regular and within its size limit")
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("file exceeds read limit")
	}
	return body, nil
}
