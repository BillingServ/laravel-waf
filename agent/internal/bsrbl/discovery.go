package bsrbl

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// FindEnvFile reuses the application already selected by the agent's Composer
// signature paths. It never searches other customers' application directories.
// Keep stable symlinks intact so release switches also update the configuration.
func FindEnvFile(explicit string, signaturePaths []string, executable, workingDirectory string) (string, error) {
	if explicit != "" {
		if !filepath.IsAbs(explicit) {
			return "", errors.New("BSRBL .env path must be absolute")
		}
		return filepath.Clean(explicit), nil
	}
	candidates := map[string]bool{}
	for _, path := range signaturePaths {
		if !filepath.IsAbs(path) && filepath.IsAbs(workingDirectory) {
			path = filepath.Join(workingDirectory, path)
		}
		if candidate := composerEnvFile(path); candidate != "" {
			candidates[candidate] = true
		}
	}
	if len(candidates) > 1 {
		return "", errors.New("multiple Laravel applications; select one with --bsrbl-env-file")
	}
	for candidate := range candidates {
		return candidate, nil
	}
	if candidate := composerEnvFile(executable); candidate != "" {
		return candidate, nil
	}
	if filepath.IsAbs(workingDirectory) {
		for directory := filepath.Clean(workingDirectory); ; directory = filepath.Dir(directory) {
			if regularFile(filepath.Join(directory, "artisan")) && regularFile(filepath.Join(directory, "composer.json")) {
				return filepath.Join(directory, ".env"), nil
			}
			if filepath.Dir(directory) == directory {
				break
			}
		}
	}
	// Process environment settings remain usable without an application path.
	return "", nil
}

func composerEnvFile(path string) string {
	if !filepath.IsAbs(path) {
		return ""
	}
	path = filepath.Clean(path)
	marker := string(filepath.Separator) + filepath.Join("vendor", "billingserv", "laravel-waf")
	index := strings.LastIndex(path, marker)
	if index < 0 || (len(path) > index+len(marker) && path[index+len(marker)] != filepath.Separator) {
		return ""
	}
	root := path[:index]
	if root == "" {
		root = string(filepath.Separator)
	}
	return filepath.Join(root, ".env")
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
