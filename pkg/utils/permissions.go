package utils

import (
	"fmt"
	"os"
	"path/filepath"
)

func CheckFileReadable(path string) error {
	if path == "" {
		return nil // Skip empty paths
	}

	expandedPath := os.ExpandEnv(path)
	info, err := os.Stat(expandedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", expandedPath)
		}
		return fmt.Errorf("cannot access file %s: %w", expandedPath, err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, expected a file: %s", expandedPath)
	}

	// Check if file is readable
	file, err := os.Open(expandedPath)
	if err != nil {
		return fmt.Errorf("cannot read file %s: %w. Fix: ensure file has read permissions (e.g., chmod 644 %s)", expandedPath, err, expandedPath)
	}
	file.Close()

	return nil
}

func CheckDirWritable(path string) error {
	if path == "" {
		return nil // Skip empty paths
	}

	expandedPath := os.ExpandEnv(path)

	// Try to create directory if it doesn't exist
	if err := os.MkdirAll(expandedPath, 0770); err != nil {
		return fmt.Errorf("cannot create directory %s: %w. Fix: ensure parent directory is writable or run with appropriate permissions", expandedPath, err)
	}

	// Check if directory is writable by creating a temporary test file
	file, err := os.CreateTemp(expandedPath, ".signatory_write_test_*")
	if err != nil {
		return fmt.Errorf("cannot write to directory %s: %w. Fix: ensure directory has write permissions (e.g., chmod 755 %s) and is owned by the correct user", expandedPath, err, expandedPath)
	}
	testFile := file.Name()
	file.Close()
	os.Remove(testFile) // Clean up test file

	return nil
}

func CheckFileWritable(path string) error {
	if path == "" {
		return nil // Skip empty paths
	}

	expandedPath := os.ExpandEnv(path)

	// Check if file exists
	info, err := os.Stat(expandedPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, check if parent directory is writable
			parentDir := filepath.Dir(expandedPath)
			return CheckDirWritable(parentDir)
		}
		return fmt.Errorf("cannot access file %s: %w", expandedPath, err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, expected a file: %s", expandedPath)
	}

	// File exists, check if it's writable
	file, err := os.OpenFile(expandedPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot write to file %s: %w. Fix: ensure file has write permissions (e.g., chmod 644 %s) and is owned by the correct user", expandedPath, err, expandedPath)
	}
	file.Close()

	return nil
}
