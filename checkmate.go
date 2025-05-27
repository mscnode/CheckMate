package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

type FileInfo struct {
	Path     string
	Name     string
	Size     int64
	ModTime  time.Time
	MD5      string
	SHA1     string
	SHA256   string
	Match    string
}

type HashType int

const (
	MD5Hash HashType = iota
	SHA1Hash
	SHA256Hash
)

// calculateHash match file's hash using the specified hash type
func calculateHash(filePath string, hashType HashType) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var hasher hash.Hash
	switch hashType {
	case MD5Hash:
		hasher = md5.New()
	case SHA1Hash:
		hasher = sha1.New()
	case SHA256Hash:
		hasher = sha256.New()
	default:
		return "", fmt.Errorf("tipo di hash non supportato")
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// detectHashType check the length of the hash string and returns the corresponding HashType
func detectHashType(hashStr string) HashType {
	switch len(hashStr) {
	case 32:
		return MD5Hash
	case 40:
		return SHA1Hash
	case 64:
		return SHA256Hash
	default:
		return SHA256Hash // default
	}
}

// processFile processes a single file, calculates its hashes, and checks against an expected hash
func processFile(filePath string, expectedHash string) (*FileInfo, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	md5Hash, err := calculateHash(filePath, MD5Hash)
	if err != nil {
		return nil, fmt.Errorf("errore nel calcolo MD5: %v", err)
	}

	sha1Hash, err := calculateHash(filePath, SHA1Hash)
	if err != nil {
		return nil, fmt.Errorf("errore nel calcolo SHA1: %v", err)
	}

	sha256Hash, err := calculateHash(filePath, SHA256Hash)
	if err != nil {
		return nil, fmt.Errorf("errore nel calcolo SHA256: %v", err)
	}

	fileInfo := &FileInfo{
		Path:   filePath,
		Name:   info.Name(),
		Size:   info.Size(),
		ModTime: info.ModTime(),
		MD5:    md5Hash,
		SHA1:   sha1Hash,
		SHA256: sha256Hash,
		Match:  "-",
	}

	if expectedHash != "" {
		expectedHash = strings.ToLower(expectedHash)
		hashType := detectHashType(expectedHash)
		
		var actualHash string
		switch hashType {
		case MD5Hash:
			actualHash = md5Hash
		case SHA1Hash:
			actualHash = sha1Hash
		case SHA256Hash:
			actualHash = sha256Hash
		}

		if actualHash == expectedHash {
			fileInfo.Match = "✓"
		} else {
			fileInfo.Match = "✗"
		}
	}

	return fileInfo, nil
}

// scanDirectory scans the specified directory, processes each file, and returns a slice of FileInfo
func scanDirectory(dirPath string, expectedHash string) ([]*FileInfo, error) {
	var files []*FileInfo
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("⚠️  Errore nell'accesso a %s: %v\n", path, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		fmt.Printf("📄 Elaborando: %s\n", path)
		
		fileInfo, err := processFile(path, expectedHash)
		if err != nil {
			fmt.Printf("⚠️  Errore nell'elaborazione di %s: %v\n", path, err)
			return nil 
		}

		files = append(files, fileInfo)
		return nil
	})

	return files, err
}

// formatSize formats the file size in a human-readable format
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// printResults prints the results of the checksum validation in a formatted table
func printResults(files []*FileInfo, expectedHash string) {
	if len(files) == 0 {
		fmt.Println("❌ Nessun file trovato nella directory specificata.")
		return
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Name < files[j].Name
	})

	fmt.Printf("\n🔍 RISULTATI DELLA VERIFICA CHECKSUM\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("📁 Directory: %s\n", filepath.Dir(files[0].Path))
	fmt.Printf("📊 File analizzati: %d\n", len(files))
	
	if expectedHash != "" {
		hashType := detectHashType(expectedHash)
		var hashTypeName string
		switch hashType {
		case MD5Hash:
			hashTypeName = "MD5"
		case SHA1Hash:
			hashTypeName = "SHA1"
		case SHA256Hash:
			hashTypeName = "SHA256"
		}
		fmt.Printf("🎯 Hash di riferimento (%s): %s\n", hashTypeName, strings.ToUpper(expectedHash))
	}
	
	fmt.Printf("⏰ Scansione completata: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════════\n\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.TabIndent)

	if expectedHash != "" {
		fmt.Fprintln(w, "MATCH\tFILE\tSIZE\tMODIFIED\tMD5\tSHA1\tSHA256")
		fmt.Fprintln(w, "─────\t────\t────\t────────\t───\t────\t──────")
	} else {
		fmt.Fprintln(w, "FILE\tSIZE\tMODIFIED\tMD5\tSHA1\tSHA256")
		fmt.Fprintln(w, "────\t────\t────────\t───\t────\t──────")
	}

	for _, file := range files {
		modTime := file.ModTime.Format("2006-01-02 15:04")
		size := formatSize(file.Size)
		
		md5Short := file.MD5[:8] + "..." + file.MD5[len(file.MD5)-8:]
		sha1Short := file.SHA1[:8] + "..." + file.SHA1[len(file.SHA1)-8:]
		sha256Short := file.SHA256[:8] + "..." + file.SHA256[len(file.SHA256)-8:]

		if expectedHash != "" {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				file.Match, file.Name, size, modTime, md5Short, sha1Short, sha256Short)
		} else {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				file.Name, size, modTime, md5Short, sha1Short, sha256Short)
		}
	}

	w.Flush()

	fmt.Printf("\n📋 HASH DONE:\n")
	fmt.Printf("─────────────────\n")
	
	for _, file := range files {
		fmt.Printf("\n📄 %s\n", file.Name)
		if expectedHash != "" {
			fmt.Printf("   Match: %s\n", file.Match)
		}
		fmt.Printf("   MD5:    %s\n", file.MD5)
		fmt.Printf("   SHA1:   %s\n", file.SHA1)
		fmt.Printf("   SHA256: %s\n", file.SHA256)
	}

	if expectedHash != "" {
		matches := 0
		for _, file := range files {
			if file.Match == "✓" {
				matches++
			}
		}
		
		fmt.Printf("\n📈 DATA:\n")
		fmt.Printf("─────────────────\n")
		fmt.Printf("✅ Matching file: %d/%d\n", matches, len(files))
		if matches == len(files) {
			fmt.Printf("🎉 All files match the reference hash!\n")
		} else if matches == 0 {
			fmt.Printf("❌ No files match the reference hash.\n")
		} else {
			fmt.Printf("⚠️  Only some files match the reference hash.\n")
		}
	}
}

func main() {
	var (
		directory = flag.String("dir", "", "Directory to scan (required)")
		hash      = flag.String("hash", "", "External hash for comparison (optional)")
		help      = flag.Bool("help", false, "Show help message")
	)

	flag.Usage = func() {
		fmt.Printf("🔐 FILE CHECKSUM \n")
		fmt.Printf("═══════════════════════════\n\n")
		fmt.Printf("Calcute hash MD5, SHA1 e SHA256 for all files\n")
		fmt.Printf("in a directory and optionally compares them to a specific hash\n\n")
		fmt.Printf("USE:\n")
		fmt.Printf("  %s -dir <directory> [-hash <hash>]\n\n", os.Args[0])
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *directory == "" {
		fmt.Printf("❌ Error: Directory is a required parameter.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if info, err := os.Stat(*directory); err != nil {
		fmt.Printf("❌ Error: Unable to access directory '%s': %v\n", *directory, err)
		os.Exit(1)
	} else if !info.IsDir() {
		fmt.Printf("❌ Error: '%s' is not a directory.\n", *directory)
		os.Exit(1)
	}

	if *hash != "" {
		*hash = strings.ToLower(strings.TrimSpace(*hash))
		if len(*hash) != 32 && len(*hash) != 40 && len(*hash) != 64 {
			fmt.Printf("❌ Errore: Hash non valido. Lunghezze supportate: 32 (MD5), 40 (SHA1), 64 (SHA256)\n")
			os.Exit(1)
		}
	}

	fmt.Printf("🚀 Scanning...\n")
	fmt.Printf("📁 Directory: %s\n", *directory)
	if *hash != "" {
		fmt.Printf("🎯 Hash: %s\n", strings.ToUpper(*hash))
	}
	fmt.Printf("─────────────────────────────────────────\n")

	files, err := scanDirectory(*directory, *hash)
	if err != nil {
		fmt.Printf("❌ Error during scanning: %v\n", err)
		os.Exit(1)
	}

	// print
	printResults(files, *hash)
}