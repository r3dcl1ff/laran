package main

import (
        "bufio"
        "flag"
        "fmt"
        "os"
        "os/exec"
        "strings"
)

func main() {
        // Print banner
        fmt.Println("\033[36m=====Laran by r3dcl1ff @Redflare-Cyber=====\033[0m")

        // Command-line flags
        fileExt := flag.String("f", "", "Specify file extension(s) to search for, e.g., -f conf,txt")
        fileExtLong := flag.String("files", "", "Specify file extension(s) to search for, e.g., --files conf,txt")
        vector := flag.String("vt", "", "Specify vector(s) to check, e.g., -vt xss,sqli")
        vectorLong := flag.String("vector", "", "Specify vector(s) to check, e.g., --vector xss,sqli")
        typeFlag := flag.String("type", "", "Specify type to filter, e.g., --type log ")
        listFlag := flag.Bool("l", false, "Display list of potential exposed file extensions")
        listFlagLong := flag.Bool("list", false, "Display list of potential exposed file extensions")
        help := flag.Bool("h", false, "Display help")
        helpLong := flag.Bool("help", false, "Display help")

        flag.Parse()

        // Display help message
        if *help || *helpLong {
                fmt.Println("Usage: laran [options]")
                fmt.Println("Options:")
                fmt.Println("  -h, --help        Display help")
                fmt.Println("  -l, --list        Display list of potential exposed file extensions")
                fmt.Println("  -f, --files       Specify file extension(s) to search for, e.g., -f conf,txt")
                fmt.Println("  -vt, --vector     Specify vector(s) to check, e.g., -vt xss,sqli")
                fmt.Println("  --type            Specify type to filter, e.g., --type log,ide,office,app,code,backup,hidden,database,source,creds,pass,conf")
                os.Exit(0)
        }

        // Display list of potential exposed file extensions
        if *listFlag || *listFlagLong {
                sensitiveExtensionsMap := getSensitiveExtensionsMap()
                categoryColors := getCategoryColors()
                fmt.Println("Potential exposed file extensions:")
                for category, extensions := range sensitiveExtensionsMap {
                        colorCode := categoryColors[category]
                        fmt.Printf("\n%s%s:%s\n", colorCode, category, "\033[0m")
                        fmt.Printf("  %s\n", strings.Join(extensions, ", "))
                }
                os.Exit(0)
        }

        // Read URLs from stdin
        urls := []string{}
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
                url := scanner.Text()
                urls = append(urls, url)
        }
        if err := scanner.Err(); err != nil {
                fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
                os.Exit(1)
        }

        // List of sensitive file extensions
        sensitiveExtensions := getSensitiveExtensions()

        // List of vulnerability vectors
        vectors := []string{
                "xss", "sqli", "rce", "ssrf", "lfi", "redirect", "ssti",
                // Add more vectors where applicable,limited by GF dependency
        }

        // Map results grouped by category
        results := make(map[string][]string)

        // Get file extension(s) to search for
        exts := *fileExt
        if exts == "" {
                exts = *fileExtLong
        }

        // Get vector(s) to search for
        vt := *vector
        if vt == "" {
                vt = *vectorLong
        }

        // Get type to filter
        typ := *typeFlag

        // Map  flags to category names
        typeToCategory := map[string]string{
                "ide":      "Editor and IDE Project Files",
                "office":   "Office Documents and Data Files",
                "app":      "Application and Package Files",
                "code":     "Additional Extensions from Original Code",
                "backup":   "Backup and Temporary Files",
                "hidden":   "Hidden Files and Directories",
                "database": "Database Files and Dumps",
                "source":   "Source Code and Script Files",
                "creds":    "Credentials, Keys, and Certificate Files",
                "pass":     "Other Sensitive Files",
                "conf":     "Configuration and Environment Files",
                "log":      "Log and Dump Files",
        }

        // Process according to flags provided
        if typ != "" {
                // Process specified type
                categoryName, ok := typeToCategory[typ]
                if !ok {
                        fmt.Fprintf(os.Stderr, "Unknown type: %s\n", typ)
                        os.Exit(1)
                }
                extensionsMap := getSensitiveExtensionsMap()
                extsList, ok := extensionsMap[categoryName]
                if !ok {
                        fmt.Fprintf(os.Stderr, "No extensions found for category: %s\n", categoryName)
                        os.Exit(1)
                }
                for _, url := range urls {
                        for _, ext := range extsList {
                                if strings.HasSuffix(url, "."+ext) {
                                        key := categoryName
                                        results[key] = append(results[key], url)
                                        break
                                }
                        }
                }
        }

        if exts != "" {
                // Process specified file extension(s)
                extsList := strings.Split(exts, ",")
                for _, url := range urls {
                        for _, ext := range extsList {
                                ext = strings.TrimSpace(ext)
                                if strings.HasSuffix(url, "."+ext) {
                                        key := "files_." + ext
                                        results[key] = append(results[key], url)
                                        break
                                }
                        }
                }
        }

        if vt != "" {
                // Process specified vulnerability vector(s)
                vtsList := strings.Split(vt, ",")
                for _, v := range vtsList {
                        v = strings.TrimSpace(v)
                        if !contains(vectors, v) {
                                fmt.Fprintf(os.Stderr, "Unknown vector: %s\n", v)
                                continue
                        }
                        matches, err := runGf(v, urls)
                        if err != nil {
                                fmt.Fprintf(os.Stderr, "Error running gf: %v\n", err)
                                os.Exit(1)
                        }
                        if len(matches) > 0 {
                                results[v] = matches
                        }
                }
        }

        if typ == "" && exts == "" && vt == "" {
                // Default use: process sensitive files and all vectors
                // Process sensitive files
                for _, url := range urls {
                        for _, ext := range sensitiveExtensions {
                                if strings.HasSuffix(url, "."+ext) {
                                        results["sensitive_files"] = append(results["sensitive_files"], url)
                                        break
                                }
                        }
                }
                // Process each vector
                for _, v := range vectors {
                        matches, err := runGf(v, urls)
                        if err != nil {
                                fmt.Fprintf(os.Stderr, "Error running gf: %v\n", err)
                                os.Exit(1)
                        }
                        if len(matches) > 0 {
                                results[v] = matches
                        }
                }
        }

        // Print results grouped by category
        for key, urls := range results {
                fmt.Printf("\033[32mResults for %s:\033[0m\n", key)
                for _, url := range urls {
                        fmt.Println(url)
                }
                fmt.Println()
        }
}

// Function to map  sensitive file extensions grouped by category
func getSensitiveExtensionsMap() map[string][]string {
        return map[string][]string{
                "Backup and Temporary Files": {
                        "bak", "bak~", "backup", "old", "orig", "save", "tmp", "temp", "copy", "~",
                },
                "Configuration and Environment Files": {
                        "conf", "config", "cfg", "ini", "env", "properties", "xml", "json", "yml", "yaml", "toml", "plist",
                },
                "Log and Dump Files": {
                        "log", "out", "err", "trace", "dump",
                },
                "Database Files and Dumps": {
                        "sql", "sql~", "sql.gz", "sql.tar.gz", "sql.zip", "db", "db3", "sqlite", "sqlite3", "mdb", "accdb", "ldf", "mdf",
                },
                "Source Code and Script Files": {
                        "php", "php~", "py", "py~", "pyc", "jsp", "asp", "asp~", "aspx", "aspx~", "pl", "rb", "rb~", "cgi",
                        "sh", "bash", "zsh", "c", "cpp", "cs", "java", "class", "jar", "war", "js", "ts", "go", "swift", "kt", "scala", "vb",
                },
                "Credentials, Keys, and Certificate Files": {
                        "pem", "key", "crt", "cer", "der", "pfx", "p12", "jks", "keystore", "ovpn", "rdp", "ppk", "id_rsa",
                        "id_rsa.pub", "ssh", "gpg", "pgp", "kdb", "kdbx", "keychain", "sso", "secrets",
                },
                "Hidden Files and Directories": {
                        "git", "svn", "hg", "bzr", "htaccess", "htpasswd", "DS_Store", "npmrc", "dockerignore", "dockercfg",
                        "dockerconfigjson", "netrc", "bash_history", "zsh_history", "history",
                },
                "Editor and IDE Project Files": {
                        "swp", "swp~", "swo", "idea", "vscode", "sublime-project", "sublime-workspace", "project", "classpath",
                        "metadata", "iml",
                },
                "Office Documents and Data Files": {
                        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "csv",
                },
                "Application and Package Files": {
                        "apk", "ipa", "exe", "dll", "so", "dmg", "iso", "img", "app", "deb", "rpm",
                },
                "Other Sensitive Files": {
                        "passwd", "shadow", "mobileconfig", "keytab",
                },
                "Additional Extensions from Original Code": {
                        "bkp", "cache", "html", "inc", "lock", "rar", "tar", "tar.bz2", "tar.gz", "txt", "wadl", "zip",
                },
        }
}

// Function to color code each category
func getCategoryColors() map[string]string {
        return map[string]string{
                "Backup and Temporary Files":               "\033[31m", // Red
                "Configuration and Environment Files":      "\033[32m", // Green
                "Log and Dump Files":                       "\033[33m", // Yellow
                "Database Files and Dumps":                 "\033[34m", // Blue
                "Source Code and Script Files":             "\033[35m", // Magenta
                "Credentials, Keys, and Certificate Files": "\033[36m", // Cyan
                "Hidden Files and Directories":             "\033[91m", // Bright Red
                "Editor and IDE Project Files":             "\033[92m", // Bright Green
                "Office Documents and Data Files":          "\033[93m", // Bright Yellow
                "Application and Package Files":            "\033[94m", // Bright Blue
                "Other Sensitive Files":                    "\033[95m", // Bright Magenta
                "Additional Extensions from Original Code": "\033[96m", // Bright Cyan
        }
}

// Function to get a flat list of all sensitive file extensions
func getSensitiveExtensions() []string {
        extensionsMap := getSensitiveExtensionsMap()
        extensionsSet := make(map[string]struct{})
        for _, exts := range extensionsMap {
                for _, ext := range exts {
                        extensionsSet[ext] = struct{}{}
                }
        }
        extensions := []string{}
        for ext := range extensionsSet {
                extensions = append(extensions, ext)
        }
        return extensions
}

// Function to execute gf with a specific vector
func runGf(vector string, urls []string) ([]string, error) {
        cmd := exec.Command("gf", vector)
        stdin, err := cmd.StdinPipe()
        if err != nil {
                return nil, err
        }
        stdout, err := cmd.StdoutPipe()
        if err != nil {
                return nil, err
        }
        if err := cmd.Start(); err != nil {
                return nil, err
        }

        // Write URLs to gf's stdin
        go func() {
                defer stdin.Close()
                writer := bufio.NewWriter(stdin)
                for _, url := range urls {
                        writer.WriteString(url + "\n")
                }
                writer.Flush()
        }()

        // Read gf's output
        matches := []string{}
        scanner := bufio.NewScanner(stdout)
        for scanner.Scan() {
                line := scanner.Text()
                matches = append(matches, line)
        }
        if err := scanner.Err(); err != nil {
                return nil, err
        }
        if err := cmd.Wait(); err != nil {
                return nil, err
        }
        return matches, nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
        for _, s := range slice {
                if s == item {
                        return true
                }
        }
        return false
}
