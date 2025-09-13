# RawrZ Security Platform - Standalone CLI

A comprehensive standalone security platform with 72+ security features. No IRC, no network dependencies - pure command-line security tools.

## Features

**72+ Security Commands** across multiple categories:

### 🔐 Core Crypto (7 commands)
- `encrypt`, `decrypt`, `hash`, `keygen`, `advancedcrypto`, `sign`, `verify`

### 🔤 Encoding (6 commands)  
- `base64encode`, `base64decode`, `hexencode`, `hexdecode`, `urlencode`, `urldecode`

### 🎲 Random Generation (3 commands)
- `random`, `uuid`, `password`

### 🔍 Analysis (3 commands)
- `analyze`, `sysinfo`, `processes`

### 🌐 Network (5 commands)
- `ping`, `dns`, `portscan`, `traceroute`, `whois`

### 📁 File Operations (3 commands)
- `files`, `upload`, `fileops`

### 📝 Text Operations (5 sub-operations)
- `textops` (uppercase, lowercase, reverse, wordcount, charcount)

### ✅ Validation (4 types)
- `validate` (email, url, ip, json)

### ⚙️ Utilities (3 commands)
- `time`, `math`, `help`

## Installation

1. Clone the repository
2. Install dependencies: `npm install`
3. Run: `node rawrz-standalone.js help`

## Usage

### Direct Node.js execution:
```bash
node rawrz-standalone.js encrypt aes256 C:\Windows\calc.exe .exe
node rawrz-standalone.js analyze C:\Windows\calc.exe
node rawrz-standalone.js portscan google.com 80 443
```

### Using the batch file:
```bash
.\rawrz-standalone.bat encrypt aes256 C:\Windows\calc.exe .exe
.\rawrz-standalone.bat help
```

### Using npm scripts:
```bash
npm start                    # Show help
npm run help                 # Show help
npm test                     # System info test
```

## Key Features

- **Custom File Extensions** - All applicable commands support custom extensions
- **Multiple Input Types** - URLs, local files, absolute paths, home directory
- **File Analysis** - Detects file types, calculates entropy, generates hashes
- **Network Tools** - Port scanning, traceroute, WHOIS, DNS lookup
- **Text Processing** - Case conversion, counting, validation
- **Mathematical Operations** - Expression evaluation
- **Professional Output** - Clean, organized results

## Examples

```bash
# Encrypt with custom extension
node rawrz-standalone.js encrypt aes256 C:\Windows\calc.exe .exe

# Analyze file
node rawrz-standalone.js analyze C:\Windows\calc.exe

# Port scan
node rawrz-standalone.js portscan google.com 80 443

# Base64 encode
node rawrz-standalone.js base64encode "Hello World"

# Validate email
node rawrz-standalone.js validate user@example.com email

# Text operations
node rawrz-standalone.js textops uppercase "hello world"

# Math operations
node rawrz-standalone.js math "2 + 2 * 3"
```

## File Input Support

- **URLs**: `https://example.com/file`
- **Local files**: `file:name.txt`
- **Absolute paths**: `C:\path\file.txt`
- **Home directory**: `~/file.txt`

## Custom Extensions

All applicable commands support custom file extensions:
- Encryption: `.exe`, `.enc`, `.bin`, `.dat`
- Hashes: `.hash`, `.txt`, `.json`
- Keys: `.key`, `.pem`, `.txt`
- Network: `.ping`, `.txt`, `.log`

## Utilities Included

- **Emoji Removal System** - Remove emojis from code files
- **File Management** - Upload, download, copy, move, delete
- **System Monitoring** - Process lists, system information

## License

MIT License - See LICENSE file for details