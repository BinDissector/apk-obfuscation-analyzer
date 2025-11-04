# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2025-11-03

### Fixed
- **Critical**: Fixed `NameError: name 'zlib' is not defined` in APK/AAR file validation
  - Missing `import zlib` statement caused CRC checksum validation to fail
  - Error appeared in HTML reports as "Cannot read ..." warnings for all APK files
  - Fixed by adding `import zlib` to module imports (line 15)
  - Affects `_validate_apk_aar_structure()` method at line 1484
  - All file validation and CRC checks now work correctly

- **Critical**: Fixed `FileNotFoundError` in cryptography analysis
  - `analyze_cryptography()` was iterating over directory path string instead of files
  - Caused "Failed to analyze crypto in p: [Errno 2] No such file or directory: 'p'" warnings
  - Error occurred because function expected list of files but received directory path
  - When iterating string "/tmp/sources", Python iterated characters: '/', 't', 'm', 'p', etc.
  - Fixed by changing function to accept `sources_dir` and use `os.walk()` like other analysis functions
  - Cryptographic analysis now works correctly and detects hardcoded keys, weak algorithms, etc.

- **Critical**: Fixed AndroidManifest.xml parsing error
  - Error: "'lxml.etree._Element' object has no attribute 'getElementsByTagName'"
  - `get_android_manifest_xml()` returns lxml Element, not DOM object
  - Fixed by using lxml methods: `.tag`, `.get()`, `.find()` instead of DOM methods
  - Manifest validation now works correctly with proper encoding (UTF-8)

### Added
- **New Feature**: AndroidManifest.xml Permission Analysis with risk-based color-coding
  - Extracts all permissions from manifest and categorizes by risk level
  - Risk categories: CRITICAL (red), HIGH (yellow), MEDIUM (blue), LOW (green), UNKNOWN (gray)
  - Calculates permission risk score (0-100) and rating (LOW/MEDIUM/HIGH)
  - Color-coded terminal output for easy visual identification
  - Classifies 60+ common Android permissions by security risk
  - Includes package metadata (name, version code, version name)
  - Integrated into single file analysis workflow

## [1.0.0] - 2025-01-01

### Fixed
- **Critical**: Fixed `TypeError: unhashable type: 'dict'` in HTML report generation
  - Issue occurred when using `{{}}` as default parameter in `.get()` calls within f-strings
  - Fixed by extracting dictionary `.get()` calls to variables before f-string usage
  - Affected functions: `_create_single_html_report()` and `_create_html_report()`
  - All 6 occurrences across 2 functions resolved
  - See `BUGFIX_UNHASHABLE_DICT.md` for detailed analysis

### Added
- Initial release of APK/AAR Obfuscation Analyzer
- Single file analysis mode for unknown obfuscation status
- Comparison mode for original vs obfuscated APK/AAR files
- Comprehensive obfuscation scoring (0-100) with four categories:
  - Identifier obfuscation analysis (40 points)
  - String encryption detection (30 points)
  - Control flow complexity (20 points)
  - Package structure analysis (10 points)
- HTML and JSON report generation
- Batch processing support for multiple APK/AAR pairs
- Release readiness checking with configurable thresholds
- Obfuscator tool detection (ProGuard, R8, DexGuard)
- Sensitive string detection (API keys, URLs, credentials)
- Readable string extraction to files
- File metadata extraction:
  - Cryptographic hashes (MD5, SHA1, SHA256)
  - APK signature information (v1, v2, v3 schemes)
  - Certificate details from signatures
- Robustness improvements:
  - Configurable jadx timeout (default: 900s/15 minutes)
  - JVM memory allocation control (default: 4G)
  - Retry logic for transient failures
  - Disk space checking before decompilation
  - Multi-threading support
- Test suite with multiple test scripts
- Docker support with Dockerfile
- Comprehensive documentation:
  - README.md with full usage guide
  - GETTING_STARTED.md for beginners
  - QUICK_REFERENCE.md for quick lookup
  - START_HERE.md as entry point
  - WHAT_TO_EXPECT.md for understanding results
  - SAMPLE_APKS.md for testing
  - DIGITAL_AI_INTEGRATION.md for enterprise solutions
  - CONTRIBUTING.md for contributors
  - CODE_OF_CONDUCT.md for community guidelines
- Shell scripts:
  - `batch_analyze.sh` for batch processing
  - `check_release.sh` for simple release checks
  - `example_usage.sh` for demonstrations
- GitHub templates:
  - Bug report template
  - Feature request template
  - Pull request template

### Changed
- Default minimum obfuscation score: 40 (recommend 50+ for high security)

### Fixed
- N/A (initial release)

### Security
- All analysis is read-only; tool does not modify APK/AAR files
- No network connections required
- Credentials and sensitive data detection in reports

---

## Release Notes Template

For future releases, use this template:

## [Version] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Deprecated
- Features that will be removed in upcoming releases

### Removed
- Features that were removed

### Fixed
- Bug fixes

### Security
- Security fixes and improvements
