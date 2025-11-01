# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
