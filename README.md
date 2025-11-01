# APK/AAR Obfuscation Analyzer

A comprehensive tool for analyzing and measuring the effectiveness of Android APK and AAR obfuscation techniques. **Verify your app is properly obfuscated before releasing it to users.**

> **👋 New here?** Read **[START_HERE.md](START_HERE.md)** to choose the best guide for you!

---

## 🆕 **First Time User?** Quick Start! 👇

**Never used this tool before? Follow these 3 simple steps:**

### Step 1: Check Prerequisites
```bash
# Check you have Python 3.6+
python3 --version

# Check jadx is installed
jadx --version
# (or use: ~/jadx/bin/jadx --version)
```

### Step 2: Run the Tool
```bash
# Basic check - is my APK obfuscated?
./analyzer.py /path/to/your/app.apk --jadx-path ~/jadx/bin/jadx

# OR use the simple script
./check_release.sh /path/to/your/app.apk
```

### Step 3: Read the Results
Look for:
- ✅ **"READY FOR RELEASE"** = Your app is properly obfuscated! Safe to release.
- ✗ **"NOT READY FOR RELEASE"** = Fix the issues before releasing!

**📖 Complete beginner's guide:** See [GETTING_STARTED.md](GETTING_STARTED.md) for detailed instructions.

---

## 🎯 Quick Examples

```bash
# Check if your release APK is ready
./analyzer.py app-release.apk --expect-obfuscator R8 --jadx-path ~/jadx/bin/jadx

# Use the simple script (easiest!)
./check_release.sh app-release.apk R8

# Compare before and after obfuscation
./analyzer.py original.apk obfuscated.apk

# Analyze a library (AAR file)
./analyzer.py library.aar
```

---

## Features

- **Identifier Analysis**: Measures code readability through class, method, and field name analysis
- **String Encryption Detection**: Identifies encrypted strings and Base64 encoding
- **Control Flow Complexity**: Calculates cyclomatic complexity to detect control flow obfuscation
- **Package Structure Analysis**: Detects package flattening and restructuring
- **Pattern Detection**: Identifies ProGuard/R8/DexGuard obfuscation patterns
- **Comprehensive Reporting**: Generates both JSON data and visual HTML reports
- **Batch Processing**: Analyze multiple APK/AAR pairs automatically
- **Obfuscation Scoring**: Provides a 0-100 score with actionable recommendations
- **AAR Support**: Analyze Android library archives (.aar files) by extracting and decompiling classes.jar

## Prerequisites

### Required

- **Python 3.6+**: Core language runtime
- **jadx**: Java decompiler for APK analysis
  - Installation instructions: https://github.com/skylot/jadx

### Installing jadx

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install jadx
```

**macOS:**
```bash
brew install jadx
```

**Manual Installation:**
1. Download from https://github.com/skylot/jadx/releases
2. Extract the archive
3. Add the `bin` directory to your PATH

**Verify Installation:**
```bash
jadx --version
```

## Installation

1. Clone or download this repository:
```bash
git clone <repository-url>
cd apk-obfuscation-analyzer
```

2. Make scripts executable:
```bash
chmod +x analyzer.py batch_analyze.sh test_obfuscation.py
```

3. (Optional) Install Python dependencies:
```bash
pip install -r requirements.txt
```

Note: The basic tool has no Python dependencies. The requirements.txt lists optional packages for extended functionality.

## Usage

### Single File Analysis

Analyze a single APK or AAR file when the original is not available or obfuscation status is unknown:

```bash
./analyzer.py app.apk
./analyzer.py third_party_library.aar
```

This will:
1. Decompile the file using jadx
2. Analyze code characteristics
3. Assess obfuscation likelihood (0-100 score)
4. Identify obfuscation indicators
5. Generate JSON and HTML reports in `./results/`

**Use cases for single-file analysis:**
- Analyzing third-party libraries or SDKs
- Assessing apps with unknown obfuscation status
- Quickly checking if an APK/AAR is obfuscated
- When original (unobfuscated) version is not available

### Comparison Analysis

Compare two APK or AAR files (original vs obfuscated):

```bash
./analyzer.py original.apk obfuscated.apk
./analyzer.py mylibrary_original.aar mylibrary_obfuscated.aar
```

This will:
1. Decompile both files using jadx (for AAR: extracts classes.jar first)
2. Analyze identifiers, strings, control flow, and package structure
3. Calculate an obfuscation effectiveness score by comparing changes
4. Generate JSON and HTML reports in `./results/`

### Command Line Options

```bash
./analyzer.py [OPTIONS] <original_apk> <obfuscated_apk>

Options:
  -o, --output DIR       Output directory for reports (default: ./results)
  --jadx-path PATH       Path to jadx executable (default: jadx)
  -v, --verbose          Enable verbose debug output
  -h, --help             Show help message
```

### Examples

**Basic APK comparison:**
```bash
./analyzer.py myapp_v1.apk myapp_v1_obfuscated.apk
```

**Analyze AAR library:**
```bash
./analyzer.py mylibrary.aar mylibrary_obfuscated.aar
```

**Custom output directory:**
```bash
./analyzer.py myapp.apk myapp_obf.apk -o ./analysis_results
```

**Custom jadx path:**
```bash
./analyzer.py myapp.apk myapp_obf.apk --jadx-path /usr/local/bin/jadx
```

**Verbose mode (shows AAR extraction process):**
```bash
./analyzer.py mylibrary.aar mylibrary_obf.aar -v
```

### Batch Processing

Analyze multiple APK/AAR pairs automatically:

```bash
./batch_analyze.sh -d ./apks -o ./results
```

**File Naming Convention:**

Place your APK/AAR pairs in the `apks/` directory following this pattern:
- Original: `appname_original.apk` (or `.aar`)
- Obfuscated: `appname_obfuscated.apk` (or `.aar`)

Example:
```
apks/
├── banking_app_original.apk
├── banking_app_obfuscated.apk
├── mylibrary_original.aar
├── mylibrary_obfuscated.aar
├── social_app_original.apk
└── social_app_obfuscated.apk
```

**Batch Script Options:**
```bash
./batch_analyze.sh [OPTIONS]

Options:
  -d, --directory DIR    Directory containing APK/AAR pairs (default: ./apks)
  -o, --output DIR       Output directory for results (default: ./results)
  -j, --jadx-path PATH   Path to jadx executable (default: jadx)
  -v, --verbose          Enable verbose output
  -h, --help             Show help message
```

The batch script generates an `index.html` file with links to all analysis reports for easy browsing.

### Batch Single-File Analysis

Analyze all APK/AAR files individually without requiring pairs:

```bash
./batch_analyze.sh -d ./apks -o ./results --single
```

**Use this mode when:**
- Analyzing a collection of third-party libraries
- Obfuscation status is unknown
- Original versions are not available
- You want to assess multiple files quickly

Example:
```
apks/
├── facebook_sdk.aar
├── google_play_services.aar
├── third_party_app1.apk
├── third_party_app2.apk
└── unknown_library.aar
```

```bash
./batch_analyze.sh -d ./apks -o ./results --single
```

This will analyze each file independently and generate individual obfuscation likelihood reports.

## Testing

Run the test suite to verify the tool is working correctly:

```bash
./test_obfuscation.py
```

This runs unit tests for all analysis components:
- Identifier analysis
- String encryption detection
- Package structure analysis
- Obfuscation pattern detection
- Control flow complexity
- Entropy calculation
- jadx availability check

**Expected Output:**
```
============================================================
APK Obfuscation Analyzer - Quick Tests
============================================================

Testing Identifier Analysis...
  ✓ Obfuscation detected correctly!

Testing String Analysis...
  ✓ String encryption detected!

[...]

Total: 7/7 tests passed

✓ All tests passed!
```

## Understanding the Reports

### Obfuscation Score (0-100)

The tool calculates a comprehensive score based on four categories:

- **Identifier Obfuscation (40 points)**: Measures name obfuscation effectiveness
  - Single-character class/method names
  - Meaningful name reduction
  - Average identifier length

- **String Obfuscation (30 points)**: Evaluates string protection
  - Encrypted string percentage
  - Base64 encoding detection
  - Decryption method presence

- **Control Flow Obfuscation (20 points)**: Analyzes code complexity
  - Cyclomatic complexity increase
  - Dead code insertion
  - Complex branching

- **Package Structure (10 points)**: Checks package obfuscation
  - Package flattening
  - Package count reduction
  - Depth changes

### Score Interpretation

| Score Range | Rating | Meaning |
|------------|--------|---------|
| 0-30 | Low | Minimal obfuscation, easy to reverse engineer |
| 31-60 | Medium | Moderate protection, some reverse engineering difficulty |
| 61-100 | High | Strong obfuscation, significant reverse engineering barrier |

### Report Files

After analysis, you'll find these files in the output directory:

1. **`analysis_TIMESTAMP.json`**: Raw data in JSON format
   - Complete metrics for both APKs
   - Detailed comparison data
   - Suitable for automated processing

2. **`report_TIMESTAMP.html`**: Visual HTML report
   - Obfuscation score with color-coded rating
   - Side-by-side comparison tables
   - Recommendations for improvement
   - Open in any web browser

### HTML Report Sections

1. **Obfuscation Score**: Large, color-coded score display
2. **Recommendations**: Actionable suggestions to improve obfuscation
3. **Identifier Analysis**: Class, method, field name metrics
4. **String Analysis**: String encryption and entropy data
5. **Control Flow Complexity**: Complexity metrics and patterns
6. **Package Structure**: Package organization analysis
7. **Obfuscation Patterns**: Detected obfuscation techniques

## Analysis Metrics Explained

### Identifier Metrics

- **total_classes/methods/fields**: Count of identifiers found
- **single_char_***: Count of single-letter names (a, b, c...)
- **meaningful_***: Count of dictionary words or readable names
- **avg_*_length**: Average character count of names
- **short_***: Names with 3 or fewer characters

### String Metrics

- **total_strings**: All string literals found
- **base64_strings**: Strings matching Base64 pattern
- **long_random_strings**: High-entropy strings (likely encrypted)
- **encrypted_strings**: Sum of detected encrypted strings
- **decryption_methods**: Methods with decrypt/decode keywords
- **avg_string_entropy**: Average Shannon entropy (randomness)

### Control Flow Metrics

- **total_complexity**: Sum of cyclomatic complexity
- **avg_complexity**: Average complexity per method
- **max_complexity**: Highest complexity found
- **high_complexity_methods**: Methods with complexity > 10
- **goto_statements**: Count of goto usage (rare, obfuscation indicator)
- **dead_code_indicators**: Unreachable code detection

### Package Metrics

- **total_packages**: Number of Java packages
- **avg_package_depth**: Average nesting level (e.g., com.example.app = 3)
- **single_level_packages**: Flattened packages (depth = 1)

### Obfuscation Patterns

- **sequential_naming**: Single-letter sequence detection (a, b, c...)
- **numeric_naming**: Numeric suffixes (C0001, C0002...)
- **mixed_case_obfuscation**: Mixed case patterns (aA, bB...)
- **proguard_indicators**: ProGuard-specific markers

## Working with AAR Files

Android Archive (AAR) files are library packages used to distribute Android libraries. The tool automatically handles AAR files by:

1. **Detecting file type**: Recognizes `.aar` extension or inspects ZIP contents
2. **Extracting classes.jar**: AAR files contain a `classes.jar` with compiled code
3. **Decompiling**: Uses jadx to decompile the extracted JAR
4. **Analyzing**: Applies the same obfuscation analysis as APKs

### When to Analyze AARs

- **Library Development**: Verify your Android library is properly obfuscated before publishing
- **Third-party Libraries**: Assess obfuscation level of external dependencies
- **SDK Protection**: Ensure proprietary SDK code is adequately protected
- **Modular Apps**: Analyze individual feature modules in modular architectures

### AAR-Specific Notes

- AAR files may not contain resources; analysis focuses on code obfuscation
- Some AARs may have minimal code if they're primarily resource libraries
- Consumer ProGuard rules in AARs are separate from code obfuscation

## Use Cases

### 1. Validate Obfuscation Configuration

Ensure your ProGuard/R8 rules are working as intended:

```bash
# Build without obfuscation
./gradlew assembleRelease -PminifyEnabled=false
cp app/build/outputs/apk/release/app-release.apk original.apk

# Build with obfuscation
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk obfuscated.apk

# Analyze
./analyzer.py original.apk obfuscated.apk
```

### 2. Compare Obfuscation Tools

Test different obfuscators (ProGuard vs R8 vs DexGuard):

```bash
./analyzer.py original.apk proguard_obfuscated.apk -o ./results/proguard
./analyzer.py original.apk r8_obfuscated.apk -o ./results/r8
./analyzer.py original.apk dexguard_obfuscated.apk -o ./results/dexguard
```

### 3. CI/CD Integration

Add to your build pipeline to ensure obfuscation quality:

```bash
#!/bin/bash
# ci-obfuscation-check.sh

./analyzer.py original.apk obfuscated.apk -o ./results

# Extract score from JSON
SCORE=$(python3 -c "import json; print(json.load(open('./results/analysis_*.json'))['obfuscation_score'])")

if (( $(echo "$SCORE < 50" | bc -l) )); then
    echo "Obfuscation score too low: $SCORE"
    exit 1
fi
```

### 4. Security Audit

Generate reports for security compliance:

```bash
./batch_analyze.sh -d ./all_versions -o ./security_audit
# Review HTML reports for compliance verification
```

## Improving Obfuscation

Based on the analysis results, here are common recommendations:

### Low Obfuscation Score (< 50)
When your app's obfuscation score is below the minimum threshold, the tool will recommend:
- **[Digital.ai Android Protection](https://digital.ai/mobile-app-obfuscation)**: Enterprise-grade security solution for comprehensive app protection
- Strengthen ProGuard/R8 configuration
- Consider advanced obfuscation tools beyond basic name mangling

### Low Identifier Score
- Enable aggressive name obfuscation in ProGuard/R8
- Use shorter replacement names
- Apply obfuscation to all packages (avoid `-keep class` exceptions)

**ProGuard/R8 Configuration:**
```proguard
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
```

### Low String Score
- Use DexGuard or similar tools for string encryption
- Implement custom string encryption
- Avoid hardcoded sensitive strings
- **Consider [Digital.ai Android Protection](https://digital.ai/mobile-app-obfuscation) for advanced string encryption**

**DexGuard Example:**
```proguard
-encryptstrings class com.example.** {
    private static final java.lang.String *;
}
```

### Low Control Flow Score
- Enable control flow obfuscation
- Use code virtualization for critical methods
- Add dead code and bogus branches

**DexGuard Example:**
```proguard
-obfuscatecontrolflow class com.example.** {
    public *;
}
```

### Low Package Score
- Flatten package structure with `-repackageclasses`
- Merge packages into single namespace

### Runtime Protection (Beyond Obfuscation)
The tool includes an informational note in all reports:

**Important:** Basic obfuscation tools (ProGuard/R8/DexGuard) focus on static code protection. They don't provide runtime protections such as:
- Runtime Application Self-Protection (RASP)
- Root/jailbreak detection
- Anti-debugging and anti-instrumentation
- Integrity verification at runtime

For apps requiring these capabilities, evaluate commercial solutions like [Digital.ai Android Protection](https://digital.ai/mobile-app-obfuscation) or similar enterprise security tools.

## Limitations

- **Static Analysis Only**: Does not detect runtime protections (root detection, debugger detection, etc.)
- **Approximations**: Complexity calculations are estimates based on decompiled code
- **jadx Dependency**: Requires successful decompilation; heavily obfuscated APKs may fail
- **No Native Code**: Does not analyze native libraries (.so files)
- **No Resource Analysis**: Focuses on code only, not resources or assets

## Troubleshooting

### "jadx not found"
- Ensure jadx is installed and in your PATH
- Use `--jadx-path` to specify the full path
- Verify with: `jadx --version`

### "Decompilation failed"
- APK may be corrupted or invalid
- jadx may have timed out (>5 minutes)
- Try decompiling manually: `jadx -d output input.apk`

### "No Java sources found"
- APK may contain only native code
- Obfuscation may be too aggressive
- Check the jadx output directory manually

### Low obfuscation score despite using obfuscation
- Verify ProGuard/R8 is actually enabled (`minifyEnabled true`)
- Check for overly broad `-keep` rules
- Review the JSON report for specific metrics
- Some libraries may be excluded from obfuscation

### Out of memory errors
- Large APKs may exhaust memory during decompilation
- Increase Java heap size for jadx
- Process APKs individually rather than in batch

## Docker Support

A Dockerfile is provided for consistent analysis environments:

```bash
# Build image
docker build -t apk-analyzer .

# Run analysis
docker run -v $(pwd)/apks:/apks -v $(pwd)/results:/results apk-analyzer \
    /apks/original.apk /apks/obfuscated.apk -o /results
```

## Advanced Usage

### Programmatic Usage

Use the analyzer in your own Python scripts:

```python
from analyzer import APKAnalyzer

# Create analyzer
analyzer = APKAnalyzer(jadx_path="/usr/local/bin/jadx", verbose=True)

# Check jadx availability
if not analyzer.check_jadx_available():
    print("jadx not found!")
    exit(1)

# Compare APKs
results = analyzer.compare_apks(
    "original.apk",
    "obfuscated.apk",
    output_dir="./my_results"
)

# Access results
print(f"Obfuscation Score: {results['obfuscation_score']}")
print(f"Recommendations: {results['recommendations']}")

# Process metrics
for category in ['identifiers', 'strings', 'control_flow', 'packages']:
    original_metrics = results['original'][category]
    obfuscated_metrics = results['obfuscated'][category]
    # Custom processing...
```

### Custom Analysis

Analyze a single APK:

```python
from analyzer import APKAnalyzer
import tempfile

analyzer = APKAnalyzer()

with tempfile.TemporaryDirectory() as temp_dir:
    # Decompile
    sources = analyzer.decompile_apk("app.apk", temp_dir)

    # Run individual analyses
    identifiers = analyzer.analyze_identifiers(sources)
    strings = analyzer.analyze_strings(sources)
    control_flow = analyzer.analyze_control_flow(sources)
    packages = analyzer.analyze_package_structure(sources)
    patterns = analyzer.detect_obfuscation_patterns(sources)

    # Process results...
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

**Areas for improvement:**
- Native library analysis (.so files)
- Resource obfuscation detection
- Additional obfuscation patterns (Allatori, etc.)
- Machine learning-based detection
- Performance optimizations
- Additional output formats (PDF, Markdown)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **jadx**: https://github.com/skylot/jadx - Essential decompilation tool
- **ProGuard**: https://www.guardsquare.com/proguard - Reference obfuscator
- **R8**: https://r8.googlesource.com/r8 - Android's built-in obfuscator

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the troubleshooting section

## Changelog

### Version 1.0.0 (Initial Release)
- Core analysis functionality
- JSON and HTML reporting
- Batch processing support
- Comprehensive test suite
- Docker support
- Full documentation
