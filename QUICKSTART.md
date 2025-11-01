# Quick Start Guide

Get started with APK/AAR Obfuscation Analyzer in 5 minutes.

## Prerequisites Check

```bash
# Check Python version (need 3.6+)
python3 --version

# Check jadx installation
jadx --version
```

If jadx is not installed:
```bash
# Ubuntu/Debian
sudo apt-get install jadx

# macOS
brew install jadx
```

## Step 1: Get APK or AAR Files

**Option A: Comparison Mode** (requires two files)
You need two files to compare:
1. Original (unobfuscated) APK or AAR
2. Obfuscated APK or AAR

**Option B: Single-File Mode** (requires one file)
Analyze a single APK or AAR when:
- You don't have the original version
- Obfuscation status is unknown
- Analyzing third-party libraries

Place them in the `apks/` directory:
```bash
cd apk-obfuscation-analyzer

# For APK files
cp /path/to/your/original.apk apks/myapp_original.apk
cp /path/to/your/obfuscated.apk apks/myapp_obfuscated.apk

# For AAR files (Android libraries)
cp /path/to/your/library.aar apks/mylib_original.aar
cp /path/to/your/library-obfuscated.aar apks/mylib_obfuscated.aar
```

**Don't have files?** See [SAMPLE_APKS.md](SAMPLE_APKS.md) for how to get test APKs/AARs.

## Step 2: Run the Analyzer

**For Comparison (two files):**
```bash
./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk
```

This will:
1. Decompile both APKs (takes 1-3 minutes)
2. Compare code obfuscation changes
3. Generate reports in `results/` directory

**For Single File Analysis:**
```bash
./analyzer.py apks/myapp.apk
# or
./analyzer.py apks/third_party_library.aar
```

This will:
1. Decompile the APK/AAR (takes 1-3 minutes)
2. Assess obfuscation likelihood (0-100 score)
3. Identify obfuscation indicators
4. Generate reports in `results/` directory

## Step 3: View Results

Open the HTML report in your browser:
```bash
# Find the latest report
ls -lt results/report_*.html | head -1

# Open in browser (Linux)
xdg-open results/report_*.html

# Open in browser (macOS)
open results/report_*.html

# Open in browser (Windows)
start results/report_*.html
```

Or view JSON data:
```bash
cat results/analysis_*.json | python3 -m json.tool
```

## Understanding Your Score

The analyzer gives a score from 0-100:

- **0-30 (Low)**: Minimal obfuscation
  - Action: Enable ProGuard/R8
  - See: [proguard-example.pro](proguard-example.pro)

- **31-60 (Medium)**: Moderate obfuscation
  - Action: Use more aggressive settings
  - Consider: String encryption, control flow obfuscation

- **61-100 (High)**: Strong obfuscation
  - Action: Maintain current settings
  - Consider: DexGuard for even stronger protection

## Common Commands

### Single File Analysis (APK or AAR)
```bash
# Analyze one APK
./analyzer.py app.apk

# Analyze one AAR library
./analyzer.py library.aar

# With custom output directory
./analyzer.py third_party_library.aar -o ./my_results
```

### Comparison Analysis (Two Files)
```bash
# Compare two APKs
./analyzer.py original.apk obfuscated.apk

# Compare two AAR libraries
./analyzer.py mylibrary.aar mylibrary_obfuscated.aar
```

### Custom Output Directory
```bash
./analyzer.py original.apk obfuscated.apk -o ./my_results
```

### Verbose Mode (shows AAR extraction for libraries)
```bash
./analyzer.py mylibrary.aar mylibrary_obfuscated.aar -v
```

### Batch Processing (APKs and AARs)
```bash
# Analyze multiple APK/AAR pairs (comparison mode)
./batch_analyze.sh -d ./apks -o ./results

# Analyze all files individually (single-file mode)
./batch_analyze.sh -d ./apks -o ./results --single
```

### Run Tests
```bash
./test_obfuscation.py
```

## Example: Building Test Files

### Building APKs

If you have an Android app project:

**Build WITHOUT Obfuscation:**

Edit `app/build.gradle`:
```gradle
android {
    buildTypes {
        release {
            minifyEnabled false  // Disable
        }
    }
}
```

Build:
```bash
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk ../apks/myapp_original.apk
```

**Build WITH Obfuscation:**

Edit `app/build.gradle`:
```gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // Enable
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
        }
    }
}
```

Build:
```bash
./gradlew clean assembleRelease
cp app/build/outputs/apk/release/app-release.apk ../apks/myapp_obfuscated.apk
```

### Building AARs

If you have an Android library project:

**Build WITHOUT Obfuscation:**

Edit `library/build.gradle`:
```gradle
android {
    buildTypes {
        release {
            minifyEnabled false  // Disable
        }
    }
}
```

Build:
```bash
./gradlew :library:assembleRelease
cp library/build/outputs/aar/library-release.aar ../apks/mylib_original.aar
```

**Build WITH Obfuscation:**

Edit `library/build.gradle`:
```gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // Enable
            proguardFiles 'proguard-rules.pro'
        }
    }
}
```

Build:
```bash
./gradlew clean :library:assembleRelease
cp library/build/outputs/aar/library-release.aar ../apks/mylib_obfuscated.aar
```

### Analyze
```bash
cd apk-obfuscation-analyzer

# For APKs
./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk

# For AARs
./analyzer.py apks/mylib_original.aar apks/mylib_obfuscated.aar
```

## Interpreting Results

### Good Signs (Effective Obfuscation)
- High percentage of single-character class names
- Low percentage of meaningful names
- High string entropy
- Increased control flow complexity

### Warning Signs (Weak Obfuscation)
- Many readable class/method names
- Plain text strings
- Low complexity increase
- Recommendations in report

## Improving Your Score

### 1. Enable R8/ProGuard
```gradle
android {
    buildTypes {
        release {
            minifyEnabled true
        }
    }
}
```

### 2. Use Aggressive Settings
Add to `proguard-rules.pro`:
```proguard
-repackageclasses ''
-allowaccessmodification
-overloadaggressively
```

### 3. String Encryption (DexGuard)
```proguard
-encryptstrings class com.yourapp.** {
    private static final java.lang.String *;
}
```

### 4. Control Flow Obfuscation (DexGuard)
```proguard
-obfuscatecontrolflow class com.yourapp.** {
    public *;
}
```

See [proguard-example.pro](proguard-example.pro) for complete configuration.

## Troubleshooting

### "jadx not found"
```bash
# Install jadx
sudo apt-get install jadx  # Ubuntu/Debian
brew install jadx          # macOS

# Or specify path
./analyzer.py original.apk obfuscated.apk --jadx-path /path/to/jadx
```

### "APK not found"
```bash
# Check file exists
ls -l apks/*.apk

# Use absolute paths
./analyzer.py /full/path/to/original.apk /full/path/to/obfuscated.apk
```

### "Score is 0"
- APKs might be identical
- Obfuscation not applied
- Check ProGuard/R8 is enabled: `minifyEnabled true`

### "Decompilation failed"
- APK might be corrupted
- Try manual decompilation: `jadx -d output input.apk`
- Check jadx version: `jadx --version`

## Next Steps

1. **Read the full documentation**: [README.md](README.md)
2. **Learn about sample APKs**: [SAMPLE_APKS.md](SAMPLE_APKS.md)
3. **See example usage**: [example_usage.sh](example_usage.sh)
4. **Review ProGuard config**: [proguard-example.pro](proguard-example.pro)

## Docker Usage (Alternative)

If you prefer Docker:

```bash
# Build image
docker build -t apk-analyzer .

# Run analysis
docker run -v $(pwd)/apks:/apks -v $(pwd)/results:/results apk-analyzer \
    /apks/myapp_original.apk /apks/myapp_obfuscated.apk -o /results

# View results
open results/report_*.html
```

## Getting Help

- Check the [README.md](README.md) for detailed documentation
- Run tests: `./test_obfuscation.py`
- Enable verbose mode: `-v` flag
- Review sample configurations: `proguard-example.pro`

## Summary

**Comparison Mode (Two Files):**
```bash
# 1. Install jadx
sudo apt-get install jadx

# 2. Get APKs
cp original.apk apks/myapp_original.apk
cp obfuscated.apk apks/myapp_obfuscated.apk

# 3. Analyze
./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk

# 4. View report
open results/report_*.html

# 5. Improve based on recommendations
```

**Single-File Mode (One File):**
```bash
# 1. Install jadx
sudo apt-get install jadx

# 2. Get APK or AAR
cp app.apk apks/myapp.apk
# or
cp library.aar apks/mylibrary.aar

# 3. Analyze
./analyzer.py apks/myapp.apk

# 4. View report
open results/single_report_*.html

# 5. Assess obfuscation level and improve if needed
```

**That's it!** You now have a complete analysis of your APK/AAR obfuscation effectiveness.
