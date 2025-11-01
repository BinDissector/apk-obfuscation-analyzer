# Getting Started - APK/AAR Obfuscation Analyzer

**Welcome!** This guide will help you analyze your Android app's obfuscation in just 5 minutes.

---

## 🎯 What Does This Tool Do?

This tool helps you **verify that your Android app (APK) or library (AAR) is properly obfuscated** before you release it to users.

**Why is this important?**
- ✅ Prevents accidentally releasing unobfuscated apps (exposing your code)
- ✅ Verifies your ProGuard/R8 configuration is working
- ✅ Ensures you're using the correct obfuscator
- ✅ Gives you confidence before releasing to production

---

## 📋 Prerequisites

You need **two things**:

### 1. Python 3.6 or newer
```bash
python3 --version
```
Should show: `Python 3.6+`

### 2. jadx (APK decompiler)
```bash
jadx --version
```

**Don't have jadx?** No problem! See the installation guide below.

---

## 🔧 Installing jadx

jadx was already installed for you at `~/jadx/bin/jadx`

**To make it available everywhere:**
```bash
# Add to your shell (already done in this session)
export PATH="$HOME/jadx/bin:$PATH"

# Or use the full path
~/jadx/bin/jadx --version
```

**Alternative - Install system-wide:**
```bash
# Ubuntu/Debian
sudo apt-get install jadx

# macOS
brew install jadx
```

---

## 🚀 Quick Start - Your First Analysis

### Step 1: Get Your APK File

You need an APK file to analyze. You can use:
- **Your app's release APK** - the one you're about to release
- **A test APK** - any Android app APK file
- **A downloaded APK** - for testing purposes

Example locations:
```bash
# If you built with Android Studio/Gradle:
app/build/outputs/apk/release/app-release.apk

# If you downloaded an APK:
~/Downloads/myapp.apk
```

### Step 2: Run the Analyzer

**Basic command** (just check if it's obfuscated):
```bash
./analyzer.py /path/to/your/app.apk
```

**For release verification** (recommended):
```bash
./analyzer.py /path/to/your/app.apk --expect-obfuscator R8 --min-score 50
```

**Example with the jadx path:**
```bash
./analyzer.py ~/Downloads/myapp.apk --jadx-path ~/jadx/bin/jadx
```

### Step 3: Read the Results

The tool will show you:

**✅ GOOD NEWS - Ready for Release:**
```
============================================================
RELEASE READINESS CHECK
============================================================

✓ Status: READY FOR RELEASE
Confidence: HIGH

✓ Expected: R8, Detected: R8

📋 RECOMMENDATIONS:
  1. ✓ Confirmed: R8 obfuscation detected
  2. Strong obfuscation detected. App is well protected.
```

**✗ BAD NEWS - NOT Ready for Release:**
```
============================================================
RELEASE READINESS CHECK
============================================================

✗ Status: NOT READY FOR RELEASE
Confidence: LOW

⚠ BLOCKERS (Must fix before release):
  1. Obfuscation score (15.0) is below minimum required (50)

📋 RECOMMENDATIONS:
  1. Enable or strengthen obfuscation settings before release
```

### Step 4: View the Detailed Report

The tool creates two reports:

**HTML Report** (visual, easy to read):
```bash
# Open the report in your browser
xdg-open results/single_report_*.html    # Linux
open results/single_report_*.html         # macOS
start results/single_report_*.html        # Windows
```

**JSON Report** (for automation):
```bash
cat results/single_analysis_*.json
```

---

## 📖 Common Use Cases

### Use Case 1: "Is my release APK properly obfuscated?"

**Before releasing to Google Play:**
```bash
./analyzer.py app/build/outputs/apk/release/app-release.apk \
    --expect-obfuscator R8 \
    --min-score 60 \
    --jadx-path ~/jadx/bin/jadx
```

**What to look for:**
- ✅ Status: READY FOR RELEASE = **Safe to release!**
- ✗ Status: NOT READY = **Fix the issues first!**

---

### Use Case 2: "Did my ProGuard configuration work?"

**After enabling ProGuard:**
```bash
./analyzer.py myapp-release.apk --expect-obfuscator ProGuard
```

**What you'll learn:**
- Which obfuscator was actually used
- Whether it's ProGuard, R8, or something else
- If the obfuscation is strong enough

---

### Use Case 3: "Compare before and after obfuscation"

**If you have both versions:**
```bash
# Build without obfuscation
./gradlew assembleRelease  # with minifyEnabled false
cp app/build/outputs/apk/release/app-release.apk before.apk

# Build with obfuscation
./gradlew clean assembleRelease  # with minifyEnabled true
cp app/build/outputs/apk/release/app-release.apk after.apk

# Compare them
./analyzer.py before.apk after.apk --jadx-path ~/jadx/bin/jadx
```

**What you'll see:**
- Detailed comparison showing what changed
- Obfuscation effectiveness score (0-100)
- Specific recommendations for improvement

---

### Use Case 4: "Analyze a third-party library"

**Check if an AAR library is obfuscated:**
```bash
./analyzer.py library.aar --jadx-path ~/jadx/bin/jadx
```

---

## 🎓 Understanding the Results

### Obfuscation Score (0-100)

| Score | Meaning | Action Needed |
|-------|---------|---------------|
| **0-30** | 🔴 **LOW** - Barely obfuscated | ⚠️ **Enable obfuscation now!** |
| **31-60** | 🟡 **MEDIUM** - Some obfuscation | ⚡ **Strengthen your settings** |
| **61-100** | 🟢 **HIGH** - Well obfuscated | ✅ **Good to go!** |

### What Gets Detected

**Obfuscator Tools:**
- **R8** - Android's default (Gradle 3.4+)
- **ProGuard** - Classic obfuscator
- **DexGuard** - Commercial, advanced obfuscation
- **Allatori** - Another commercial option

**Obfuscation Indicators:**
- ✅ Short, random class names (a, b, c instead of MainActivity)
- ✅ Encrypted strings
- ✅ Complex control flow
- ✅ Flattened package structure

---

## 🔧 Command Reference

### Basic Commands

```bash
# Simple analysis
./analyzer.py myapp.apk

# With jadx path
./analyzer.py myapp.apk --jadx-path ~/jadx/bin/jadx

# Verify before release
./analyzer.py myapp.apk --expect-obfuscator R8 --min-score 60

# Custom output directory
./analyzer.py myapp.apk -o ./my_results

# Verbose mode (shows detailed progress)
./analyzer.py myapp.apk -v

# Compare two APKs
./analyzer.py original.apk obfuscated.apk
```

### All Options

```bash
./analyzer.py --help
```

**Options:**
- `--expect-obfuscator {ProGuard,R8,DexGuard,Allatori}` - Verify which tool was used
- `--min-score NUMBER` - Minimum score required (default: 50)
- `--jadx-path PATH` - Path to jadx (default: `jadx`)
- `-o, --output DIR` - Where to save reports (default: `./results`)
- `-v, --verbose` - Show detailed progress

---

## 🎯 Real-World Example

Let's say you're about to release version 2.0 of your app:

```bash
# 1. Build your release APK
./gradlew clean assembleRelease

# 2. Check if it's ready for release
cd ~/apk-obfuscation-analyzer

./analyzer.py ~/MyApp/app/build/outputs/apk/release/app-release.apk \
    --expect-obfuscator R8 \
    --min-score 60 \
    --jadx-path ~/jadx/bin/jadx

# 3. Wait for analysis (takes 1-3 minutes)
# Decompiling file...
# Analyzing file...
# Assessing obfuscation likelihood...
# Checking release readiness...

# 4. Check the result
# ✓ Status: READY FOR RELEASE
# Confidence: HIGH

# 5. View the detailed report
xdg-open results/single_report_*.html

# 6. If everything looks good, upload to Google Play! 🎉
```

---

## ❓ Troubleshooting

### Problem: "jadx not found"

**Solution:**
```bash
# Use the full path to jadx
./analyzer.py myapp.apk --jadx-path ~/jadx/bin/jadx

# Or add jadx to your PATH
export PATH="$HOME/jadx/bin:$PATH"
source ~/.bashrc
```

---

### Problem: "ERROR: File not found"

**Solution:**
```bash
# Check the file exists
ls -l /path/to/your/app.apk

# Use absolute paths instead of relative
./analyzer.py /home/user/Downloads/myapp.apk

# Or navigate to the directory first
cd ~/Downloads
~/apk-obfuscation-analyzer/analyzer.py myapp.apk
```

---

### Problem: "Score is 0 even though I enabled obfuscation"

**Possible causes:**
1. **ProGuard/R8 not actually enabled**
   ```gradle
   // Check build.gradle - make sure this is true
   minifyEnabled true
   ```

2. **Too many -keep rules**
   - Check your `proguard-rules.pro`
   - Remove broad `-keep class` rules

3. **Analyzing wrong APK**
   - Make sure you're analyzing the `release` build
   - Not the `debug` build

**Verify obfuscation manually:**
```bash
# Decompile and look at class names
jadx -d /tmp/check myapp.apk
ls /tmp/check/sources/
# Should see short names like: a.java, b.java, c.java
```

---

### Problem: "Decompilation takes forever"

**For large APKs (>100MB):**
- Be patient, it can take 5-10 minutes
- Make sure you have enough RAM (4GB+)
- Try with verbose mode to see progress: `-v`

---

## 🆘 Need Help?

**Check these resources:**
1. **README.md** - Complete documentation
2. **QUICKSTART.md** - Quick reference guide
3. **./analyzer.py --help** - Command help
4. **./test_obfuscation.py** - Run tests to verify installation

**Common questions:**

**Q: Do I need both APKs (before and after)?**
A: No! You can analyze just one APK to check if it's obfuscated.

**Q: Will this work with AAR files?**
A: Yes! Use the same commands, just replace `.apk` with `.aar`.

**Q: How long does analysis take?**
A: Usually 1-3 minutes for typical APKs. Larger apps take longer.

**Q: What score should I aim for?**
A: Minimum 50 for release. Aim for 70+ for strong protection.

**Q: Can I automate this in CI/CD?**
A: Yes! Check the JSON output and exit codes for automation.

---

## 🎉 You're Ready!

**Start with the simplest command:**
```bash
./analyzer.py /path/to/your/app.apk --jadx-path ~/jadx/bin/jadx
```

**Then check the HTML report:**
```bash
xdg-open results/single_report_*.html
```

**That's it!** You now know if your app is properly obfuscated. 🚀

---

## 📚 Next Steps

Once you're comfortable with basic analysis:

1. **Learn about comparison mode** - Compare before/after obfuscation
2. **Integrate with CI/CD** - Automate release checks
3. **Batch processing** - Analyze multiple APKs at once
4. **Customize settings** - Adjust minimum scores and requirements

See **README.md** for advanced usage!
