# 👋 Welcome to APK/AAR Obfuscation Analyzer!

**Choose your path based on your experience level:**

---

## 🆕 I'm New Here - First Time User

**Start here:**
1. 📖 Read [GETTING_STARTED.md](GETTING_STARTED.md) - Complete beginner's guide
2. ⚡ Try the simple script: `./check_release.sh your-app.apk`
3. 👀 See [WHAT_TO_EXPECT.md](WHAT_TO_EXPECT.md) - Visual guide of what you'll see

**Quick test:**
```bash
# Make sure you have jadx
jadx --version
# Or: ~/jadx/bin/jadx --version

# Run the tool
./check_release.sh /path/to/your/app.apk
```

---

## 🎯 I Want to Check My APK Before Release

**You're in the right place! This is the most common use case.**

**Quick command:**
```bash
./check_release.sh /path/to/your-app-release.apk R8
```

**What you'll get:**
- ✅ or ✗ Clear decision: Ready for release or not
- 🎯 Verification that R8/ProGuard was used
- 📋 Specific issues to fix (if any)
- 📊 Detailed HTML report

**See:** [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for common commands

---

## 🔍 I Want to Compare Before/After Obfuscation

**You have two versions of your APK:**

```bash
./analyzer.py original.apk obfuscated.apk --jadx-path ~/jadx/bin/jadx
```

**See:** [QUICKSTART.md](QUICKSTART.md) - Section on comparison analysis

---

## 📚 I Want Complete Documentation

**Full documentation:**
- [README.md](README.md) - Complete feature list and documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide with all features
- [SAMPLE_APKS.md](SAMPLE_APKS.md) - How to get test APKs

---

## 🛠️ I Want to Automate This (CI/CD)

**For automation:**
1. Read [README.md](README.md) - See "CI/CD Integration" section
2. Use JSON output: `results/single_analysis_*.json`
3. Check exit codes: 0 = success, 1 = failure

**Example CI/CD script:**
```bash
#!/bin/bash
./analyzer.py app-release.apk --expect-obfuscator R8 --min-score 60

if [ $? -eq 0 ]; then
    echo "✅ APK passed obfuscation check"
    exit 0
else
    echo "✗ APK failed obfuscation check"
    exit 1
fi
```

---

## ❓ I Need Help / Troubleshooting

**Common issues:**

### "jadx not found"
```bash
# Use full path
./analyzer.py app.apk --jadx-path ~/jadx/bin/jadx
```

### "File not found"
```bash
# Use absolute path
./analyzer.py /full/path/to/app.apk
```

### "Score is 0"
Your obfuscation is not enabled. Check your `build.gradle`:
```gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // Must be true!
        }
    }
}
```

**See:** [GETTING_STARTED.md](GETTING_STARTED.md) - Troubleshooting section

---

## 📖 Documentation Guide

**Which guide should I read?**

| Document | Best For |
|----------|----------|
| [START_HERE.md](START_HERE.md) | Choosing where to begin (you are here!) |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Complete beginners, step-by-step guide |
| [WHAT_TO_EXPECT.md](WHAT_TO_EXPECT.md) | Visual guide showing output examples |
| [QUICK_REFERENCE.md](QUICK_REFERENCE.md) | Quick lookup of common commands |
| [QUICKSTART.md](QUICKSTART.md) | Users who know basics, want quick ref |
| [README.md](README.md) | Complete documentation, all features |
| [SAMPLE_APKS.md](SAMPLE_APKS.md) | How to get test APK files |

---

## 🎯 Most Common Workflows

### Workflow 1: Pre-Release Check (Most Common!)
```bash
# 1. Build your release APK
./gradlew assembleRelease

# 2. Check if it's ready
./check_release.sh app/build/outputs/apk/release/app-release.apk R8

# 3. Look for: ✓ READY FOR RELEASE

# 4. If ready → Upload to Google Play
# 5. If not ready → Fix issues and try again
```

### Workflow 2: Verify Obfuscation is Working
```bash
# Check any APK
./analyzer.py myapp.apk --jadx-path ~/jadx/bin/jadx

# Review the HTML report
xdg-open results/single_report_*.html
```

### Workflow 3: Compare Versions
```bash
# Build without obfuscation (minifyEnabled false)
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk before.apk

# Build with obfuscation (minifyEnabled true)
./gradlew clean assembleRelease
cp app/build/outputs/apk/release/app-release.apk after.apk

# Compare
./analyzer.py before.apk after.apk
```

---

## ⚡ TL;DR - Just Tell Me What to Do!

**For first-time users:**
```bash
./check_release.sh /path/to/your/app.apk
```

**For release verification:**
```bash
./check_release.sh /path/to/your/app.apk R8 60
```

**For detailed analysis:**
```bash
./analyzer.py /path/to/your/app.apk --jadx-path ~/jadx/bin/jadx
xdg-open results/single_report_*.html
```

---

## 💡 Quick Tips

✅ **Always check your release APK** before uploading to Google Play

✅ **Aim for a score of 60+** for production apps

✅ **Use `--expect-obfuscator`** to verify the right tool was used

✅ **Keep the HTML reports** for your release records

✅ **Run as part of your release checklist** - don't skip this step!

---

## 🆘 Still Confused?

**Read these in order:**
1. [GETTING_STARTED.md](GETTING_STARTED.md) - Detailed beginner's guide
2. [WHAT_TO_EXPECT.md](WHAT_TO_EXPECT.md) - See what the output looks like
3. Try running: `./check_release.sh` (without arguments) to see help

**Or just run this:**
```bash
./analyzer.py --help
```

---

## 🎉 Ready to Begin!

**Choose your starting point above and let's verify your app is properly obfuscated!**

**Most users should start with:** [GETTING_STARTED.md](GETTING_STARTED.md)
