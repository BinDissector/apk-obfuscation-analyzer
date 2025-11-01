# Quick Reference Card

**Keep this open while you use the tool!**

---

## 🚀 Most Common Commands

### Check if APK is ready for release
```bash
./check_release.sh /path/to/app.apk R8
```

### Basic analysis (any APK/AAR)
```bash
./analyzer.py /path/to/file.apk --jadx-path ~/jadx/bin/jadx
```

### Full release check
```bash
./analyzer.py app-release.apk \
    --expect-obfuscator R8 \
    --min-score 60 \
    --jadx-path ~/jadx/bin/jadx
```

### Compare before and after
```bash
./analyzer.py original.apk obfuscated.apk
```

---

## 📊 Understanding Scores

| Score | Status | Meaning |
|-------|--------|---------|
| 0-30  | 🔴 LOW | Not obfuscated - **DON'T RELEASE** |
| 31-60 | 🟡 MEDIUM | Some obfuscation - **Improve it** |
| 61-100 | 🟢 HIGH | Well obfuscated - **Good to go!** |

---

## ✅ Release Checklist

Before releasing your app:

- [ ] Run: `./check_release.sh app-release.apk R8`
- [ ] Status shows: **✓ READY FOR RELEASE**
- [ ] No blockers listed
- [ ] Score is above 50 (preferably 60+)
- [ ] Correct obfuscator detected (R8/ProGuard)
- [ ] Review HTML report looks good

---

## 🔧 Available Obfuscators

- **R8** - Default in modern Android (Gradle 3.4+)
- **ProGuard** - Classic obfuscator
- **DexGuard** - Commercial, advanced
- **Allatori** - Commercial alternative

Not sure which you're using? Run without `--expect-obfuscator` and the tool will detect it.

---

## 📁 Where are the results?

**HTML Report:** `results/single_report_*.html`
```bash
xdg-open results/single_report_*.html
```

**JSON Data:** `results/single_analysis_*.json`
```bash
cat results/single_analysis_*.json | python3 -m json.tool
```

---

## ⚠️ Common Issues & Fixes

### "jadx not found"
```bash
# Use full path
./analyzer.py app.apk --jadx-path ~/jadx/bin/jadx
```

### "File not found"
```bash
# Use absolute path
./analyzer.py /home/user/Downloads/app.apk

# Or navigate to the directory first
cd ~/Downloads
~/apk-obfuscation-analyzer/analyzer.py app.apk
```

### "Score is 0"
Your obfuscation isn't enabled. Check:
```gradle
// build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true  // Must be true!
        }
    }
}
```

---

## 📖 Need More Help?

- **First-time user?** → `GETTING_STARTED.md`
- **Detailed docs?** → `README.md`
- **Quick start?** → `QUICKSTART.md`
- **Command help?** → `./analyzer.py --help`

---

## 💡 Pro Tips

**Tip 1:** Always check your release APK before uploading to Google Play

**Tip 2:** Set a minimum score of 60 for production apps

**Tip 3:** If using R8, make sure to use `--expect-obfuscator R8`

**Tip 4:** Keep the HTML report for your records

**Tip 5:** Add this to your CI/CD pipeline for automatic checks
