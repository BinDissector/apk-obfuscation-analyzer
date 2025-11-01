# Getting Sample APKs for Testing

To test the APK Obfuscation Analyzer, you need APK pairs (original and obfuscated versions). Here are several approaches to obtain test APKs.

## Option 1: Build Your Own App (Recommended)

This is the best approach for understanding obfuscation effectiveness on your own code.

### Create a Simple Android App

1. **Create a new Android project:**
```bash
# Using Android Studio or command line
android create project --target android-33 --name TestApp --path ./TestApp \
    --activity MainActivity --package com.example.testapp
```

2. **Build without obfuscation:**
```gradle
// app/build.gradle
android {
    buildTypes {
        release {
            minifyEnabled false  // No obfuscation
        }
    }
}
```

```bash
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk ./apks/testapp_original.apk
```

3. **Build with obfuscation:**
```gradle
// app/build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

```bash
./gradlew clean
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk ./apks/testapp_obfuscated.apk
```

4. **Analyze:**
```bash
./analyzer.py apks/testapp_original.apk apks/testapp_obfuscated.apk
```

## Option 2: Open Source Apps

Download and build open-source Android apps from GitHub.

### Popular Open Source Apps:

1. **AntennaPod** (Podcast Player)
   - https://github.com/AntennaPod/AntennaPod
   - Clone, build with/without obfuscation

2. **Simple Mobile Tools**
   - https://github.com/SimpleMobileTools
   - Various simple apps (calculator, gallery, etc.)

3. **Firefox Focus**
   - https://github.com/mozilla-mobile/focus-android
   - Privacy browser by Mozilla

4. **Telegram FOSS**
   - https://github.com/Telegram-FOSS-Team/Telegram-FOSS
   - Open source Telegram client

### Steps:
```bash
# Example with Simple Calculator
git clone https://github.com/SimpleMobileTools/Simple-Calculator.git
cd Simple-Calculator

# Build original (edit build.gradle to disable minify)
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk ../apks/calculator_original.apk

# Build obfuscated (edit build.gradle to enable minify)
./gradlew clean
./gradlew assembleRelease
cp app/build/outputs/apk/release/app-release.apk ../apks/calculator_obfuscated.apk
```

## Option 3: APK Download Sites (For Educational Purposes Only)

**⚠️ Legal Warning:** Only download APKs you have the right to analyze. Respect copyright and terms of service.

### Sites (use at your own discretion):
- APKMirror: https://www.apkmirror.com/
- F-Droid: https://f-droid.org/ (open source apps)
- APKPure: https://apkpure.com/

**Note:** Downloaded APKs are typically already obfuscated. To create pairs:
1. Download an APK (this will be the "obfuscated" version)
2. Deobfuscate it manually or use it as a baseline
3. Compare different versions or builds

## Option 4: Create Minimal Test Apps

Create minimal apps specifically for testing obfuscation.

### Simple Test App

**MainActivity.java:**
```java
package com.example.testapp;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {
    private String apiKey = "my-secret-api-key";
    private UserManager userManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        userManager = new UserManager();
        authenticateUser();
    }

    private void authenticateUser() {
        String username = "admin";
        String password = "password123";
        userManager.login(username, password);
    }
}
```

**UserManager.java:**
```java
package com.example.testapp;

public class UserManager {
    private DatabaseHelper dbHelper;

    public UserManager() {
        dbHelper = new DatabaseHelper();
    }

    public boolean login(String username, String password) {
        return dbHelper.validateCredentials(username, password);
    }

    public void logout() {
        dbHelper.clearSession();
    }
}
```

**DatabaseHelper.java:**
```java
package com.example.testapp;

public class DatabaseHelper {
    public boolean validateCredentials(String user, String pass) {
        return true;
    }

    public void clearSession() {
        // Clear session
    }
}
```

Build this twice (with/without obfuscation) to see clear differences:
- Original: `MainActivity`, `UserManager`, `DatabaseHelper`
- Obfuscated: `a`, `b`, `c` or similar short names

## Option 5: Use Test APKs from Android SDK

The Android SDK samples include several example apps.

```bash
# Location (adjust for your SDK installation)
$ANDROID_HOME/samples/

# Common locations:
# - Linux: ~/Android/Sdk/samples/
# - macOS: ~/Library/Android/sdk/samples/
# - Windows: C:\Users\<username>\AppData\Local\Android\Sdk\samples\
```

## Testing Recommendations

### For Comprehensive Testing:

1. **Start Simple:**
   - Small app (3-5 classes)
   - Clear naming conventions
   - Some string literals

2. **Progress to Complex:**
   - Medium app (20+ classes)
   - External libraries
   - Multiple packages

3. **Test Real-World:**
   - Actual production app
   - Sensitive data handling
   - API keys and secrets

### Naming Convention

Always use consistent naming for your test APKs:
```
apks/
├── app1_original.apk
├── app1_obfuscated.apk
├── app2_original.apk
├── app2_obfuscated.apk
└── ...
```

## Quick Start Example

Create a minimal test app in 5 minutes:

```bash
# 1. Create Android project
mkdir -p TestApp/app/src/main/java/com/example/test

# 2. Create MainActivity.java
cat > TestApp/app/src/main/java/com/example/test/MainActivity.java << 'EOF'
package com.example.test;
import android.app.Activity;
public class MainActivity extends Activity {
    private String secret = "my-secret-key";
}
EOF

# 3. Build configurations (create build.gradle files as shown above)

# 4. Build both versions
cd TestApp
./gradlew assembleRelease  # Without obfuscation first
./gradlew assembleRelease  # With obfuscation second

# 5. Analyze
cd ..
./analyzer.py TestApp/original.apk TestApp/obfuscated.apk
```

## Verification

Before analyzing, verify your APKs are different:

```bash
# Check file sizes (obfuscated is usually smaller)
ls -lh apks/*.apk

# Quick inspection with jadx
jadx -d /tmp/original apks/app_original.apk
jadx -d /tmp/obfuscated apks/app_obfuscated.apk

# Compare class names
find /tmp/original -name "*.java" | head
find /tmp/obfuscated -name "*.java" | head
```

## Troubleshooting

### "No differences detected"
- Ensure minifyEnabled is actually different between builds
- Check ProGuard rules aren't preventing obfuscation
- Verify you're comparing different APK files

### "APK already obfuscated"
- If downloading APKs, most are already obfuscated
- Compare different obfuscation levels instead
- Or use as baseline for your own apps

### "Build failed"
- Check Android SDK is installed
- Verify Gradle version compatibility
- Review build.gradle for errors

## Resources

- **Android Developer Guide:** https://developer.android.com/studio/build/shrink-code
- **ProGuard Manual:** https://www.guardsquare.com/manual/home
- **R8 Documentation:** https://r8.googlesource.com/r8
- **jadx Repository:** https://github.com/skylot/jadx

## Legal Notice

Always ensure you have the legal right to analyze any APK. This tool is intended for:
- Analyzing your own applications
- Educational purposes with properly licensed software
- Security research with authorization
- Open source applications under compatible licenses

Do not use this tool to reverse engineer proprietary applications without permission.
