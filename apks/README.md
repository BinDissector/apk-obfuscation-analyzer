# APK/AAR Files Directory

Place your APK and AAR files in this directory for analysis.

## For Comparison Analysis

Use this naming convention for comparing original vs obfuscated versions:

```
apks/
├── myapp_original.apk
├── myapp_obfuscated.apk
├── mylibrary_original.aar
└── mylibrary_obfuscated.aar
```

Then run:
```bash
./batch_analyze.sh -d ./apks -o ./results
```

## For Single File Analysis

Place any APK or AAR files you want to analyze individually:

```
apks/
├── third_party_sdk.aar
├── competitor_app.apk
└── mystery_library.aar
```

Then run:
```bash
./batch_analyze.sh -d ./apks -o ./results --single
```

Or analyze individual files:
```bash
./analyzer.py apks/third_party_sdk.aar
```

## Note

APK and AAR files are excluded from git by default (see `.gitignore`) due to their large size.
