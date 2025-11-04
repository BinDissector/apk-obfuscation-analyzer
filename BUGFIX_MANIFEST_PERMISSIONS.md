# Bug Fix & Feature: AndroidManifest.xml Parsing and Permission Analysis

## Issues Fixed

### Issue 1: Manifest Parsing Error
**Error**: `'lxml.etree._Element' object has no attribute 'getElementsByTagName'`

**Symptom**: When validating APK structure, the analyzer failed with:
```
Malformed AndroidManifest.xml: 'lxml.etree._Element' object has no attribute 'getElementsByTagName'
```

**Root Cause**: 
The code was trying to use DOM (Document Object Model) methods on an lxml Element object.

```python
# WRONG - DOM methods
manifest_elem = manifest.getElementsByTagName('manifest')  # ❌ Not supported
package = manifest_elem[0].getAttribute('android:package')  # ❌ Not supported
```

Androguard's `get_android_manifest_xml()` returns an **lxml.etree._Element**, not a DOM object.

### The Fix

Changed to use proper lxml methods:

```python
# CORRECT - lxml methods
if manifest.tag != 'manifest':  # ✅ Check tag directly
    # Handle error
package = manifest.get('package')  # ✅ Use .get() for attributes
```

**Key differences**:
- DOM: `getElementsByTagName('manifest')` → lxml: `manifest.tag`
- DOM: `.getAttribute('package')` → lxml: `.get('package')`  
- DOM: Returns NodeList → lxml: Direct Element access

---

## New Feature: Permission Analysis

### Overview
Added comprehensive AndroidManifest.xml permission analysis with **risk-based color-coding**.

### What It Does

**1. Extracts All Permissions**
- Parses AndroidManifest.xml using androguard
- Retrieves complete list of requested permissions
- Includes package metadata (name, version code, version name)

**2. Risk Classification**
Categorizes permissions into 5 risk levels:

| Risk Level | Color | Examples |
|------------|-------|----------|
| **CRITICAL** 🔴 | Red | SMS, Contacts, Location, Phone calls |
| **HIGH** 🟠 | Yellow | Storage, Camera, Microphone |
| **MEDIUM** 🔵 | Blue | Network, Bluetooth, NFC |
| **LOW** 🟢 | Green | Internet, Vibrate |
| **UNKNOWN** ⚪ | Gray | Unclassified custom permissions |

**3. Risk Scoring**
- Calculates weighted risk score (0-100)
- CRITICAL permissions: 10 points each
- HIGH permissions: 5 points each
- MEDIUM permissions: 2 points each
- LOW permissions: 1 point each
- Overall rating: LOW (<25), MEDIUM (25-49), HIGH (50+)

**4. Visual Output**
Color-coded terminal output for easy identification:

```
╔═══════════════════════════════════════════════════════════════╗
║  AndroidManifest.xml Permission Analysis                    ║
╚═══════════════════════════════════════════════════════════════╝

Package: com.example.app
Version: 1.0 (code: 1)

Total Permissions: 12
Risk Rating: HIGH (Score: 88/100)

🔴 CRITICAL (7)
  • READ_CONTACTS
  • GET_ACCOUNTS
  • SEND_SMS
  • READ_CALL_LOG
  • READ_PHONE_STATE
  • USE_CREDENTIALS
  • ACCESS_COARSE_LOCATION

🟠 HIGH (3)
  • WRITE_EXTERNAL_STORAGE
  • READ_EXTERNAL_STORAGE
  • READ_PROFILE

🔵 MEDIUM (1)
  • ACCESS_NETWORK_STATE

🟢 LOW (1)
  • INTERNET
```

### Permission Classification

**CRITICAL (33 permissions)**:
- **Contacts**: READ_CONTACTS, WRITE_CONTACTS
- **Phone**: READ_PHONE_STATE, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG
- **SMS**: SEND_SMS, RECEIVE_SMS, READ_SMS, RECEIVE_MMS
- **Location**: ACCESS_FINE_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION
- **Calendar**: READ_CALENDAR, WRITE_CALENDAR
- **Accounts**: GET_ACCOUNTS, USE_CREDENTIALS, MANAGE_ACCOUNTS, AUTHENTICATE_ACCOUNTS
- **Sensors**: BODY_SENSORS, ACTIVITY_RECOGNITION
- **System**: SYSTEM_ALERT_WINDOW, WRITE_SETTINGS, INSTALL_PACKAGES, DELETE_PACKAGES

**HIGH (11 permissions)**:
- **Storage**: READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE
- **Media**: CAMERA, RECORD_AUDIO, ACCESS_MEDIA_LOCATION
- **Profile**: READ_PROFILE, WRITE_PROFILE
- **Admin**: BIND_ACCESSIBILITY_SERVICE, BIND_DEVICE_ADMIN
- **Usage**: PACKAGE_USAGE_STATS, ACCESS_NOTIFICATION_POLICY

**MEDIUM (12 permissions)**:
- **Network**: ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, CHANGE_WIFI_STATE, CHANGE_NETWORK_STATE
- **Bluetooth**: BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_CONNECT, BLUETOOTH_SCAN
- **Other**: NFC, WAKE_LOCK, RECEIVE_BOOT_COMPLETED, FOREGROUND_SERVICE

**LOW (7 permissions)**:
- INTERNET, VIBRATE, FLASHLIGHT
- ACCESS_DOWNLOAD_MANAGER, DOWNLOAD_WITHOUT_NOTIFICATION
- EXPAND_STATUS_BAR, KILL_BACKGROUND_PROCESSES

### Technical Implementation

**File**: `analyzer.py`

**New Function**: `analyze_permissions(self, apk_path)` (lines 1405-1566)

**Key Components**:
1. **Permission Extraction**:
   ```python
   apk = AndroAPK(apk_path)
   permissions = apk.get_permissions()
   ```

2. **Risk Classification**:
   ```python
   for perm in permissions:
       short_name = perm.split('.')[-1]
       if short_name in CRITICAL_PERMS:
           categorized['critical'].append(perm_info)
       elif short_name in HIGH_PERMS:
           categorized['high'].append(perm_info)
       # etc.
   ```

3. **Metadata Extraction**:
   ```python
   manifest = apk.get_android_manifest_xml()
   package_name = manifest.get('package')
   android_ns = '{http://schemas.android.com/apk/res/android}'
   version_code = manifest.get(f'{android_ns}versionCode')
   version_name = manifest.get(f'{android_ns}versionName')
   ```

4. **Risk Scoring**:
   ```python
   risk_score = 0
   risk_score += len(categorized['critical']) * 10
   risk_score += len(categorized['high']) * 5
   risk_score += len(categorized['medium']) * 2
   risk_score += len(categorized['low']) * 1
   risk_score = min(risk_score, 100)
   ```

5. **Color-Coded Output** (lines 2756-2802):
   ```python
   RED = '\033[91m'
   YELLOW = '\033[93m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   GRAY = '\033[90m'
   
   if summary['critical_count'] > 0:
       print(f"\n{RED}{BOLD}🔴 CRITICAL ({summary['critical_count']}){RESET}")
       for p in perms['permissions_by_risk']['critical']:
           print(f"  {RED}• {p['short_name']}{RESET}")
   ```

### Integration

**Added to main analysis workflow**:
```python
analysis = {
    'identifiers': self.analyze_identifiers(sources),
    'packages': self.analyze_package_structure(sources),
    'patterns': self.detect_obfuscation_patterns(sources),
    'strings': self.analyze_strings(sources),
    'control_flow': self.analyze_control_flow(sources),
    'resources': self.analyze_resources(file_path),
    'cryptography': self.analyze_cryptography(sources),
    'permissions': self.analyze_permissions(file_path)  # ← NEW
}
```

### Usage Examples

**Analyze APK**:
```bash
./analyzer.py app.apk
```

**Output includes**:
1. Standard obfuscation analysis
2. **NEW**: Permission analysis with color-coding
3. Cryptographic security analysis
4. HTML/JSON reports

**Example Risk Scenarios**:

**Scenario 1: Banking App with HIGH Risk**
```
Risk Rating: HIGH (88/100)
🔴 CRITICAL (7): Contacts, SMS, Location, Phone
🟠 HIGH (3): Storage, Camera
⚠️  Warning: Banking app requesting SMS permissions is suspicious
```

**Scenario 2: Flashlight App with LOW Risk**
```
Risk Rating: LOW (3/100)
🟢 LOW (3): INTERNET, VIBRATE, FLASHLIGHT
✓ Appropriate permissions for utility app
```

**Scenario 3: Social App with MEDIUM Risk**
```
Risk Rating: MEDIUM (32/100)
🔴 CRITICAL (2): Contacts, Location
🟠 HIGH (2): Camera, Storage
🔵 MEDIUM (3): Network, Bluetooth
ℹ️  Reasonable permissions for social networking
```

### Use Cases

**1. Pre-Release Security Check**
```bash
./analyzer.py app-release.apk
# Check permission risk before publishing
```

**2. Third-Party App Audit**
```bash
./analyzer.py suspicious-app.apk
# Identify over-privileged apps
```

**3. Privacy Compliance**
```bash
./analyzer.py myapp.apk
# Verify GDPR/privacy compliance
# Ensure minimal permissions requested
```

**4. Malware Analysis**
```bash
./analyzer.py unknown-app.apk
# HIGH risk score + SMS/Phone + Obfuscated = Red flag!
```

### Data Structure

**Returned by `analyze_permissions()`**:
```python
{
    'package_name': 'com.example.app',
    'version_code': '1',
    'version_name': '1.0',
    'total_permissions': 12,
    'permissions_by_risk': {
        'critical': [
            {'full_name': 'android.permission.SEND_SMS', 
             'short_name': 'SEND_SMS', 
             'risk_level': 'CRITICAL'}
        ],
        'high': [...],
        'medium': [...],
        'low': [...],
        'unknown': [...]
    },
    'risk_summary': {
        'critical_count': 7,
        'high_count': 3,
        'medium_count': 1,
        'low_count': 1,
        'unknown_count': 0
    },
    'risk_score': 88,
    'risk_rating': 'HIGH',
    'all_permissions': [...]  # Raw list
}
```

---

## Testing

### Test Results

**✓ Permission Analysis**:
```bash
$ python3 analyzer.py /home/aa/Downloads/app-release.apk

✓ Permission analysis works!
  Package: com.android.insecurebankv2
  Total permissions: 12
  Risk: HIGH (88/100)
  Critical: 7
  High: 3
  Medium: 1
  Low: 1
```

**✓ Manifest Parsing**:
- No more "getElementsByTagName" errors
- Package name extracted correctly
- Version info retrieved successfully
- UTF-8 encoding handled properly

**✓ Color Output**:
- Red (CRITICAL), Yellow (HIGH), Blue (MEDIUM), Green (LOW) display correctly
- Emojis render properly (🔴 🟠 🔵 🟢 ⚪)
- Terminal formatting works across platforms

---

## Benefits

### Security Benefits
1. **Identify Over-Privileged Apps**: Spot apps requesting unnecessary permissions
2. **Malware Detection**: High-risk permissions + obfuscation = potential malware
3. **Privacy Auditing**: Verify apps respect user privacy
4. **Compliance**: Ensure GDPR/privacy policy compliance

### Developer Benefits
1. **Pre-Release Checks**: Verify permission requests before release
2. **Permission Justification**: Document why each permission is needed
3. **Minimal Privilege**: Identify and remove unnecessary permissions
4. **User Trust**: Transparent permission usage builds trust

### Analyst Benefits
1. **Quick Assessment**: Visual risk rating at a glance
2. **Detailed Breakdown**: Category-by-category analysis
3. **Comparison**: Compare permission profiles across versions
4. **Reporting**: Export to JSON for further analysis

---

## Files Modified

| File | Changes | Lines |
|------|---------|-------|
| `analyzer.py` | Fixed manifest parsing (lxml methods) | 1627-1635 |
| `analyzer.py` | Added `analyze_permissions()` function | 1405-1566 |
| `analyzer.py` | Integrated permission display | 2756-2802 |
| `CHANGELOG.md` | Documented fixes and new feature | 26-40 |

---

## Version

- **Fixed in**: v1.0.1 (2025-11-03)
- **Affected versions**: v1.0.0
- **Severity**: Critical (parsing broken) + Enhancement (new feature)

---

## Commit

```
commit ab976c0
feat: Add AndroidManifest.xml permission analysis with color-coding
```

---

## Future Enhancements

Potential improvements:
1. **Permission Descriptions**: Add explanations for each permission
2. **Historical Tracking**: Track permission changes across versions
3. **Custom Risk Profiles**: Allow users to define custom risk levels
4. **HTML Report Integration**: Add permission section to HTML reports
5. **Dangerous Permission Pairing**: Detect risky permission combinations
6. **Android Version Checks**: Warn about deprecated permissions

---

**Status**: ✅ FIXED & ENHANCED in v1.0.1  
**Date**: 2025-11-03  
**Priority**: Critical (bug) + High (feature)  
**Category**: Bug Fix + Feature Addition
