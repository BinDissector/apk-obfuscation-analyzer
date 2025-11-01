#!/usr/bin/env python3
"""
Test script for file metadata extraction (hashes and signatures)
"""

import os
import tempfile
import zipfile
from analyzer import APKAnalyzer

def test_hash_calculation():
    """Test hash calculation on a temporary file"""
    print("="*70)
    print("Testing Hash Calculation")
    print("="*70)
    print()

    analyzer = APKAnalyzer(verbose=True)

    # Create a temporary file with known content
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
        tmp.write("Hello, World! This is a test file.")
        tmp_path = tmp.name

    try:
        # Calculate hashes
        hashes = analyzer._calculate_file_hashes(tmp_path)

        print("Hash Results:")
        print(f"  MD5:    {hashes.get('md5', 'N/A')}")
        print(f"  SHA1:   {hashes.get('sha1', 'N/A')}")
        print(f"  SHA256: {hashes.get('sha256', 'N/A')}")
        print()

        # Verify hashes are not empty
        if 'error' in hashes:
            print(f"✗ FAIL: Error calculating hashes: {hashes['error']}")
            return False

        if hashes.get('md5') and hashes.get('sha1') and hashes.get('sha256'):
            print("✓ PASS: All hash values calculated successfully")
            return True
        else:
            print("✗ FAIL: Some hash values are missing")
            return False

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def test_signature_extraction():
    """Test signature extraction on a mock APK"""
    print()
    print("="*70)
    print("Testing Signature Extraction")
    print("="*70)
    print()

    analyzer = APKAnalyzer(verbose=True)

    # Create a mock APK file (just a ZIP with no META-INF)
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.apk') as tmp:
        tmp_path = tmp.name

        # Create a basic ZIP structure
        with zipfile.ZipFile(tmp_path, 'w') as zf:
            zf.writestr('AndroidManifest.xml', 'mock manifest')
            zf.writestr('classes.dex', 'mock dex')

    try:
        # Extract signature info
        signature = analyzer._extract_signature_info(tmp_path)

        print("Signature Results:")
        print(f"  Signed: {signature.get('signed', False)}")
        print(f"  v1 Signed: {signature.get('v1_signed', False)}")
        print(f"  v2 Signed: {signature.get('v2_signed', False)}")
        print(f"  v3 Signed: {signature.get('v3_signed', False)}")
        print()

        # For an unsigned APK, we expect signed=False
        if not signature.get('signed'):
            print("✓ PASS: Correctly detected unsigned APK")
            return True
        else:
            print("✗ FAIL: Should have detected as unsigned")
            return False

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def test_aar_signature_note():
    """Test that AAR files get the appropriate note"""
    print()
    print("="*70)
    print("Testing AAR Signature Handling")
    print("="*70)
    print()

    analyzer = APKAnalyzer(verbose=True)

    # Create a mock AAR file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.aar') as tmp:
        tmp_path = tmp.name

        # Create a basic ZIP structure
        with zipfile.ZipFile(tmp_path, 'w') as zf:
            zf.writestr('AndroidManifest.xml', 'mock manifest')
            zf.writestr('classes.jar', 'mock jar')

    try:
        # Extract signature info
        signature = analyzer._extract_signature_info(tmp_path)

        print("Signature Results for AAR:")
        print(f"  Note: {signature.get('note', 'N/A')}")
        print()

        # For an AAR file, we expect a note saying signature info is not applicable
        if signature.get('note'):
            print("✓ PASS: AAR file correctly gets informational note")
            return True
        else:
            print("✗ FAIL: AAR should have note about signature not applicable")
            return False

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    print()
    print("File Metadata Extraction Tests")
    print()

    results = []
    results.append(("Hash Calculation", test_hash_calculation()))
    results.append(("Signature Extraction", test_signature_extraction()))
    results.append(("AAR Signature Handling", test_aar_signature_note()))

    print()
    print("="*70)
    print("Test Summary")
    print("="*70)

    all_passed = True
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")
        if not passed:
            all_passed = False

    print("="*70)
    if all_passed:
        print("All tests PASSED!")
        exit(0)
    else:
        print("Some tests FAILED!")
        exit(1)
