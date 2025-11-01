#!/usr/bin/env python3
"""
Test script for readable string extraction
"""

from analyzer import APKAnalyzer

def test_readable_string_detection():
    """Test the _is_readable_string method"""
    analyzer = APKAnalyzer(verbose=True)

    # Test cases: (string, expected_result, description)
    test_cases = [
        ("Hello World", True, "Simple English phrase"),
        ("Welcome to the application", True, "Longer English sentence"),
        ("Error occurred", True, "Short English phrase"),
        ("MainActivity", True, "Programming term with vowels"),
        ("User logged in successfully", True, "Complete English sentence"),
        ("Please enter your password", True, "Instructions with proper English"),
        ("abcdefghijklmnop", False, "Random letters without meaning"),
        ("xyzqrt", False, "Consonants without vowels"),
        ("123456789", False, "Numbers only"),
        ("a1b2c3", False, "Mixed alphanumeric"),
        ("if (x > y) {", False, "Code snippet"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", False, "Base64-like string"),
        ("ab", False, "Too short"),
        ("xyz", False, "Too short and no vowels"),
        ("Hello\u0001World", False, "Contains non-printable characters"),
        ("ConstraintTableLayout", True, "Long class name with meaning"),
        ("init", True, "Common programming term"),
        ("error", True, "Common error term"),
        ("data", True, "Common data term"),
        ("\\u0012test", False, "Unicode escape sequences"),
    ]

    print("=" * 70)
    print("Testing Readable String Detection")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    for string, expected, description in test_cases:
        result = analyzer._is_readable_string(string)
        status = "✓ PASS" if result == expected else "✗ FAIL"

        if result == expected:
            passed += 1
        else:
            failed += 1

        print(f"{status} | '{string[:30]}...' if len(string) > 30 else '{string}'")
        print(f"       Expected: {expected}, Got: {result} - {description}")
        print()

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 70)

    return failed == 0

if __name__ == "__main__":
    success = test_readable_string_detection()
    exit(0 if success else 1)
