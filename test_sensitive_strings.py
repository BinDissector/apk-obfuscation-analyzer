#!/usr/bin/env python3
"""
Test script for sensitive string detection
"""

from analyzer import APKAnalyzer

def test_sensitive_string_detection():
    """Test the _detect_sensitive_strings method"""
    analyzer = APKAnalyzer(verbose=True)

    # Test cases with various sensitive strings
    test_strings = [
        # URLs
        "https://api.example.com/v1/users",
        "http://192.168.1.1/config",

        # API Keys
        "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe",  # Google API key pattern
        "AKIAIOSFODNN7EXAMPLE",  # AWS Access Key pattern

        # Package names
        "com.example.myapp.MainActivity",
        "org.apache.commons.lang3.StringUtils",

        # Email addresses
        "support@example.com",
        "admin@mycompany.org",

        # IP addresses
        "192.168.1.1",
        "10.0.0.1",

        # Database strings
        "jdbc:mysql://localhost:3306/mydb",
        "mongodb://admin:password@localhost:27017",

        # Generic secrets (long alphanumeric with mixed case)
        "Ktn5YhZqWx7Nm9PqLpRt2Vc3XbYz",

        # Non-sensitive strings (should not be detected)
        "Hello World",
        "Welcome to the application",
        "MainActivity",
        "error",
    ]

    print("=" * 70)
    print("Testing Sensitive String Detection")
    print("=" * 70)
    print()

    result = analyzer._detect_sensitive_strings(test_strings)

    print("Detection Results:")
    print(f"  Total Sensitive Strings: {result['total_sensitive']}")
    print()

    categories = [
        ('API Keys', 'api_keys'),
        ('URLs', 'urls'),
        ('Package Names', 'package_names'),
        ('Email Addresses', 'email_addresses'),
        ('IP Addresses', 'ip_addresses'),
        ('Database Strings', 'database_strings'),
        ('Secrets', 'secrets'),
    ]

    for category_name, category_key in categories:
        items = result.get(category_key, [])
        count = len(items)

        if count > 0:
            print(f"  {category_name}: {count} found")
            for item in items:
                if isinstance(item, dict):
                    print(f"    - {item['type']}: {item['string'][:60]}")
                else:
                    print(f"    - {item[:60]}")
            print()

    # Verification
    print("=" * 70)
    print("Verification:")
    print("=" * 70)

    checks = [
        (len(result['urls']) >= 2, "URLs detected"),
        (len(result['api_keys']) >= 2, "API keys detected"),
        (len(result['package_names']) >= 2, "Package names detected"),
        (len(result['email_addresses']) >= 2, "Email addresses detected"),
        (len(result['ip_addresses']) >= 2, "IP addresses detected"),
        (len(result['database_strings']) >= 2, "Database strings detected"),
        (result['total_sensitive'] >= 10, "Total sensitive strings count correct"),
    ]

    all_passed = True
    for check, description in checks:
        status = "✓ PASS" if check else "✗ FAIL"
        print(f"{status}: {description}")
        if not check:
            all_passed = False

    print("=" * 70)
    if all_passed:
        print("All checks PASSED!")
    else:
        print("Some checks FAILED!")
    print("=" * 70)

    return all_passed

if __name__ == "__main__":
    success = test_sensitive_string_detection()
    exit(0 if success else 1)
