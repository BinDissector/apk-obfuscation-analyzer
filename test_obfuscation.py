#!/usr/bin/env python3
"""
Quick test script for APK obfuscation detection
Tests individual components of the analyzer without full APK decompilation
"""

import sys
import tempfile
import os
from pathlib import Path


def test_identifier_analysis():
    """Test identifier analysis on sample code"""
    print("Testing Identifier Analysis...")

    # Create sample Java files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Original code (readable)
        original_code = """
public class UserManager {
    private String userName;
    private int userId;

    public void authenticateUser() {
        // Authentication logic
    }

    public boolean validateCredentials(String password) {
        return true;
    }
}
"""

        # Obfuscated code
        obfuscated_code = """
public class a {
    private String b;
    private int c;

    public void d() {
        // Authentication logic
    }

    public boolean e(String f) {
        return true;
    }
}
"""

        # Write test files
        original_file = os.path.join(temp_dir, "UserManager.java")
        obfuscated_file = os.path.join(temp_dir, "a.java")

        with open(original_file, 'w') as f:
            f.write(original_code)

        with open(obfuscated_file, 'w') as f:
            f.write(obfuscated_code)

        # Test analysis
        from analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        print("\n  Original code analysis:")
        original_metrics = analyzer.analyze_identifiers(temp_dir)
        print(f"    Classes: {original_metrics['total_classes']}")
        print(f"    Single-char classes: {original_metrics['single_char_classes']}")
        print(f"    Meaningful classes: {original_metrics['meaningful_classes']}")

        # Remove original, keep obfuscated
        os.remove(original_file)

        print("\n  Obfuscated code analysis:")
        obfuscated_metrics = analyzer.analyze_identifiers(temp_dir)
        print(f"    Classes: {obfuscated_metrics['total_classes']}")
        print(f"    Single-char classes: {obfuscated_metrics['single_char_classes']}")
        print(f"    Meaningful classes: {obfuscated_metrics['meaningful_classes']}")

        # Verify detection
        if obfuscated_metrics['single_char_classes'] > 0:
            print("\n  ✓ Obfuscation detected correctly!")
            return True
        else:
            print("\n  ✗ Failed to detect obfuscation")
            return False


def test_string_analysis():
    """Test string encryption detection"""
    print("\nTesting String Analysis...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Code with encrypted strings
        encrypted_code = """
public class Config {
    private static final String API_KEY = "dGhpc2lzYXRlc3RrZXk=";
    private static final String SECRET = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=";

    public String decrypt(String encrypted) {
        return base64Decode(encrypted);
    }
}
"""

        test_file = os.path.join(temp_dir, "Config.java")
        with open(test_file, 'w') as f:
            f.write(encrypted_code)

        from analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        metrics = analyzer.analyze_strings(temp_dir)
        print(f"\n  Total strings: {metrics['total_strings']}")
        print(f"  Base64 strings: {metrics['base64_strings']}")
        print(f"  Decryption methods: {metrics['decryption_methods']}")

        if metrics['base64_strings'] > 0:
            print("\n  ✓ String encryption detected!")
            return True
        else:
            print("\n  ✗ Failed to detect string encryption")
            return False


def test_package_structure():
    """Test package structure analysis"""
    print("\nTesting Package Structure Analysis...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create nested package structure
        deep_package = os.path.join(temp_dir, "com", "example", "myapp", "ui", "activities")
        os.makedirs(deep_package, exist_ok=True)

        # Create a Java file
        test_file = os.path.join(deep_package, "MainActivity.java")
        with open(test_file, 'w') as f:
            f.write("public class MainActivity {}")

        from analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        metrics = analyzer.analyze_package_structure(temp_dir)
        print(f"\n  Total packages: {metrics['total_packages']}")
        print(f"  Max depth: {metrics['max_package_depth']}")
        print(f"  Avg depth: {metrics['avg_package_depth']:.1f}")

        if metrics['max_package_depth'] >= 5:
            print("\n  ✓ Deep package structure detected!")
            return True
        else:
            print("\n  ✗ Unexpected package depth")
            return False


def test_obfuscation_patterns():
    """Test obfuscation pattern detection"""
    print("\nTesting Obfuscation Pattern Detection...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Create files with obfuscation patterns
        patterns = ['a.java', 'b.java', 'c.java', 'C0001.java', 'C0002.java']

        for filename in patterns:
            filepath = os.path.join(temp_dir, filename)
            with open(filepath, 'w') as f:
                classname = filename.replace('.java', '')
                f.write(f"public class {classname} {{}}")

        from analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        metrics = analyzer.detect_obfuscation_patterns(temp_dir)
        print(f"\n  Sequential naming: {metrics['sequential_naming']}")
        print(f"  Numeric naming: {metrics['numeric_naming']}")

        if metrics['sequential_naming'] > 0 or metrics['numeric_naming'] > 0:
            print("\n  ✓ Obfuscation patterns detected!")
            return True
        else:
            print("\n  ✗ Failed to detect patterns")
            return False


def test_control_flow():
    """Test control flow complexity analysis"""
    print("\nTesting Control Flow Analysis...")

    with tempfile.TemporaryDirectory() as temp_dir:
        # Complex control flow code
        complex_code = """
public class ComplexClass {
    public void complexMethod(int x, int y) {
        if (x > 0) {
            while (y < 10) {
                for (int i = 0; i < 5; i++) {
                    if (i % 2 == 0) {
                        switch (i) {
                            case 0:
                                break;
                            case 2:
                                break;
                            case 4:
                                break;
                        }
                    }
                }
                y++;
            }
        } else if (x < 0) {
            // More logic
        }
    }
}
"""

        test_file = os.path.join(temp_dir, "ComplexClass.java")
        with open(test_file, 'w') as f:
            f.write(complex_code)

        from analyzer import APKAnalyzer
        analyzer = APKAnalyzer()

        metrics = analyzer.analyze_control_flow(temp_dir)
        print(f"\n  Total methods: {metrics['total_methods']}")
        print(f"  Average complexity: {metrics['avg_complexity']:.1f}")
        print(f"  Max complexity: {metrics['max_complexity']:.1f}")

        if metrics['avg_complexity'] > 5:
            print("\n  ✓ Complex control flow detected!")
            return True
        else:
            print("\n  ✗ Low complexity")
            return False


def test_entropy_calculation():
    """Test entropy calculation"""
    print("\nTesting Entropy Calculation...")

    from analyzer import APKAnalyzer
    analyzer = APKAnalyzer()

    # Test strings
    low_entropy = "aaaaaaaaaa"
    high_entropy = "k3Js8x9Pq2"

    low_e = analyzer._calculate_entropy(low_entropy)
    high_e = analyzer._calculate_entropy(high_entropy)

    print(f"\n  Low entropy string: '{low_entropy}' = {low_e:.2f}")
    print(f"  High entropy string: '{high_entropy}' = {high_e:.2f}")

    if high_e > low_e:
        print("\n  ✓ Entropy calculation working!")
        return True
    else:
        print("\n  ✗ Entropy calculation failed")
        return False


def test_jadx_check():
    """Test jadx availability"""
    print("\nTesting jadx Availability...")

    from analyzer import APKAnalyzer
    analyzer = APKAnalyzer()

    if analyzer.check_jadx_available():
        print("\n  ✓ jadx is available!")
        return True
    else:
        print("\n  ✗ jadx not found")
        print("\n  Note: jadx is required for full APK analysis")
        print("  Install: https://github.com/skylot/jadx")
        return False


def run_all_tests():
    """Run all unit tests"""
    print("="*60)
    print("APK Obfuscation Analyzer - Quick Tests")
    print("="*60)

    tests = [
        ("Identifier Analysis", test_identifier_analysis),
        ("String Analysis", test_string_analysis),
        ("Package Structure", test_package_structure),
        ("Obfuscation Patterns", test_obfuscation_patterns),
        ("Control Flow", test_control_flow),
        ("Entropy Calculation", test_entropy_calculation),
        ("jadx Availability", test_jadx_check),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n  ✗ Test failed with error: {e}")
            results.append((name, False))
        print()

    # Summary
    print("="*60)
    print("Test Summary")
    print("="*60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}: {name}")

    print()
    print(f"Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
