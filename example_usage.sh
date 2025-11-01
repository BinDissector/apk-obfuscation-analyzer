#!/bin/bash

# Example Usage Script for APK Obfuscation Analyzer
# This demonstrates common usage patterns

set -e

echo "APK Obfuscation Analyzer - Example Usage"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Example 1: Basic Analysis
echo -e "${BLUE}Example 1: Basic APK Comparison${NC}"
echo "Command: ./analyzer.py original.apk obfuscated.apk"
echo ""
# Uncomment to run:
# ./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk
echo ""

# Example 2: Custom Output Directory
echo -e "${BLUE}Example 2: Custom Output Directory${NC}"
echo "Command: ./analyzer.py original.apk obfuscated.apk -o ./my_analysis"
echo ""
# Uncomment to run:
# ./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk -o ./my_analysis
echo ""

# Example 3: Verbose Mode
echo -e "${BLUE}Example 3: Verbose Mode for Debugging${NC}"
echo "Command: ./analyzer.py original.apk obfuscated.apk -v"
echo ""
# Uncomment to run:
# ./analyzer.py apks/myapp_original.apk apks/myapp_obfuscated.apk -v
echo ""

# Example 4: Batch Processing
echo -e "${BLUE}Example 4: Batch Process Multiple APK Pairs${NC}"
echo "Command: ./batch_analyze.sh -d ./apks -o ./results"
echo ""
echo "Setup: Place APK pairs in ./apks/ directory:"
echo "  - app1_original.apk + app1_obfuscated.apk"
echo "  - app2_original.apk + app2_obfuscated.apk"
echo ""
# Uncomment to run:
# ./batch_analyze.sh -d ./apks -o ./results
echo ""

# Example 5: Docker Analysis
echo -e "${BLUE}Example 5: Run Analysis in Docker${NC}"
echo "Build: docker build -t apk-analyzer ."
echo "Run: docker run -v \$(pwd)/apks:/apks -v \$(pwd)/results:/results apk-analyzer \\"
echo "       /apks/original.apk /apks/obfuscated.apk -o /results"
echo ""

# Example 6: CI/CD Integration
echo -e "${BLUE}Example 6: CI/CD Score Check${NC}"
cat << 'EOF'
#!/bin/bash
# ci-check.sh - Fail build if obfuscation score is too low

./analyzer.py original.apk obfuscated.apk -o ./results

# Extract score from latest JSON report
SCORE=$(python3 -c "
import json
import glob
report = max(glob.glob('./results/analysis_*.json'))
data = json.load(open(report))
print(int(data['obfuscation_score']))
")

echo "Obfuscation Score: $SCORE/100"

if [ "$SCORE" -lt 50 ]; then
    echo "ERROR: Obfuscation score too low!"
    exit 1
fi

echo "✓ Obfuscation meets minimum requirements"
EOF
echo ""

# Example 7: Running Tests
echo -e "${BLUE}Example 7: Run Test Suite${NC}"
echo "Command: ./test_obfuscation.py"
echo ""
# Uncomment to run:
# ./test_obfuscation.py
echo ""

# Example 8: Programmatic Usage
echo -e "${BLUE}Example 8: Use in Python Script${NC}"
cat << 'EOF'
# analyze.py
from analyzer import APKAnalyzer

analyzer = APKAnalyzer(verbose=True)
results = analyzer.compare_apks(
    "original.apk",
    "obfuscated.apk",
    output_dir="./analysis"
)

print(f"Score: {results['obfuscation_score']}")

if results['obfuscation_score'] < 50:
    print("Warning: Low obfuscation!")
    for rec in results['recommendations']:
        print(f"  - {rec}")
EOF
echo ""

echo -e "${GREEN}=========================================="
echo "For more examples, see README.md"
echo -e "==========================================${NC}"
