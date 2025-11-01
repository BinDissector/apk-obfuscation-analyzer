#!/bin/bash
#
# Simple Release Checker Script
# This script makes it easy to check if your APK is ready for release
#

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║      APK Release Readiness Checker                        ║"
echo "║      Quick check before releasing to production           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if APK file is provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}📋 Usage:${NC}"
    echo "  $0 <path-to-your-apk> [obfuscator] [min-score] [timeout] [memory]"
    echo ""
    echo -e "${GREEN}✨ Quick Start Examples:${NC}"
    echo ""
    echo -e "  ${BLUE}Basic check:${NC}"
    echo "    $0 app-release.apk"
    echo ""
    echo -e "  ${BLUE}Verify R8 obfuscation:${NC}"
    echo "    $0 app-release.apk R8"
    echo ""
    echo -e "  ${BLUE}Require score of 60+:${NC}"
    echo "    $0 app-release.apk ProGuard 60"
    echo ""
    echo -e "  ${BLUE}Large APK with custom timeout and memory:${NC}"
    echo "    $0 large-app.apk R8 50 1800 8G"
    echo ""
    echo -e "${YELLOW}ℹ️  Available obfuscators:${NC} R8, ProGuard"
    echo -e "${YELLOW}ℹ️  Default minimum score:${NC} 40 (recommend 50+ for high security)"
    echo -e "${YELLOW}ℹ️  Default timeout:${NC} 900 seconds (15 minutes)"
    echo -e "${YELLOW}ℹ️  Default memory:${NC} 4G (increase for large APKs)"
    echo ""
    echo -e "${BLUE}📖 Need help?${NC} See GETTING_STARTED.md"
    exit 1
fi

APK_FILE="$1"
EXPECTED_OBFUSCATOR="${2:-}"
MIN_SCORE="${3:-40}"
JADX_TIMEOUT="${4:-900}"
JADX_MEMORY="${5:-4G}"

# Check if APK exists
if [ ! -f "$APK_FILE" ]; then
    echo -e "${RED}✗ Error: APK file not found: $APK_FILE${NC}"
    exit 1
fi

echo -e "${BLUE}Analyzing:${NC} $APK_FILE"
if [ -n "$EXPECTED_OBFUSCATOR" ]; then
    echo -e "${BLUE}Expected Obfuscator:${NC} $EXPECTED_OBFUSCATOR"
fi
echo -e "${BLUE}Minimum Score Required:${NC} $MIN_SCORE"
echo -e "${BLUE}Timeout:${NC} $JADX_TIMEOUT seconds ($((JADX_TIMEOUT/60)) minutes)"
echo -e "${BLUE}Memory:${NC} $JADX_MEMORY"
echo ""

# Find jadx
JADX_PATH="jadx"
if [ -f "$HOME/jadx/bin/jadx" ]; then
    JADX_PATH="$HOME/jadx/bin/jadx"
fi

# Build command
CMD="./analyzer.py \"$APK_FILE\" --jadx-path \"$JADX_PATH\" --min-score $MIN_SCORE --jadx-timeout $JADX_TIMEOUT --jadx-memory $JADX_MEMORY"
if [ -n "$EXPECTED_OBFUSCATOR" ]; then
    CMD="$CMD --expect-obfuscator $EXPECTED_OBFUSCATOR"
fi

echo -e "${BLUE}Running analysis...${NC}"
echo ""

# Run analyzer
if eval $CMD; then
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ Analysis Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}View detailed HTML report:${NC}"
    echo "  xdg-open results/single_report_*.html"
    echo ""
    echo -e "${BLUE}View JSON data:${NC}"
    echo "  cat results/single_analysis_*.json | python3 -m json.tool"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}✗ Analysis Failed${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting tips:${NC}"
    echo "  1. Make sure jadx is installed: jadx --version"
    echo "  2. Check the APK file is valid"
    echo "  3. Try with verbose mode: ./analyzer.py \"$APK_FILE\" -v"
    echo ""
    exit 1
fi
