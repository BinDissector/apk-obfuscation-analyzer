#!/bin/bash

# Batch APK/AAR Obfuscation Analyzer
# Processes multiple APK/AAR pairs for comparison

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
OUTPUT_DIR="./results"
JADX_PATH="jadx"
VERBOSE=""
SINGLE_MODE=false

# Usage information
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Batch process APK/AAR files for obfuscation analysis.

Options:
    -d, --directory DIR    Directory containing APK/AAR files (default: ./apks)
    -o, --output DIR       Output directory for results (default: ./results)
    -j, --jadx-path PATH   Path to jadx executable (default: jadx)
    -s, --single           Analyze all files individually (no pairing required)
    -v, --verbose          Enable verbose output
    -h, --help             Show this help message

File Naming Convention for Pairs:
    Place APK/AAR pairs in the specified directory with naming pattern:
    - Original: app_name_original.apk (or .aar)
    - Obfuscated: app_name_obfuscated.apk (or .aar)

Single File Mode (-s):
    Analyzes all APK/AAR files individually, useful when:
    - Obfuscation status is unknown
    - No original version available
    - Analyzing third-party libraries

Examples:
    # Analyze pairs
    ./apks/
        myapp_original.apk
        myapp_obfuscated.apk

    $0 -d ./apks -o ./results

    # Analyze all files individually
    ./apks/
        app1.apk
        app2.apk
        library1.aar

    $0 -d ./apks -o ./results --single

EOF
    exit 0
}

# Parse command line arguments
APK_DIR="./apks"

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--directory)
            APK_DIR="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -j|--jadx-path)
            JADX_PATH="$2"
            shift 2
            ;;
        -s|--single)
            SINGLE_MODE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE="-v"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Check if APK directory exists
if [ ! -d "$APK_DIR" ]; then
    echo -e "${RED}ERROR: APK directory not found: $APK_DIR${NC}"
    echo "Create the directory and place your APK pairs there."
    exit 1
fi

# Check if analyzer.py exists
if [ ! -f "./analyzer.py" ]; then
    echo -e "${RED}ERROR: analyzer.py not found in current directory${NC}"
    echo "Make sure you're running this script from the project directory."
    exit 1
fi

# Check if jadx is available
if ! command -v "$JADX_PATH" &> /dev/null; then
    echo -e "${RED}ERROR: jadx not found at '$JADX_PATH'${NC}"
    echo "Please install jadx or specify the correct path with --jadx-path"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Batch APK/AAR Obfuscation Analyzer${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Files Directory: $APK_DIR"
echo "Output Directory: $OUTPUT_DIR"
echo "jadx Path: $JADX_PATH"
echo ""

# Single file mode: analyze all APK/AAR files individually
if [ "$SINGLE_MODE" = true ]; then
    echo -e "${YELLOW}Mode: Single File Analysis (no pairing)${NC}"
    echo ""

    # Find all APK and AAR files
    all_files=$(find "$APK_DIR" \( -name "*.apk" -o -name "*.aar" \) -type f | sort)

    if [ -z "$all_files" ]; then
        echo -e "${RED}ERROR: No APK or AAR files found in $APK_DIR${NC}"
        exit 1
    fi

    total_files=$(echo "$all_files" | wc -l)
    current=0
    success=0
    failed=0

    echo -e "${GREEN}Found $total_files file(s) to analyze${NC}"
    echo ""

    # Process each file
    while IFS= read -r file_path; do
        ((current++))

        file_name=$(basename "$file_path")
        base_name="${file_name%.*}"

        echo -e "${BLUE}----------------------------------------${NC}"
        echo -e "${BLUE}[$current/$total_files] Analyzing: $file_name${NC}"
        echo -e "${BLUE}----------------------------------------${NC}"

        # Create subdirectory for this file's results
        file_output_dir="${OUTPUT_DIR}/${base_name}"
        mkdir -p "$file_output_dir"

        # Run analyzer (single file mode)
        if python3 ./analyzer.py "$file_path" \
            -o "$file_output_dir" \
            --jadx-path "$JADX_PATH" \
            $VERBOSE; then
            echo -e "${GREEN}✓ Successfully analyzed $file_name${NC}"
            ((success++))
        else
            echo -e "${RED}✗ Failed to analyze $file_name${NC}"
            ((failed++))
        fi

        echo ""

    done <<< "$all_files"

    # Jump to summary
    total_pairs=$total_files

else
    # Pair mode: find and compare original/obfuscated pairs
    echo -e "${YELLOW}Mode: Comparison (pairing required)${NC}"
    echo ""

    # Find all original files (both APK and AAR)
    original_files=$(find "$APK_DIR" \( -name "*_original.apk" -o -name "*_original.aar" \) -type f | sort)

    if [ -z "$original_files" ]; then
        echo -e "${YELLOW}WARNING: No file pairs found with naming pattern *_original.apk or *_original.aar${NC}"
        echo ""
        echo "Expected naming convention:"
        echo "  - Original: app_name_original.apk (or .aar)"
        echo "  - Obfuscated: app_name_obfuscated.apk (or .aar)"
        echo ""
        echo "Tip: Use --single mode to analyze files individually"
        exit 1
    fi

    # Count total pairs
    total_pairs=$(echo "$original_files" | wc -l)
    current=0
    success=0
    failed=0

    echo -e "${GREEN}Found $total_pairs file pair(s) to process${NC}"
    echo ""

    # Process each pair
    while IFS= read -r original_file; do
        ((current++))

        # Detect file extension
        if [[ "$original_file" == *.apk ]]; then
            ext=".apk"
            ext_pattern="_original.apk"
        else
            ext=".aar"
            ext_pattern="_original.aar"
        fi

        # Extract base name (remove _original.ext)
        base_name=$(basename "$original_file" "$ext_pattern")
        file_dir=$(dirname "$original_file")
        obfuscated_file="${file_dir}/${base_name}_obfuscated${ext}"

        echo -e "${BLUE}----------------------------------------${NC}"
        echo -e "${BLUE}[$current/$total_pairs] Processing: $base_name${NC}"
        echo -e "${BLUE}----------------------------------------${NC}"

        # Check if obfuscated file exists
        if [ ! -f "$obfuscated_file" ]; then
            echo -e "${RED}ERROR: Obfuscated file not found: $obfuscated_file${NC}"
            echo -e "${YELLOW}Skipping this pair...${NC}"
            ((failed++))
            echo ""
            continue
        fi

        echo "Original: $original_file"
        echo "Obfuscated: $obfuscated_file"
        echo ""

        # Create subdirectory for this app's results
        app_output_dir="${OUTPUT_DIR}/${base_name}"
        mkdir -p "$app_output_dir"

        # Run analyzer
        if python3 ./analyzer.py "$original_file" "$obfuscated_file" \
            -o "$app_output_dir" \
            --jadx-path "$JADX_PATH" \
            $VERBOSE; then
            echo -e "${GREEN}✓ Successfully analyzed $base_name${NC}"
            ((success++))
        else
            echo -e "${RED}✗ Failed to analyze $base_name${NC}"
            ((failed++))
        fi

        echo ""

    done <<< "$original_files"

fi  # End of single/pair mode if statement

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Batch Analysis Complete${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Total pairs processed: $total_pairs"
echo -e "${GREEN}Successful: $success${NC}"
if [ $failed -gt 0 ]; then
    echo -e "${RED}Failed: $failed${NC}"
fi
echo ""
echo "Results saved to: $OUTPUT_DIR"

# Generate index.html with links to all reports
index_file="${OUTPUT_DIR}/index.html"
echo "Generating index page: $index_file"

cat > "$index_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>APK/AAR Obfuscation Analysis - Batch Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .summary {
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .app-list {
            list-style: none;
            padding: 0;
        }
        .app-item {
            padding: 15px;
            margin: 10px 0;
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            border-radius: 4px;
        }
        .app-item:hover {
            background-color: #e9ecef;
        }
        .app-item a {
            color: #2c3e50;
            text-decoration: none;
            font-size: 18px;
            font-weight: bold;
        }
        .app-item a:hover {
            color: #3498db;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>APK/AAR Obfuscation Analysis - Batch Results</h1>
        <div class="summary">
            <p><strong>Total Analyzed:</strong> TOTAL_COUNT</p>
            <p class="timestamp">Generated: TIMESTAMP</p>
        </div>
        <h2>Analysis Reports</h2>
        <ul class="app-list">
LINKS
        </ul>
    </div>
</body>
</html>
EOF

# Add links to each report
links=""
total_count=0
for app_dir in "$OUTPUT_DIR"/*/; do
    if [ -d "$app_dir" ]; then
        app_name=$(basename "$app_dir")
        # Find the most recent HTML report (both comparison and single-file)
        latest_report=$(ls -t "${app_dir}"/report_*.html "${app_dir}"/single_report_*.html 2>/dev/null | head -n 1)
        if [ -n "$latest_report" ]; then
            report_file=$(basename "$latest_report")
            links="${links}            <li class=\"app-item\"><a href=\"${app_name}/${report_file}\">${app_name}</a></li>\n"
            ((total_count++))
        fi
    fi
done

# Update index.html with actual data
timestamp=$(date '+%Y-%m-%d %H:%M:%S')
sed -i "s/TOTAL_COUNT/$total_count/" "$index_file"
sed -i "s/TIMESTAMP/$timestamp/" "$index_file"
sed -i "s|LINKS|$links|" "$index_file"

echo -e "${GREEN}✓ Index page created: $index_file${NC}"
echo ""
echo "Open $index_file in your browser to view all results."

exit 0
