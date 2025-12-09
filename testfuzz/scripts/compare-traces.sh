#!/bin/bash
# Cross-VM Trace Comparison Script
# Compares execution traces between geth and Besu for divergent test clusters

set -euo pipefail

# Default configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BESU_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
GETH_ROOT="${GETH_ROOT:-$BESU_ROOT/../go-ethereum}"
BESU_FUZZ="$BESU_ROOT/testfuzz/build/install/BesuFuzz/bin/BesuFuzz"
GETH_TRACE="${GETH_ROOT}/statetest-trace"
FORK="${FORK:-Osaka}"
OUTPUT_DIR=""
VALIDATION_REPORT=""
MAX_CLUSTERS="${MAX_CLUSTERS:-0}"  # 0 = all clusters
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <validation-report.json>

Compare execution traces between geth and Besu for divergent test clusters.

Options:
    -o, --output-dir DIR     Output directory (default: trace-comparison-YYYY-MM-DD)
    -f, --fork FORK          EVM fork to use (default: $FORK)
    -g, --geth-root DIR      Path to go-ethereum root (default: $GETH_ROOT)
    -n, --max-clusters N     Maximum number of clusters to process (default: all)
    -v, --verbose            Enable verbose output
    -h, --help               Show this help message

Environment Variables:
    GETH_ROOT               Path to go-ethereum root directory
    FORK                    EVM fork to use for execution
    MAX_CLUSTERS            Maximum clusters to process (0 = all)
    VERBOSE                 Set to 'true' for verbose output

Examples:
    # Compare all clusters from a validation report
    $(basename "$0") validation-results-2025-12-09/validation_report.json

    # Compare first 10 clusters with verbose output
    $(basename "$0") -n 10 -v validation_report.json

    # Specify output directory and fork
    $(basename "$0") -o ./my-comparison -f Prague validation_report.json

Output Structure:
    <output-dir>/
    ├── summary.json           # Overall comparison summary
    ├── summary.txt            # Human-readable summary
    └── cluster-<hash>/        # Per-cluster directories
        ├── test.json          # Original test file
        ├── besu-trace.jsonl   # Besu execution trace
        ├── geth-trace.jsonl   # Geth execution trace
        ├── diff.txt           # Side-by-side diff
        └── report.json        # Structured comparison report

EOF
    exit "${1:-0}"
}

log() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    echo -e "${GREEN}[OK]${NC} $*" >&2
}

debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $*" >&2
    fi
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--fork)
                FORK="$2"
                shift 2
                ;;
            -g|--geth-root)
                GETH_ROOT="$2"
                GETH_TRACE="${GETH_ROOT}/statetest-trace"
                shift 2
                ;;
            -n|--max-clusters)
                MAX_CLUSTERS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE="true"
                shift
                ;;
            -h|--help)
                usage 0
                ;;
            -*)
                error "Unknown option: $1"
                usage 1
                ;;
            *)
                if [[ -z "$VALIDATION_REPORT" ]]; then
                    VALIDATION_REPORT="$1"
                else
                    error "Unexpected argument: $1"
                    usage 1
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$VALIDATION_REPORT" ]]; then
        error "Validation report file is required"
        usage 1
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="trace-comparison-$(date -I)"
    fi
}

# Validate prerequisites
check_prerequisites() {
    log "Checking prerequisites..."

    # Check validation report exists
    if [[ ! -f "$VALIDATION_REPORT" ]]; then
        error "Validation report not found: $VALIDATION_REPORT"
        exit 2
    fi

    # Check BesuFuzz
    if [[ ! -x "$BESU_FUZZ" ]]; then
        warn "BesuFuzz not found at $BESU_FUZZ"
        log "Building BesuFuzz..."
        (cd "$BESU_ROOT" && ./gradlew :testfuzz:installDist -q)
        if [[ ! -x "$BESU_FUZZ" ]]; then
            error "Failed to build BesuFuzz"
            exit 2
        fi
    fi
    success "BesuFuzz: $BESU_FUZZ"

    # Check geth statetest-trace
    if [[ ! -x "$GETH_TRACE" ]]; then
        warn "geth statetest-trace not found at $GETH_TRACE"
        log "Building statetest-trace..."
        if [[ ! -d "$GETH_ROOT" ]]; then
            error "go-ethereum not found at $GETH_ROOT. Set GETH_ROOT or use --geth-root"
            exit 2
        fi
        (cd "$GETH_ROOT" && go build -o statetest-trace ./tests/fuzzers/statetest/cmd/statetest-trace/)
        if [[ ! -x "$GETH_TRACE" ]]; then
            error "Failed to build statetest-trace"
            exit 2
        fi
    fi
    success "Geth statetest-trace: $GETH_TRACE"

    # Check jq is available
    if ! command -v jq &> /dev/null; then
        error "jq is required but not installed"
        exit 2
    fi
    success "jq: $(which jq)"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    success "Output directory: $OUTPUT_DIR"
}

# Extract unique clusters from validation report
extract_clusters() {
    log "Extracting divergence clusters from $VALIDATION_REPORT..."

    # Use jq to extract unique (expectedTraceHash, actualTraceHash) pairs
    # and pick one representative test file for each
    local clusters_json
    clusters_json=$(jq -r '
        .divergences
        | group_by(.expectedTraceHash + "_" + .actualTraceHash)
        | map({
            clusterKey: (.[0].expectedTraceHash + "_" + .[0].actualTraceHash),
            expectedHash: .[0].expectedTraceHash,
            actualHash: .[0].actualTraceHash,
            count: length,
            representative: .[0].path,
            testName: .[0].testName,
            divergenceType: .[0].divergenceType
        })
        | sort_by(-.count)
    ' "$VALIDATION_REPORT")

    echo "$clusters_json"
}

# Compare traces for a single cluster
compare_cluster() {
    local cluster_num="$1"
    local cluster_key="$2"
    local expected_hash="$3"
    local actual_hash="$4"
    local test_file="$5"
    local test_name="$6"
    local divergence_type="$7"
    local cluster_count="$8"

    # Use first 8 chars of expected + first 8 chars of actual hash for unique dir name
    local short_key="${expected_hash:0:8}_${actual_hash:0:8}"
    local cluster_dir="$OUTPUT_DIR/cluster-${short_key}"
    mkdir -p "$cluster_dir"

    debug "Processing cluster $cluster_num: $cluster_key"
    debug "  Test file: $test_file"
    debug "  Test name: $test_name"

    # Check test file exists
    if [[ ! -f "$test_file" ]]; then
        warn "Test file not found: $test_file"
        echo '{"status":"error","error":"test_file_not_found"}' > "$cluster_dir/report.json"
        return 1
    fi

    # Copy test file
    cp "$test_file" "$cluster_dir/test.json"

    local besu_trace="$cluster_dir/besu-trace.jsonl"
    local geth_trace="$cluster_dir/geth-trace.jsonl"
    local diff_file="$cluster_dir/diff.txt"
    local report_file="$cluster_dir/report.json"

    # Generate Besu trace
    debug "  Generating Besu trace..."
    if ! "$BESU_FUZZ" dump-trace "$test_file" --fork="$FORK" > "$besu_trace" 2>/dev/null; then
        warn "Besu trace generation failed for $test_file"
        echo '{"status":"error","error":"besu_trace_failed"}' > "$report_file"
        return 1
    fi

    # Generate geth trace
    debug "  Generating geth trace..."
    if ! "$GETH_TRACE" dump "$test_file" > "$geth_trace" 2>/dev/null; then
        warn "Geth trace generation failed for $test_file"
        echo '{"status":"error","error":"geth_trace_failed"}' > "$report_file"
        return 1
    fi

    # Extract trace hashes from outputs
    local besu_hash geth_hash
    besu_hash=$(tail -1 "$besu_trace" | jq -r '._result.traceHash // empty' 2>/dev/null || echo "")
    geth_hash=$(tail -1 "$geth_trace" | jq -r '._result.traceHash // empty' 2>/dev/null || echo "")

    # Extract state roots (from stateRoot line, not _result line)
    local besu_state_root geth_state_root
    besu_state_root=$(grep '"stateRoot"' "$besu_trace" | head -1 | jq -r '.stateRoot // empty' 2>/dev/null || echo "")
    geth_state_root=$(grep '"stateRoot"' "$geth_trace" | head -1 | jq -r '.stateRoot // empty' 2>/dev/null || echo "")

    # Count trace lines (excluding meta/result lines)
    local besu_lines geth_lines
    besu_lines=$(grep -c '"pc":' "$besu_trace" 2>/dev/null || true)
    besu_lines="${besu_lines:-0}"
    geth_lines=$(grep -c '"pc":' "$geth_trace" 2>/dev/null || true)
    geth_lines="${geth_lines:-0}"

    # Generate diff
    debug "  Generating diff..."
    {
        echo "=== Trace Comparison: Cluster $cluster_key ==="
        echo "Test: $test_file"
        echo "Fork: $FORK"
        echo ""
        echo "Expected trace hash (geth): $expected_hash"
        echo "Actual trace hash (besu):   $actual_hash"
        echo ""
        echo "Besu trace hash: $besu_hash ($besu_lines trace lines)"
        echo "Geth trace hash: $geth_hash ($geth_lines trace lines)"
        echo ""
        echo "Besu state root: $besu_state_root"
        echo "Geth state root: $geth_state_root"
        echo ""
        echo "=== Side-by-side diff (first 100 differences) ==="
        diff -y --width=200 --suppress-common-lines \
            <(head -50 "$besu_trace" | jq -c '. | {pc,op,opName,gas,stack}' 2>/dev/null || cat) \
            <(head -50 "$geth_trace" | jq -c '. | {pc,op,opName,gas,stack}' 2>/dev/null || cat) \
            | head -100 || true
        echo ""
        echo "=== First diverging line ==="
        local first_diff_line
        first_diff_line=$(diff <(head -50 "$besu_trace") <(head -50 "$geth_trace") | head -5 || true)
        echo "$first_diff_line"
    } > "$diff_file"

    # Find first divergence
    local first_divergence=""
    local divergence_pc=""
    local besu_op="" geth_op=""

    # Compare line by line to find first difference
    while IFS= read -r besu_line && IFS= read -r geth_line <&3; do
        # Skip meta lines
        if [[ "$besu_line" == *'"_meta"'* ]] || [[ "$besu_line" == *'"_result"'* ]]; then
            continue
        fi

        local besu_normalized geth_normalized
        besu_normalized=$(echo "$besu_line" | jq -c '{pc,op,opName,gas}' 2>/dev/null || echo "$besu_line")
        geth_normalized=$(echo "$geth_line" | jq -c '{pc,op,opName,gas}' 2>/dev/null || echo "$geth_line")

        if [[ "$besu_normalized" != "$geth_normalized" ]]; then
            divergence_pc=$(echo "$besu_line" | jq -r '.pc // "unknown"' 2>/dev/null || echo "unknown")
            besu_op=$(echo "$besu_line" | jq -r '.opName // "unknown"' 2>/dev/null || echo "unknown")
            geth_op=$(echo "$geth_line" | jq -r '.opName // "unknown"' 2>/dev/null || echo "unknown")
            first_divergence="pc=$divergence_pc: besu=$besu_op, geth=$geth_op"
            break
        fi
    done < "$besu_trace" 3< "$geth_trace"

    # Determine divergence category
    local category="unknown"
    if [[ "$besu_op" == *"not defined"* ]]; then
        category="missing_opcode"
    elif [[ -n "$besu_op" && -n "$geth_op" && "$besu_op" != "$geth_op" ]]; then
        category="opcode_mismatch"
    elif [[ "$besu_state_root" != "$geth_state_root" && -n "$besu_state_root" && -n "$geth_state_root" ]]; then
        category="state_root_mismatch"
    elif [[ "$besu_lines" != "$geth_lines" ]]; then
        category="trace_length_mismatch"
    elif [[ "$besu_hash" != "$geth_hash" && -n "$besu_hash" && -n "$geth_hash" ]]; then
        category="trace_hash_mismatch"
    fi

    # Generate report
    jq -n \
        --arg cluster_key "$cluster_key" \
        --arg test_file "$test_file" \
        --arg test_name "$test_name" \
        --arg fork "$FORK" \
        --arg expected_hash "$expected_hash" \
        --arg actual_hash "$actual_hash" \
        --arg besu_hash "$besu_hash" \
        --arg geth_hash "$geth_hash" \
        --arg besu_state_root "$besu_state_root" \
        --arg geth_state_root "$geth_state_root" \
        --argjson besu_lines "$besu_lines" \
        --argjson geth_lines "$geth_lines" \
        --arg first_divergence "$first_divergence" \
        --arg category "$category" \
        --arg divergence_type "$divergence_type" \
        --argjson cluster_count "$cluster_count" \
        '{
            status: "compared",
            clusterKey: $cluster_key,
            testFile: $test_file,
            testName: $test_name,
            fork: $fork,
            expectedTraceHash: $expected_hash,
            actualTraceHash: $actual_hash,
            besuTraceHash: $besu_hash,
            gethTraceHash: $geth_hash,
            besuStateRoot: $besu_state_root,
            gethStateRoot: $geth_state_root,
            besuTraceLines: $besu_lines,
            gethTraceLines: $geth_lines,
            firstDivergence: $first_divergence,
            category: $category,
            divergenceType: $divergence_type,
            clusterSize: $cluster_count,
            hashMatch: ($besu_hash == $geth_hash),
            stateRootMatch: ($besu_state_root == $geth_state_root)
        }' > "$report_file"

    return 0
}

# Generate summary report
generate_summary() {
    local total_clusters="$1"
    local processed_clusters="$2"
    local successful="$3"
    local failed="$4"

    log "Generating summary report..."

    # Aggregate all cluster reports
    local all_reports=()
    for report in "$OUTPUT_DIR"/cluster-*/report.json; do
        if [[ -f "$report" ]]; then
            all_reports+=("$report")
        fi
    done

    # Generate JSON summary
    {
        echo "{"
        echo "  \"generatedAt\": \"$(date -Iseconds)\","
        echo "  \"validationReport\": \"$VALIDATION_REPORT\","
        echo "  \"fork\": \"$FORK\","
        echo "  \"totalClusters\": $total_clusters,"
        echo "  \"processedClusters\": $processed_clusters,"
        echo "  \"successful\": $successful,"
        echo "  \"failed\": $failed,"
        echo "  \"outputDir\": \"$OUTPUT_DIR\","
        echo "  \"besuTool\": \"$BESU_FUZZ\","
        echo "  \"gethTool\": \"$GETH_TRACE\","
        echo "  \"clusters\": ["

        local first=true
        for report in "${all_reports[@]}"; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            cat "$report"
        done

        echo ""
        echo "  ],"

        # Category breakdown
        echo "  \"categoryBreakdown\": {"
        if [[ ${#all_reports[@]} -gt 0 ]]; then
            jq -s '
                group_by(.category)
                | map({key: .[0].category, value: length})
                | from_entries
            ' "${all_reports[@]}" | sed 's/^/    /' | tail -n +2 | head -n -1
        fi
        echo "  }"
        echo "}"
    } | jq '.' > "$OUTPUT_DIR/summary.json"

    # Generate human-readable summary
    {
        echo "========================================"
        echo "Cross-VM Trace Comparison Summary"
        echo "========================================"
        echo ""
        echo "Generated: $(date)"
        echo "Validation Report: $VALIDATION_REPORT"
        echo "Fork: $FORK"
        echo ""
        echo "Results:"
        echo "  Total clusters:     $total_clusters"
        echo "  Processed:          $processed_clusters"
        echo "  Successful:         $successful"
        echo "  Failed:             $failed"
        echo ""
        echo "Category Breakdown:"

        if [[ ${#all_reports[@]} -gt 0 ]]; then
            jq -rs '
                group_by(.category)
                | map("  \(.[0].category): \(length) clusters")
                | .[]
            ' "${all_reports[@]}" 2>/dev/null || echo "  (no data)"
        fi

        echo ""
        echo "Divergence Details:"
        echo "-------------------"

        for report in "${all_reports[@]}"; do
            local cluster_key test_name first_div category cluster_size
            cluster_key=$(jq -r '.clusterKey' "$report")
            test_name=$(jq -r '.testName' "$report")
            first_div=$(jq -r '.firstDivergence' "$report")
            category=$(jq -r '.category' "$report")
            cluster_size=$(jq -r '.clusterSize' "$report")

            echo ""
            echo "Cluster: ${cluster_key:0:16}..."
            echo "  Category: $category"
            echo "  Size: $cluster_size tests"
            echo "  Representative: $test_name"
            echo "  First divergence: $first_div"
        done

        echo ""
        echo "========================================"
        echo "Output directory: $OUTPUT_DIR"
        echo "========================================"
    } > "$OUTPUT_DIR/summary.txt"

    success "Summary written to $OUTPUT_DIR/summary.json and $OUTPUT_DIR/summary.txt"
}

# Main execution
main() {
    parse_args "$@"
    check_prerequisites

    log "Starting cross-VM trace comparison..."
    log "Fork: $FORK"
    log "Validation report: $VALIDATION_REPORT"

    # Extract clusters
    local clusters_json
    clusters_json=$(extract_clusters)

    local total_clusters
    total_clusters=$(echo "$clusters_json" | jq 'length')
    log "Found $total_clusters divergence clusters"

    # Determine how many to process
    local process_count="$total_clusters"
    if [[ "$MAX_CLUSTERS" -gt 0 && "$MAX_CLUSTERS" -lt "$total_clusters" ]]; then
        process_count="$MAX_CLUSTERS"
        log "Processing first $process_count clusters (use -n to change)"
    fi

    # Process each cluster
    local successful=0
    local failed=0
    local i=0

    while IFS= read -r cluster; do
        ((i++)) || true

        if [[ "$MAX_CLUSTERS" -gt 0 && "$i" -gt "$MAX_CLUSTERS" ]]; then
            break
        fi

        local cluster_key expected_hash actual_hash test_file test_name divergence_type cluster_count
        cluster_key=$(echo "$cluster" | jq -r '.clusterKey')
        expected_hash=$(echo "$cluster" | jq -r '.expectedHash')
        actual_hash=$(echo "$cluster" | jq -r '.actualHash')
        test_file=$(echo "$cluster" | jq -r '.representative')
        test_name=$(echo "$cluster" | jq -r '.testName')
        divergence_type=$(echo "$cluster" | jq -r '.divergenceType')
        cluster_count=$(echo "$cluster" | jq -r '.count')

        printf "\r[%d/%d] Processing cluster %s_%s... " "$i" "$process_count" "${expected_hash:0:8}" "${actual_hash:0:8}"

        if compare_cluster "$i" "$cluster_key" "$expected_hash" "$actual_hash" "$test_file" "$test_name" "$divergence_type" "$cluster_count"; then
            ((successful++)) || true
        else
            ((failed++)) || true
        fi
    done < <(echo "$clusters_json" | jq -c '.[]')

    echo ""  # Clear progress line

    # Generate summary
    generate_summary "$total_clusters" "$process_count" "$successful" "$failed"

    log "Comparison complete!"
    log "  Processed: $process_count clusters"
    log "  Successful: $successful"
    log "  Failed: $failed"
    log "  Output: $OUTPUT_DIR"

    # Show quick summary
    echo ""
    cat "$OUTPUT_DIR/summary.txt"

    # Return appropriate exit code
    if [[ "$failed" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
