#!/bin/bash

# Meraki Enhanced Reporting Suite Runner
# Executes all Python scripts in order with timing and status reporting

echo "🚀 Starting Meraki Enhanced Reporting Suite"
echo "=========================================="

# Start timer
START_TIME=$(date +%s)

# Array of scripts to run in order
SCRIPTS=(
    "meraki_env.py"
    "meraki_query.py" 
    "meraki_backup.py"
    "merge_recommendations.py"
    "report_generator.py"
)

# Track success/failure
SUCCESS_COUNT=0
FAIL_COUNT=0

# Run each script
for script in "${SCRIPTS[@]}"; do
    if [[ -f "$script" ]]; then
        echo ""
        echo "📋 Running: $script"
        echo "-------------------"
        
        SCRIPT_START=$(date +%s)
        if python3 "$script"; then
            SCRIPT_END=$(date +%s)
            SCRIPT_DURATION=$((SCRIPT_END - SCRIPT_START))
            echo "✅ $script completed successfully in ${SCRIPT_DURATION}s"
            ((SUCCESS_COUNT++))
        else
            SCRIPT_END=$(date +%s)
            SCRIPT_DURATION=$((SCRIPT_END - SCRIPT_START))
            echo "❌ $script failed after ${SCRIPT_DURATION}s"
            ((FAIL_COUNT++))
        fi
    else
        echo ""
        echo "⚠️  Script not found: $script - skipping"
    fi
done

# Calculate total time
END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# Final summary
echo ""
echo "=========================================="
echo "📊 SUITE EXECUTION SUMMARY"
echo "=========================================="
echo "✅ Successful scripts: $SUCCESS_COUNT"
echo "❌ Failed scripts: $FAIL_COUNT"
echo "⏱️  Total execution time: ${TOTAL_DURATION}s"
echo ""

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "🎉 All scripts completed successfully!"
    echo "📊 Reports have been generated in the backup directories"
else
    echo "⚠️  Some scripts failed. Please check the output above for details."
fi

echo "=========================================="