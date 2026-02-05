#!/bin/bash
# Validation script for Akamai MISP module
# Run this before deploying to MISP

set -e

echo "=========================================="
echo "Akamai MISP Module Validation"
echo "=========================================="
echo ""

# Check Python version
echo "1. Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Python version: $python_version"

required_version="3.6"
if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "   ✗ ERROR: Python 3.6+ required"
    exit 1
fi
echo "   ✓ Python version OK"
echo ""

# Check if dependencies are installed
echo "2. Checking dependencies..."
dependencies=("requests" "pymisp" "akamai.edgegrid")

for dep in "${dependencies[@]}"; do
    if python3 -c "import ${dep//./_}" 2>/dev/null; then
        version=$(python3 -c "import ${dep//./_}; print(getattr(${dep//./_}, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
        echo "   ✓ $dep ($version)"
    else
        echo "   ✗ $dep not installed"
        echo "   Install with: pip install -r requirements.txt"
        exit 1
    fi
done
echo ""

# Run syntax check
echo "3. Checking Python syntax..."
if python3 -m py_compile akamai_ioc.py 2>/dev/null; then
    echo "   ✓ Syntax OK"
else
    echo "   ✗ Syntax errors found"
    exit 1
fi
echo ""

# Run validation tests
echo "4. Running validation tests..."
if [ -f "tests/test_validation.py" ]; then
    if python3 tests/test_validation.py; then
        echo "   ✓ All validation tests passed"
    else
        echo "   ✗ Validation tests failed"
        exit 1
    fi
else
    echo "   ⚠ Test file not found, skipping"
fi
echo ""

# Check for security issues with bandit (if installed)
echo "5. Security scan (optional)..."
if command -v bandit &> /dev/null; then
    if bandit -r akamai_ioc.py -f txt 2>/dev/null; then
        echo "   ✓ No security issues found"
    else
        echo "   ⚠ Security issues detected (review manually)"
    fi
else
    echo "   ⚠ Bandit not installed, skipping"
    echo "   Install with: pip install bandit"
fi
echo ""

# Summary
echo "=========================================="
echo "✓ Validation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Review the validation results above"
echo "2. Copy module to MISP: cp akamai_ioc.py \${MISP_MODULES_BASE}/site-packages/misp_modules/modules/expansion/"
echo "3. Reload MISP modules"
echo "4. Configure API credentials in MISP settings"
echo "5. Test with a sample domain/hostname"
echo ""
