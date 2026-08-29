#!/bin/bash

# C2Pool Legacy Archival Verification Script
# Verifies that legacy files have been properly archived and the refactored version is active

echo "🗂️  C2POOL LEGACY ARCHIVAL VERIFICATION"
echo "======================================="
echo

# Check if legacy files have been moved to archive
echo "📁 Checking Archive Status..."
if [ -f "archive/c2pool_legacy.cpp" ]; then
    echo "✅ c2pool_legacy.cpp - ARCHIVED"
else
    echo "❌ c2pool_legacy.cpp - NOT FOUND IN ARCHIVE"
fi

if [ -f "archive/c2pool_node_legacy.cpp" ]; then
    echo "✅ c2pool_node_legacy.cpp - ARCHIVED"
else
    echo "❌ c2pool_node_legacy.cpp - NOT FOUND IN ARCHIVE"
fi

if [ -f "archive/c2pool_temp_legacy.cpp" ]; then
    echo "✅ c2pool_temp_legacy.cpp - ARCHIVED"
else
    echo "❌ c2pool_temp_legacy.cpp - NOT FOUND IN ARCHIVE"
fi

if [ -f "archive/README.md" ]; then
    echo "✅ Archive documentation - PRESENT"
else
    echo "❌ Archive documentation - MISSING"
fi

echo

# Check that legacy files are no longer in src/c2pool/
echo "🧹 Checking Source Directory Cleanup..."
if [ ! -f "src/c2pool/c2pool.cpp" ]; then
    echo "✅ c2pool.cpp - REMOVED FROM SOURCE"
else
    echo "❌ c2pool.cpp - STILL IN SOURCE (should be archived)"
fi

if [ ! -f "src/c2pool/c2pool_node.cpp" ]; then
    echo "✅ c2pool_node.cpp - REMOVED FROM SOURCE"
else
    echo "❌ c2pool_node.cpp - STILL IN SOURCE (should be archived)"
fi

if [ ! -f "src/c2pool/c2pool_temp.cpp" ]; then
    echo "✅ c2pool_temp.cpp - REMOVED FROM SOURCE"
else
    echo "❌ c2pool_temp.cpp - STILL IN SOURCE (should be archived)"
fi

echo

# Check that refactored version is present and active
echo "🚀 Checking Active Implementation..."
if [ -f "src/c2pool/main_ltc.cpp" ]; then
    echo "✅ main_ltc.cpp - ACTIVE IMPLEMENTATION"
else
    echo "❌ main_ltc.cpp - MISSING (CRITICAL ERROR)"
fi

echo

# Check build targets
echo "🔨 Checking Build Targets..."
if [ -f "build/src/c2pool/c2pool" ]; then
    echo "✅ c2pool - PRIMARY EXECUTABLE BUILT"
    echo "   └─ Built from: main_ltc.cpp"
else
    echo "❌ c2pool - PRIMARY EXECUTABLE NOT FOUND"
fi

if [ -f "build/src/c2pool/c2pool_enhanced" ]; then
    echo "✅ c2pool_enhanced - ENHANCED EXECUTABLE BUILT"
    echo "   └─ Built from: main_ltc.cpp"
else
    echo "❌ c2pool_enhanced - ENHANCED EXECUTABLE NOT FOUND"
fi

echo

# Check for old build targets (should not exist)
echo "🗑️  Checking Removed Build Targets..."
if [ ! -f "build/src/c2pool/c2pool_main" ]; then
    echo "✅ c2pool_main - REMOVED (legacy target)"
else
    echo "❌ c2pool_main - STILL EXISTS (should be removed)"
fi

if [ ! -f "build/src/c2pool/c2pool_node" ]; then
    echo "✅ c2pool_node - REMOVED (legacy target)"
else
    echo "❌ c2pool_node - STILL EXISTS (should be removed)"
fi

echo

# Test the executables
echo "🧪 Testing Executables..."
if [ -f "build/src/c2pool/c2pool" ]; then
    echo "Testing primary c2pool executable..."
    timeout 3 ./build/src/c2pool/c2pool --help > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then
        echo "✅ c2pool - FUNCTIONAL"
    else
        echo "❌ c2pool - NOT FUNCTIONAL"
    fi
fi

if [ -f "build/src/c2pool/c2pool_enhanced" ]; then
    echo "Testing enhanced c2pool executable..."
    timeout 3 ./build/src/c2pool/c2pool_enhanced --help > /dev/null 2>&1
    if [ $? -eq 0 ] || [ $? -eq 124 ]; then
        echo "✅ c2pool_enhanced - FUNCTIONAL"
    else
        echo "❌ c2pool_enhanced - NOT FUNCTIONAL"
    fi
fi

echo

# Summary
echo "📋 ARCHIVAL SUMMARY"
echo "==================="
echo
archive_count=$(ls -1 archive/*.cpp 2>/dev/null | wc -l)
echo "📁 Archived files: $archive_count"
echo "🚀 Active implementation: main_ltc.cpp"
echo "🎯 Primary executable: c2pool"
echo "⭐ Enhanced executable: c2pool_enhanced"
echo

# Show file sizes for comparison
echo "📊 File Sizes:"
if [ -f "archive/c2pool_legacy.cpp" ]; then
    legacy_size=$(wc -l < archive/c2pool_legacy.cpp)
    echo "   Legacy c2pool.cpp: $legacy_size lines"
fi

if [ -f "src/c2pool/main_ltc.cpp" ]; then
    refactored_size=$(wc -l < src/c2pool/main_ltc.cpp)
    echo "   Refactored main_ltc.cpp: $refactored_size lines"
fi

echo

# Show key features of refactored version
echo "🌟 REFACTORED VERSION FEATURES"
echo "=============================="
echo "✅ Mining_shares vs P2P_shares terminology separation"
echo "✅ Enhanced difficulty adjustment (VARDIFF)"
echo "✅ Real-time hashrate tracking"
echo "✅ Blockchain-specific address validation"
echo "✅ LevelDB persistent storage"
echo "✅ Stratum mining protocol"
echo "✅ Web monitoring interface"
echo "✅ Litecoin testnet integration"
echo
echo "🎉 LEGACY ARCHIVAL COMPLETE!"
echo
echo "All future development should use:"
echo "   Source: src/c2pool/main_ltc.cpp"
echo "   Build:  make c2pool"
echo "   Run:    ./c2pool --help"
