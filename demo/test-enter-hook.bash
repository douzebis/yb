# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# Simple test for ENTER hook
# Run with: bin/prompt demo/test-enter-hook.bash

# Single-line command
echo "Test 1: Single line"

# Multi-line command
echo "Test 2: Multi-line \
with continuation"

# Another multi-line
printf "Test 3: Printf \
multi-line"

echo "Done!"
