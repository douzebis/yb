# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

# Test file for heredoc support in bin/prompt
# Run with: bin/prompt demo/test-heredoc.bash

# Simple heredoc
cat <<EOF
This is a heredoc
It should work correctly
EOF

# Heredoc with variable expansion
cat <<EOF
Current directory: $PWD
EOF

# Backslash continuation (should still work)
for i in a b c; do \
  echo "Item: $i"; \
done

# Another heredoc
cat <<'DELIMITER'
This uses a different delimiter
DELIMITER

echo "All tests complete!"
