# Test file for bin/prompt multi-line handling
# Run with: bin/prompt demo/test-multiline.bash

# Single-line command (should work as before)
echo "Single line test"

# Multi-line command with backslash continuation
echo "Multi-line test: \
this should work on one line"

# Another multi-line example
cat <<EOF
This is a heredoc
It should work correctly
EOF

# Complex multi-line
for i in 1 2 3; do \
  echo "Item $i"; \
done

# End of test
echo "All tests complete"
