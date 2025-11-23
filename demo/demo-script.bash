# ============================================================================
# yb Demo Script - Secure Blob Storage on YubiKey
# ============================================================================
# Run this with: bin/prompt demo/demo-script.bash
#
# Prerequisites:
# - YubiKey inserted
# - Default PIN (123456) or change commands accordingly
# - Default management key or specify with --key
# ============================================================================

# === SETUP ===================================================================

# Check YubiKey is detected
ykman list

# Auto-detect YubiKey serial number
SERIAL=$(ykman list | sed 's/^.*: //' | head -1)
echo "Detected YubiKey serial: $SERIAL"

# === INITIAL PIN DEMONSTRATION ===============================================

# First, demonstrate manual PIN entry (user enters PIN to see how it works)
echo "Demo 1: Manual PIN entry - you'll be prompted to enter your PIN"
echo "My first secret" | yb --serial $SERIAL store --encrypted demo-secret-1

# Show that we can fetch it (another manual PIN prompt)
echo "Demo 2: Fetching encrypted data - you'll be prompted again"
yb --serial $SERIAL fetch demo-secret-1

# === PIN MANAGEMENT ==========================================================

# Now store PIN in variable for rest of demo (more convenient)
echo ""
echo "For the rest of this demo, we'll store the PIN in a variable."
read -s -p "Enter your YubiKey PIN: " PIN
echo ""
echo "PIN stored in \$PIN variable. We'll use --pin flag from now on."

# === INITIAL SETUP ===========================================================

# Format the YubiKey for blob storage (uses default object count: 12)
# This initializes PIV objects and generates an ECC P-256 encryption key
yb --serial $SERIAL --pin $PIN format --generate

# Verify the store was initialized correctly
yb --serial $SERIAL fsck | head -20

# === STORING DATA ============================================================

# Store encrypted data (requires PIN to fetch)
echo "My SSH passphrase is: correct-horse-battery-staple" | yb --serial $SERIAL --pin $PIN store --encrypted ssh-passphrase

# Store unencrypted data (no PIN needed to fetch)
echo "https://github.com/douzebis/yb" | yb --serial $SERIAL --pin $PIN store --unencrypted github-url

# Store data from a file
echo "Production API key: sk_live_abc123xyz789" > /tmp/api-key.txt
yb --serial $SERIAL --pin $PIN store --encrypted --input /tmp/api-key.txt api-key

# Store a larger blob (configuration file) - create file first, then store
cat > /tmp/app-config.json <<'EOF'
{
  "database": {
    "host": "prod-db.example.com",
    "port": 5432,
    "ssl": true
  },
  "api": {
    "endpoint": "https://api.example.com/v2",
    "timeout": 30
  }
}
EOF
yb --serial $SERIAL --pin $PIN store --encrypted --input /tmp/app-config.json db-config

# === LISTING BLOBS ===========================================================

# List all stored blobs
yb --serial $SERIAL ls

# Show the format:
# Columns: Encryption | Chunks | Size | Modified | Name
# - : encrypted, U : unencrypted

# === RETRIEVING DATA =========================================================

# Fetch unencrypted data (no PIN required)
yb --serial $SERIAL fetch github-url

# Fetch encrypted data with PIN provided via flag
yb --serial $SERIAL --pin $PIN fetch ssh-passphrase

# Fetch to a file
yb --serial $SERIAL --pin $PIN fetch db-config > /tmp/restored-config.json
cat /tmp/restored-config.json

# Fetch API key
yb --serial $SERIAL --pin $PIN fetch api-key

# === MANAGING BLOBS ==========================================================

# Check store health
yb --serial $SERIAL fsck | grep -E "(yblob_magic|object_count|store_age|blob_name)"

# Remove a blob
yb --serial $SERIAL --pin $PIN rm api-key

# Verify it's gone
yb --serial $SERIAL ls

# === ADVANCED FEATURES =======================================================

# Test encryption vs unencrypted performance
time echo "test data encrypted" | yb --serial $SERIAL --pin $PIN store --encrypted perf-enc
time echo "test data unencrypted" | yb --serial $SERIAL --pin $PIN store --unencrypted perf-unenc

# === PRACTICAL EXAMPLES ======================================================

# Example 1: Quick password storage and retrieval (clipboard copy if xclip available)
echo "MySecurePassword123!" | yb --serial $SERIAL --pin $PIN store --encrypted temp-pwd
yb --serial $SERIAL --pin $PIN fetch temp-pwd | tr -d '\n' | xclip -selection clipboard 2>/dev/null || echo "[Password would be copied to clipboard if xclip is installed]"

# Example 2: Multi-device scenario (if you have multiple YubiKeys)
# yb --serial 12345678 --pin $PIN ls  # Device 1
# yb --serial 87654321 --pin $PIN ls  # Device 2

# === SELF-TEST ===============================================================

# Run comprehensive self-test (WARNING: This reformats the YubiKey!)
# Uncomment to run:
# yb --serial $SERIAL --pin $PIN self-test -n 50

# === CLEANUP =================================================================

# Remove all test blobs
yb --serial $SERIAL ls | awk '{print $5}' | tail -n +2 | while read blob; do echo "Removing: $blob"; yb --serial $SERIAL --pin $PIN rm "$blob" 2>/dev/null || true; done

# Final state
echo "Final YubiKey state:"
yb --serial $SERIAL ls

# Clean up temp files
rm -f /tmp/api-key.txt /tmp/app-config.json /tmp/restored-config.json

# Unset PIN variable for security
unset PIN

# === END OF DEMO =============================================================
# For more information, see:
# - USER_GUIDE.md - Complete user documentation
# - DESIGN.md - Technical design details
# - https://github.com/douzebis/yb
# ============================================================================
