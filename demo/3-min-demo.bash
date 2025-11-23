# ============================================================================
# yb - 3-Minute Quick Demo
# ============================================================================
# Run this with: bin/prompt demo/3-min-demo.bash
#
# Prerequisites:
# - Factory-reset YubiKey inserted (default PIN: 123456, PUK: 12345678)
# - This demo will change credentials to non-defaults
# ============================================================================

# === STEP 1: DETECT YUBIKEY =================================================

# Check which YubiKey is connected
ykman list

# Auto-detect serial number
SERIAL=$(ykman list | grep -o 'Serial: [0-9]*' | cut -d' ' -f2)
echo "Using YubiKey serial: $SERIAL"

# === STEP 2: CHANGE DEFAULT CREDENTIALS =====================================

# Change PIN from factory default (123456) to a new PIN (654321)
echo "Changing PIN from default 123456 to 654321..."
ykman --device $SERIAL piv access change-pin --pin 123456 --new-pin 654321

# Change PUK from factory default (12345678) to a new PUK (87654321)
echo "Changing PUK from default 12345678 to 87654321..."
ykman --device $SERIAL piv access change-puk --puk 12345678 --new-puk 87654321

# Enable PIN-protected management key mode (generates random AES-192 key)
# This stores the management key on the YubiKey, accessible only with PIN
echo "Enabling PIN-protected management key mode..."
ykman --device $SERIAL piv access change-management-key --generate --protect --pin 654321

# Verify the new configuration
echo "Current PIV configuration:"
ykman --device $SERIAL piv info

# === STEP 3: FORMAT YUBIKEY FOR BLOB STORAGE ================================

# Initialize yb store with encryption key generation
# With PIN-protected mode, we only need --pin (no --key needed!)
yb --serial $SERIAL --pin 654321 format --generate

# === STEP 4: STORE A SECRET ==================================================

# Store an encrypted secret (password, API key, etc.)
echo "my-super-secret-password-123" | yb --serial $SERIAL --pin 654321 store --encrypted my-secret

# Verify it was stored
echo "Stored blobs:"
yb --serial $SERIAL ls

# === STEP 5: RETRIEVE THE SECRET =============================================

# Fetch the encrypted secret (requires PIN for decryption)
echo "Retrieving secret..."
yb --serial $SERIAL --pin 654321 fetch my-secret

# === DEMO COMPLETE ===========================================================

echo ""
echo "✓ Demo complete!"
echo ""
echo "What we did:"
echo "  1. Changed PIN from 123456 → 654321"
echo "  2. Changed PUK from 12345678 → 87654321"
echo "  3. Enabled PIN-protected management key mode"
echo "  4. Initialized yb store with encryption"
echo "  5. Stored and retrieved an encrypted secret"
echo ""
echo "Notice: With PIN-protected mode, you only need --pin for all operations!"
echo "        No need to remember or store a 48-character management key."
echo ""
echo "Next steps:"
echo "  - Store more secrets: yb --serial $SERIAL --pin 654321 store --encrypted <name>"
echo "  - List all blobs:     yb --serial $SERIAL ls"
echo "  - Remove a blob:      yb --serial $SERIAL --pin 654321 rm <name>"
echo "  - See USER_GUIDE.md for complete documentation"

# ============================================================================
# END OF 3-MINUTE DEMO
# ============================================================================
