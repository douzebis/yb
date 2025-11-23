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

# Auto-detect serial number for credential changes
SERIAL=$(ykman list | grep -o 'Serial: [0-9]*' | cut -d' ' -f2)

# === STEP 2: CHANGE DEFAULT CREDENTIALS =====================================

# Change PIN from factory default (123456) to a new PIN (654321)
ykman --device $SERIAL piv access change-pin --pin 123456 --new-pin 654321

# Change PUK from factory default (12345678) to a new PUK (87654321)
ykman --device $SERIAL piv access change-puk --puk 12345678 --new-puk 87654321

# Enable PIN-protected management key mode (generates random AES-192 key)
# This stores the management key on-device, accessible only with PIN
# With PIN-protected mode, you only need PIN for write operations!
ykman --device $SERIAL piv access change-management-key --generate --protect --pin 654321

# Verify the new configuration (notice "protected by PIN")
ykman --device $SERIAL piv info

# === STEP 3: FORMAT YUBIKEY FOR BLOB STORAGE ================================

# Initialize yb store with encryption key generation
# From now on, you'll enter the PIN (654321) when prompted
yb format --generate

# === STEP 4: STORE A SECRET ==================================================

# Store an encrypted secret (you'll be prompted for PIN)
echo "my-super-secret-password-123" | yb store --encrypted my-secret

# List stored blobs (no credentials needed for read-only operations)
yb ls

# === STEP 5: RETRIEVE THE SECRET =============================================

# Fetch the encrypted secret (you'll be prompted for PIN for decryption)
yb fetch my-secret

# ============================================================================
# DEMO COMPLETE
# ============================================================================
# What we did:
#   1. Changed PIN from 123456 → 654321
#   2. Changed PUK from 12345678 → 87654321
#   3. Enabled PIN-protected management key mode
#   4. Initialized yb store with encryption
#   5. Stored and retrieved an encrypted secret
#
# Notice: With PIN-protected mode, you only need PIN for all operations!
#         No need to remember or store a 48-character management key.
#
# Next steps:
#   - Store more secrets:  yb store --encrypted <name>
#   - List all blobs:      yb ls
#   - Filter by pattern:   yb ls "*.txt"
#   - Remove a blob:       yb rm <name>
#   - See USER_GUIDE.md for complete documentation
# ============================================================================
