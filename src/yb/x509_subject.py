# Allowed RDN attribute types in Yubico/OpenSSL style
VALID_ATTRS = {'CN', 'O', 'OU', 'C', 'L', 'ST', 'emailAddress'}

# Special characters that must be escaped if present in values
SPECIAL_CHARS = set(',=+<>#;"\\')

# Note: verifies subject follows the legacy syntax (e.g. yubico-piv-tool)
def verify_x509_subject(subject: str) -> list:
    """
    Validates a subject string in Yubico/OpenSSL slash-delimited format.
    Returns list of (key, value) tuples if valid.
    Raises ValueError if invalid.
    """
    if not subject.startswith('/'):
        raise ValueError("Subject must start with '/'")
    subject = subject[:-1]

    parts = subject.strip().split('/')[1:]  # Skip the first empty part

    rdn_list = []
    for part in parts:
        if '=' not in part:
            raise ValueError(f"Missing '=' in RDN: {part}")
        key, value = part.split('=', 1)

        if key not in VALID_ATTRS:
            raise ValueError(f"Invalid RDN attribute: {key}")

        # Check for unescaped special characters
        i = 0
        while i < len(value):
            if value[i] == '\\':
                i += 2  # skip escaped char
            elif value[i] in SPECIAL_CHARS:
                raise ValueError(f"Unescaped special character '{value[i]}' in value for {key}")
            else:
                i += 1

        # Leading/trailing spaces must be escaped
        if (value.startswith(' ') or value.endswith(' ') or value.startswith('#')) and not value.startswith('\\'):
            raise ValueError(f"Leading/trailing spaces or '#' must be escaped in value: {value}")

        rdn_list.append((key, value))

    return rdn_list


## Example usage
#try:
#    subject_str = "/CN=YubiKey ECCP256/O=Example Corp/C=US"
#    parsed = verify_x509_subject(subject_str)
#    print("Valid subject:", parsed)
#except ValueError as e:
#    print("Invalid subject:", e)
