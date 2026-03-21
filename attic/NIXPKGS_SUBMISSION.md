<!--
SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# Nixpkgs Submission Guide for yb

This guide walks through the complete process of submitting yb to nixpkgs.

## Overview

Since you're already a nixpkgs maintainer (douzebis), you only need **one pull request** to add the yb package.

The process is simplified to:
1. **Step 1**: Create v0.1.0 release on GitHub
2. **Step 2**: Add yb package to nixpkgs
3. **Step 3**: Test thoroughly
4. **Step 4**: Submit PR

---

## Step 1: Create v0.1.0 Release

### 1.1 Prepare Release in yb Repository

```bash
cd /home/experiment/code/yb

# Ensure everything is committed
git status

# Ensure you're on main branch and up to date
git checkout main
git pull origin main
```

### 1.2 Create and Push Release Tag

```bash
# Create annotated tag
git tag -a v0.1.0 -m "Release v0.1.0 - Initial nixpkgs submission

Features:
- Hardware-backed encryption using YubiKey PIV
- ~36 KB storage capacity
- PIN-protected management key mode
- Multi-device support with interactive selection
- Shell auto-completion for blob names
- Glob pattern filtering for blob listing
"

# Push tag to GitHub
git push origin v0.1.0
```

### 1.3 Create GitHub Release

1. Go to: https://github.com/douzebis/yb/releases/new
2. Select tag: `v0.1.0`
3. Release title: `v0.1.0 - Initial Release`
4. Description: Copy the tag message above
5. Click "Publish release"

### 1.4 Calculate Source Hash

```bash
# Calculate the hash for the source tarball
nix-prefetch-url --unpack https://github.com/douzebis/yb/archive/v0.1.0.tar.gz
```

This will output a hash like: `sha256-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890...`

**Save this hash** - you'll need it for package.nix in Step 2.

---

## Step 2: Add yb Package to nixpkgs

### 2.1 Fork and Clone nixpkgs (if not already done)

```bash
# Fork nixpkgs on GitHub first: https://github.com/NixOS/nixpkgs/fork

# Clone your fork
git clone https://github.com/douzebis/nixpkgs.git
cd nixpkgs

# Add upstream remote
git remote add upstream https://github.com/NixOS/nixpkgs.git
```

### 2.2 Update Your nixpkgs Fork

```bash
cd nixpkgs

# Ensure you're on latest master
git checkout master
git pull upstream master

# Create a new branch for the package
git checkout -b add-package-yb
```

### 2.3 Create Package Directory Structure

```bash
# Create the package directory (using pkgs/by-name structure)
mkdir -p pkgs/by-name/yb/yb
```

### 2.4 Copy and Update package.nix

```bash
# Copy the package definition from yb repository
cp /home/experiment/code/yb/doc/package.nix pkgs/by-name/yb/yb/package.nix
```

Now edit `pkgs/by-name/yb/yb/package.nix`:

**Add the hash from Step 1.4:**
```nix
hash = "sha256-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890...";  # Replace with actual hash
```

Note: The maintainer field is already set to `douzebis` in the template.

### 2.5 Test the Package Locally

```bash
cd ~/nixpkgs

# Build the package
nix-build -A yb

# Test that it runs
./result/bin/yb --help
./result/bin/yb format --help
```

### 2.6 Run Package Quality Checks

```bash
cd ~/nixpkgs

# Format check (recommended)
nix fmt pkgs/by-name/yb/yb/package.nix

# Verify Python imports work
nix-build -A yb
```

---

## Step 3: Thorough Testing

Before submitting, test the package thoroughly:

### 3.1 Basic Functionality Tests

```bash
cd ~/nixpkgs

# Ensure the build is complete
nix-build -A yb

# Test all subcommands show help
./result/bin/yb --help
./result/bin/yb format --help
./result/bin/yb store --help
./result/bin/yb fetch --help
./result/bin/yb ls --help
./result/bin/yb rm --help
./result/bin/yb fsck --help

# Test with actual YubiKey (if available)
./result/bin/yb format --generate
echo "test-data" | ./result/bin/yb store --encrypted test-blob
./result/bin/yb ls
./result/bin/yb fetch test-blob
./result/bin/yb rm test-blob
```

### 3.2 Cross-Platform Testing (if possible)

```bash
cd ~/nixpkgs

# Test on different architectures (if available)
nix-build -A yb --argstr system x86_64-linux
nix-build -A yb --argstr system aarch64-linux
```

### 3.3 Check Dependencies

```bash
cd ~/nixpkgs

# Verify runtime dependencies are properly wrapped
# Create a temporary nix-shell with yb from local checkout
nix-shell -E 'with import ./. {}; mkShell { buildInputs = [ yb ]; }' --run "which yubico-piv-tool"
nix-shell -E 'with import ./. {}; mkShell { buildInputs = [ yb ]; }' --run "which pkcs11-tool"
nix-shell -E 'with import ./. {}; mkShell { buildInputs = [ yb ]; }' --run "which openssl"
nix-shell -E 'with import ./. {}; mkShell { buildInputs = [ yb ]; }' --run "which ykman"

# Or simply check the wrapped executable has correct library paths
ldd ./result/bin/.yb-wrapped | grep -i yubico
```

### 3.4 Installation Test

```bash
cd ~/nixpkgs

# Test installation from local nixpkgs
nix-env -f . -iA yb

# Verify it's in PATH
which yb
yb --help

# Clean up
nix-env -e yb
```

---

## Step 4: Submit Pull Request

### 4.1 Commit and Push

```bash
cd nixpkgs

# Add the package file
git add pkgs/by-name/yb/yb/package.nix

# Commit with conventional format
git commit -m "yb: init at 0.1.0"

# Push to your fork
git push origin add-package-yb
```

### 4.2 Create Pull Request

1. Go to: https://github.com/YOUR_GITHUB_USERNAME/nixpkgs/compare
2. Set base repository: `NixOS/nixpkgs`, base: `master`
3. Set head repository: `YOUR_GITHUB_USERNAME/nixpkgs`, compare: `add-package-yb`
4. Create pull request with title: `yb: init at 0.1.0`

### 4.3 Pull Request Description Template

```markdown
## Description

Add `yb` - a CLI tool for securely storing and retrieving binary blobs using YubiKey.

### Package Details

- **Version**: 0.1.0
- **License**: MIT
- **Platforms**: Linux (YubiKey support is best on Linux)
- **Maintainer**: @douzebis

### Features

- Hardware-backed encryption using YubiKey PIV
- ~36 KB storage capacity (expandable to ~48 KB)
- PIN-protected management key mode
- Multi-device support with interactive selection
- Shell auto-completion for blob names
- Glob pattern filtering for blob listing

### Testing

Tested on:
- [x] x86_64-linux
- [ ] aarch64-linux (optional)

#### Build Test
```bash
nix-build '<nixpkgs>' -A yb
```

#### Functionality Test
```bash
nix-shell -p yb --run "yb --help"
```

#### Runtime Dependencies
All required tools are properly wrapped:
- yubico-piv-tool
- pkcs11-tool (from opensc)
- openssl
- yubikey-manager

### Additional Notes

This package uses the new `pkgs/by-name` structure (RFC 140).

Tests are disabled (`doCheck = false`) as they require physical YubiKey hardware.

### Related Links

- Homepage: https://github.com/douzebis/yb
- Release: https://github.com/douzebis/yb/releases/tag/v0.1.0
- Documentation: https://github.com/douzebis/yb#readme
```

### 4.4 Respond to Review Feedback

The nixpkgs maintainers will review your PR. Be prepared to:
- Answer questions about the package
- Make requested changes
- Run additional tests
- Update documentation

Typical turnaround for reviews: 3-7 days

---

## Pre-Submission Checklist

Before submitting the package PR, verify:

### Code Quality
- [ ] Package builds successfully: `nix-build -A yb`
- [ ] No evaluation errors: `nix-instantiate --eval`
- [ ] Format is correct: `nix fmt pkgs/by-name/yb/yb/package.nix`
- [ ] All dependencies are declared
- [ ] makeWrapperArgs correctly sets LD_LIBRARY_PATH

### Metadata
- [ ] Correct version number (0.1.0)
- [ ] Valid license (MIT)
- [ ] Homepage URL is correct
- [ ] Changelog URL points to v0.1.0 release
- [ ] Description is clear and concise
- [ ] longDescription provides additional context
- [ ] Maintainer is set (after maintainer PR merged)
- [ ] mainProgram is set to "yb"
- [ ] Platforms are appropriate (Linux)

### Testing
- [ ] Package installs: `nix-env -iA nixpkgs.yb`
- [ ] Binary is in PATH after install
- [ ] Help text works: `yb --help`
- [ ] All subcommands show help
- [ ] Runtime dependencies are available
- [ ] Python imports work: `python -c 'import yb'`

### Source
- [ ] GitHub release v0.1.0 exists
- [ ] Source hash is correct
- [ ] fetchFromGitHub points to correct repo and tag

### Documentation
- [ ] README.md is clear and helpful
- [ ] USER_GUIDE.md provides complete usage instructions
- [ ] Man page (yb.1) is included

---

## Timeline Estimate

- **Step 1** (Release): 1 hour
- **Step 2** (Package creation): 1-2 hours
- **Step 3** (Testing): 1-2 hours
- **Step 4** (PR submission + review): 3-7 days

**Total estimated time**: ~1 week from start to merge

---

## Common Issues and Solutions

### Issue: Hash Mismatch

If you get a hash mismatch error:

```bash
# Recalculate the hash
nix-prefetch-url --unpack https://github.com/douzebis/yb/archive/v0.1.0.tar.gz

# Update package.nix with the new hash
```

### Issue: Missing Dependencies

If runtime tools are not found:

```bash
# Verify makeWrapperArgs includes all needed paths
# Add to buildInputs if needed
```

### Issue: Python Import Errors

```bash
# Ensure all Python dependencies are in 'dependencies'
# Ensure setuptools/wheel are in 'build-system'
```

### Issue: Build Fails

```bash
# Check the build log
nix-build -A yb 2>&1 | less

# Common fixes:
# - Add missing dependencies to buildInputs
# - Ensure pyproject.toml / setup.py is correct
# - Check that src points to correct tag
```

---

## After Merge

Once your PR is merged:

1. **Announcement**: Consider announcing on social media, forums, etc.
2. **Documentation**: Update yb README to mention nixpkgs availability
3. **Maintenance**: Watch for issues reported by nixpkgs users
4. **Updates**: When releasing new versions, submit update PRs to nixpkgs

To update the package later:

```bash
# Same process but commit message is:
git commit -m "yb: 0.1.0 -> 0.2.0"
```

---

## Resources

- **Nixpkgs Manual**: https://nixos.org/manual/nixpkgs/stable/
- **Contributing Guide**: https://github.com/NixOS/nixpkgs/blob/master/CONTRIBUTING.md
- **Package Submission**: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md
- **RFC 140 (by-name)**: https://github.com/NixOS/rfcs/pull/140
- **Python Packages**: https://nixos.org/manual/nixpkgs/stable/#python
- **Example PR**: https://github.com/NixOS/nixpkgs/pull/409224

---

## Quick Reference Commands

```bash
# Find GitHub ID
curl https://api.github.com/users/douzebis | jq .id

# Calculate source hash
nix-prefetch-url --unpack https://github.com/douzebis/yb/archive/v0.1.0.tar.gz

# Build package
nix-build -A yb

# Test package
nix-shell -p yb --run "yb --help"

# Format package file
nix fmt pkgs/by-name/yb/yb/package.nix

# Install package
nix-env -iA nixpkgs.yb
```
