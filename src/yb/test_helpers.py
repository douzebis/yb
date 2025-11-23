#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Test helpers for Store testing.

Shared utilities for both unit tests and self-test functionality.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import Enum


# === TOY FILESYSTEM (GROUND TRUTH) ============================================

class ToyFilesystem:
    """
    Simple in-memory filesystem to track expected state.

    Maps blob_name -> (payload, modification_time)
    """

    def __init__(self):
        self.files: dict[str, tuple[bytes, int]] = {}

    def store(self, name: str, payload: bytes, mtime: int) -> None:
        """Store or update a file."""
        self.files[name] = (payload, mtime)

    def fetch(self, name: str) -> tuple[bytes, int] | None:
        """Fetch a file. Returns None if not found."""
        return self.files.get(name)

    def remove(self, name: str) -> bool:
        """Remove a file. Returns True if removed, False if not found."""
        if name in self.files:
            del self.files[name]
            return True
        return False

    def list(self) -> list[str]:
        """List all file names."""
        return sorted(self.files.keys())

    def __repr__(self) -> str:
        return f"ToyFilesystem({len(self.files)} files: {list(self.files.keys())})"


# === OPERATION TYPES ==========================================================

class OpType(Enum):
    """Types of operations to test."""
    STORE = "store"
    FETCH = "fetch"
    REMOVE = "remove"
    LIST = "list"


@dataclass
class Operation:
    """Represents a single test operation."""
    op_type: OpType
    name: str
    payload: bytes = b''
    encrypted: bool = False  # For self-test: track if operation should use encryption

    def __repr__(self) -> str:
        enc_marker = " [encrypted]" if self.encrypted else ""
        if self.op_type == OpType.STORE:
            return f"STORE({self.name!r}, {len(self.payload)} bytes{enc_marker})"
        else:
            return f"{self.op_type.value.upper()}({self.name!r})"


# === OPERATION GENERATOR ======================================================

class OperationGenerator:
    """Generates pseudo-random operations for testing."""

    def __init__(self, seed: int = 42, max_capacity: int = 50):
        """
        Initialize generator with a fixed seed for reproducibility.

        Args:
            seed: Random seed for deterministic test runs
            max_capacity: Maximum number of files the store can hold
        """
        self.rng = random.Random(seed)
        self.max_capacity = max_capacity
        self.name_pool = [
            "config", "secret", "backup", "key", "cert", "data",
            "log", "cache", "index", "metadata", "state", "info",
            "settings", "profile", "session", "token", "auth", "creds",
            "database", "schema", "archive", "snapshot", "checkpoint",
        ]
        self.existing_files: set[str] = set()

    def generate(self, count: int, encryption_ratio: float = 0.0) -> list[Operation]:
        """
        Generate a sequence of random operations.

        Args:
            count: Number of operations to generate
            encryption_ratio: Ratio of operations that should use encryption (0.0-1.0)

        Returns:
            List of Operation objects
        """
        operations = []

        for _ in range(count):
            # Choose operation type based on current state and capacity
            if not self.existing_files:
                # No files yet, must store
                op_type = OpType.STORE
            elif len(self.existing_files) >= self.max_capacity:
                # At capacity, can't create new files - only update, fetch, remove, or list
                op_type = self.rng.choices(
                    [OpType.STORE, OpType.FETCH, OpType.REMOVE, OpType.LIST],
                    weights=[20, 40, 30, 10],  # More removes to free space
                    k=1
                )[0]
            elif len(self.existing_files) >= self.max_capacity * 0.8:
                # Near capacity, reduce new stores
                op_type = self.rng.choices(
                    [OpType.STORE, OpType.FETCH, OpType.REMOVE, OpType.LIST],
                    weights=[25, 35, 25, 15],
                    k=1
                )[0]
            else:
                # Plenty of space - normal distribution
                op_type = self.rng.choices(
                    [OpType.STORE, OpType.FETCH, OpType.REMOVE, OpType.LIST],
                    weights=[40, 35, 15, 10],
                    k=1
                )[0]

            if op_type == OpType.STORE:
                # Store: use existing name (update) or new name (create)
                at_capacity = len(self.existing_files) >= self.max_capacity

                if at_capacity or (self.existing_files and self.rng.random() < 0.3):
                    # Update existing file (required if at capacity)
                    name = self.rng.choice(list(self.existing_files))
                else:
                    # Create new file
                    name = self.rng.choice(self.name_pool)
                    # Add suffix to avoid collisions
                    if name in self.existing_files:
                        name = f"{name}-{self.rng.randint(1000, 9999)}"

                # Generate random payload
                # Distribution: mostly small (1-1KB), some medium (1-5KB), few large (5-16KB)
                r = self.rng.random()
                if r < 0.7:
                    # 70%: Small blobs (1-1KB)
                    size = self.rng.randint(1, 1024)
                elif r < 0.95:
                    # 25%: Medium blobs (1-5KB)
                    size = self.rng.randint(1024, 5 * 1024)
                else:
                    # 5%: Large blobs (5-16KB)
                    size = self.rng.randint(5 * 1024, 16 * 1024)

                payload = bytes([self.rng.randint(0, 255) for _ in range(size)])

                # Determine if this operation should use encryption
                encrypted = self.rng.random() < encryption_ratio

                operations.append(Operation(OpType.STORE, name, payload, encrypted))
                self.existing_files.add(name)

            elif op_type == OpType.FETCH:
                # Fetch: read existing or non-existent file
                if self.rng.random() < 0.1:
                    # 10% chance to fetch non-existent file
                    name = f"nonexistent-{self.rng.randint(1000, 9999)}"
                else:
                    name = self.rng.choice(list(self.existing_files))

                operations.append(Operation(OpType.FETCH, name))

            elif op_type == OpType.REMOVE:
                # Remove: delete existing or non-existent file
                if self.rng.random() < 0.1:
                    # 10% chance to remove non-existent file
                    name = f"nonexistent-{self.rng.randint(1000, 9999)}"
                else:
                    name = self.rng.choice(list(self.existing_files))

                operations.append(Operation(OpType.REMOVE, name))
                self.existing_files.discard(name)

            elif op_type == OpType.LIST:
                # List: no name needed
                operations.append(Operation(OpType.LIST, ""))

        return operations
