# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Mahdi Akil
"""Append-only Merkle tree as in RFC 9162 (Certificate Transparency v2), section 2.1.

`MerkleTree` keeps the leaves and caches subtree hashes, so roots and proofs
cost O(log n) amortised. The verify functions are pure and follow the RFC's
algorithms step by step.
"""

from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


EMPTY_ROOT = hashlib.sha256(b"").digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


class MerkleTree:
    def __init__(self) -> None:
        self.leaves: list[bytes] = []  # leaf hashes
        self._cache: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, data: bytes) -> int:
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def truncate(self, size: int) -> None:
        """Drop leaves past `size` (used to undo a failed sync); cached subtrees beyond it go too."""
        del self.leaves[size:]
        self._cache = {k: v for k, v in self._cache.items() if k[1] <= size}

    def _mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.leaves[lo]
        key = (lo, hi)
        h = self._cache.get(key)
        if h is None:
            k = _split(n)
            h = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
            self._cache[key] = h
        return h

    def root(self, size: int | None = None) -> bytes:
        size = len(self.leaves) if size is None else size
        if size > len(self.leaves):
            raise ValueError("size beyond tree")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("bad index or size")
        return self._path(index, 0, size)

    def _path(self, m: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return self._path(m, lo, lo + k) + [self._mth(lo + k, hi)]
        return self._path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = len(self.leaves) if second is None else second
        if not 0 <= first <= second <= len(self.leaves):
            raise ValueError("bad sizes")
        if first == 0 or first == second:
            return []
        return self._subproof(first, 0, second, True)

    def _subproof(self, m: int, lo: int, hi: int, b: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            return [] if b else [self._mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return self._subproof(m, lo, lo + k, b) + [self._mth(lo + k, hi)]
        return self._subproof(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162, 2.1.3.2. `leaf` is the leaf *hash*."""
    if index >= size or index < 0:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162, 2.1.4.2. True iff the tree of size `second` extends the one of size `first`."""
    if first < 0 or first > second:
        return False
    if first == 0:
        return proof == []
    if first == second:
        return proof == [] and first_root == second_root
    if first & (first - 1) == 0:  # exact power of two
        proof = [first_root] + list(proof)
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
