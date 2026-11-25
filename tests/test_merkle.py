# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Mahdi Akil
"""Run:  PYTHONPATH=src python3 -m unittest discover -s tests"""

import os
import unittest

from readreceipts.merkle import MerkleTree, verify_consistency, verify_inclusion


class TestMerkle(unittest.TestCase):
    def test_inclusion_and_consistency_for_every_size(self):
        t = MerkleTree()
        for n in range(1, 70):
            t.append(os.urandom(8))
            root = t.root()
            for i in range(n):
                self.assertTrue(verify_inclusion(t.leaves[i], i, n, t.inclusion_proof(i), root))
            for m in range(n + 1):
                self.assertTrue(verify_consistency(m, n, t.root(m), root, t.consistency_proof(m, n)))

    def test_wrong_index_fails(self):
        t = MerkleTree()
        for i in range(9):
            t.append(bytes([i]))
        self.assertFalse(verify_inclusion(t.leaves[0], 1, 9, t.inclusion_proof(0), t.root()))

    def test_rewritten_history_is_inconsistent(self):
        a, b = MerkleTree(), MerkleTree()
        for i in range(10):
            a.append(bytes([i]))
            b.append(bytes([i]) if i != 4 else b"x")
        self.assertFalse(verify_consistency(6, 10, b.root(6), a.root(), a.consistency_proof(6, 10)))

    def test_truncate_undoes_appends(self):
        t = MerkleTree()
        for i in range(5):
            t.append(bytes([i]))
        r5 = t.root()
        t.append(b"extra")
        t.truncate(5)
        self.assertEqual(t.root(), r5)


if __name__ == "__main__":
    unittest.main()
