//! RFC 6962-style Merkle tree: inclusion and consistency proofs.
//!
//! Domain-separated hashing (leaf prefix `0x00`, node prefix `0x01`) prevents
//! second-preimage attacks across leaves and internal nodes. This is the proof
//! machinery that lets anyone verify the audit log is append-only and that a given
//! event is included — without trusting the operator.

use secgit_crypto::primitives::sha256;

pub type Hash = [u8; 32];

pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256(&buf)
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(0x01);
    buf.extend_from_slice(l);
    buf.extend_from_slice(r);
    sha256(&buf)
}

/// Largest power of two strictly less than `n` (n >= 2).
fn largest_pow2_lt(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash (root) of `leaves` (already leaf-hashed values).
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaves[0],
        n => {
            let k = largest_pow2_lt(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Inclusion proof for leaf index `m` in a tree of the given `leaves`.
pub fn inclusion_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m < n);
    if n == 1 {
        return vec![];
    }
    let k = largest_pow2_lt(n);
    if m < k {
        let mut p = inclusion_proof(&leaves[..k], m);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_proof(&leaves[k..], m - k);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof: recompute the root from `leaf` at index `m` in a tree of
/// size `n` and compare to `expected_root`.
///
/// This is the canonical RFC 6962 verification (the inverse of [`inclusion_proof`],
/// which emits siblings bottom-up). The proof splits into `inner` siblings consumed
/// against the bits of `m`, followed by `border` right-edge siblings folded in from the
/// left — matching the recursive prover for non-power-of-two tree sizes.
pub fn verify_inclusion(
    leaf: &Hash,
    m: usize,
    n: usize,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    if m >= n {
        return false;
    }
    let inner = inner_proof_size(m, n);
    let border = (m >> inner).count_ones() as usize;
    if proof.len() != inner + border {
        return false;
    }
    let mut acc = *leaf;
    // Inner siblings: deepest first; bit i of m says whether we are the left child.
    for (i, p) in proof[..inner].iter().enumerate() {
        if (m >> i) & 1 == 0 {
            acc = node_hash(&acc, p);
        } else {
            acc = node_hash(p, &acc);
        }
    }
    // Border siblings live on the right edge of the tree; we are always their right child.
    for p in &proof[inner..] {
        acc = node_hash(p, &acc);
    }
    &acc == expected_root
}

/// Number of inner (non-border) proof nodes for `index` in a tree of `size`.
fn inner_proof_size(index: usize, size: usize) -> usize {
    let x = index ^ (size - 1);
    (usize::BITS - x.leading_zeros()) as usize
}

/// Consistency proof between a prefix tree of size `m` and the full tree (`size n`).
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m <= n && m > 0);
    subproof(m, leaves, true)
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        if b {
            return vec![];
        }
        return vec![root(leaves)];
    }
    let k = largest_pow2_lt(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// Verify a consistency proof between `(m, root_m)` and `(n, root_n)`.
pub fn verify_consistency(
    m: usize,
    n: usize,
    proof: &[Hash],
    root_m: &Hash,
    root_n: &Hash,
) -> bool {
    if m == 0 || m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && root_m == root_n;
    }

    let mut node = m - 1;
    let mut last = n - 1;
    while node % 2 == 1 {
        node /= 2;
        last /= 2;
    }

    let mut it = proof.iter();
    let (mut fr, mut sr);
    if node > 0 {
        let Some(first) = it.next() else { return false };
        fr = *first;
        sr = *first;
    } else {
        fr = *root_m;
        sr = *root_m;
    }

    while node > 0 {
        if node % 2 == 1 {
            let Some(p) = it.next() else { return false };
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
        } else if node < last {
            let Some(p) = it.next() else { return false };
            sr = node_hash(&sr, p);
        }
        node /= 2;
        last /= 2;
    }

    while last > 0 {
        let Some(p) = it.next() else { return false };
        sr = node_hash(&sr, p);
        last /= 2;
    }

    it.next().is_none() && &fr == root_m && &sr == root_n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(format!("entry-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn inclusion_proofs_verify_for_all_indices() {
        for n in 1..=33 {
            let ls = leaves(n);
            let r = root(&ls);
            for m in 0..n {
                let proof = inclusion_proof(&ls, m);
                assert!(verify_inclusion(&ls[m], m, n, &proof, &r), "n={n} m={m}");
            }
        }
    }

    #[test]
    fn tampered_inclusion_fails() {
        let ls = leaves(8);
        let r = root(&ls);
        let proof = inclusion_proof(&ls, 3);
        let bad = leaf_hash(b"forged");
        assert!(!verify_inclusion(&bad, 3, 8, &proof, &r));
    }

    #[test]
    fn consistency_proofs_verify() {
        for n in 2..=33 {
            let full = leaves(n);
            let root_n = root(&full);
            for m in 1..n {
                let root_m = root(&full[..m]);
                let proof = consistency_proof(&full, m);
                assert!(
                    verify_consistency(m, n, &proof, &root_m, &root_n),
                    "n={n} m={m}"
                );
            }
        }
    }

    #[test]
    fn consistency_rejects_forked_history() {
        let full = leaves(8);
        let root_n = root(&full);
        // A different "old root" (history was rewritten) must not verify.
        let mut forged = leaves(4);
        forged[0] = leaf_hash(b"rewritten");
        let bad_root_m = root(&forged);
        let proof = consistency_proof(&full, 4);
        assert!(!verify_consistency(4, 8, &proof, &bad_root_m, &root_n));
    }

    // ---- Named non-power-of-two regressions (guard the previously-fixed border bug) ----
    // The recursive prover emits "border" siblings on the right edge that must be folded in
    // as a *right* child; an off-by-one here silently breaks verification for sizes that are
    // not a power of two. These pin n = 3,5,6,7 explicitly so a regression is named, not
    // just lost inside a range loop. CI(mock).

    #[test]
    fn inclusion_named_non_pow2_sizes() {
        for &n in &[3usize, 5, 6, 7] {
            let ls = leaves(n);
            let r = root(&ls);
            for m in 0..n {
                let proof = inclusion_proof(&ls, m);
                assert!(
                    verify_inclusion(&ls[m], m, n, &proof, &r),
                    "valid inclusion must verify (n={n} m={m})"
                );
                // A single corrupted sibling in the proof must break verification.
                if !proof.is_empty() {
                    let mut bad = proof.clone();
                    bad[0][0] ^= 0xFF;
                    assert!(
                        !verify_inclusion(&ls[m], m, n, &bad, &r),
                        "corrupted-sibling proof must fail (n={n} m={m})"
                    );
                }
            }
        }
    }

    #[test]
    fn inclusion_wrong_tree_size_is_rejected() {
        // A proof built for size n must not verify when presented with a different n: the
        // inner/border split depends on n, so a mismatched size is a tamper signal.
        let ls = leaves(6);
        let r = root(&ls);
        let proof = inclusion_proof(&ls, 4);
        assert!(verify_inclusion(&ls[4], 4, 6, &proof, &r));
        assert!(!verify_inclusion(&ls[4], 4, 7, &proof, &r));
        assert!(!verify_inclusion(&ls[4], 4, 5, &proof, &r));
    }

    #[test]
    fn consistency_named_non_pow2_sizes() {
        for &n in &[3usize, 5, 6, 7] {
            let full = leaves(n);
            let root_n = root(&full);
            for m in 1..n {
                let root_m = root(&full[..m]);
                let proof = consistency_proof(&full, m);
                assert!(
                    verify_consistency(m, n, &proof, &root_m, &root_n),
                    "valid consistency must verify (n={n} m={m})"
                );
                // Corrupting any proof node must break consistency verification.
                if !proof.is_empty() {
                    let mut bad = proof.clone();
                    bad[0][0] ^= 0xFF;
                    assert!(
                        !verify_consistency(m, n, &bad, &root_m, &root_n),
                        "corrupted consistency proof must fail (n={n} m={m})"
                    );
                }
            }
        }
    }
}
