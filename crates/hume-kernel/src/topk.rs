//! Top-K por heap parcial: mantém os `K` maiores em O(N log K) (SPEC-0039 §6).
//!
//! Evita a ordenação total (`Sort-Breaking`) de `ORDER BY … LIMIT K`: um
//! min-heap de tamanho `K` rastreia apenas os maiores elementos vistos.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Os `k` maiores valores de `data`, em ordem decrescente. O(N log K).
pub fn top_k_u64(data: &[u64], k: usize) -> Vec<u64> {
    if k == 0 {
        return Vec::new();
    }
    // Min-heap de tamanho ≤ k: o topo é o menor dos maiores.
    let mut heap: BinaryHeap<Reverse<u64>> = BinaryHeap::with_capacity(k + 1);
    for &v in data {
        if heap.len() < k {
            heap.push(Reverse(v));
        } else if let Some(&Reverse(min)) = heap.peek() {
            if v > min {
                heap.pop();
                heap.push(Reverse(v));
            }
        }
    }
    let mut out: Vec<u64> = heap.into_iter().map(|Reverse(v)| v).collect();
    out.sort_unstable_by(|a, b| b.cmp(a));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brute_top_k(data: &[u64], k: usize) -> Vec<u64> {
        let mut v = data.to_vec();
        v.sort_unstable_by(|a, b| b.cmp(a));
        v.truncate(k);
        v
    }

    #[test]
    fn matches_full_sort() {
        let data: Vec<u64> = (0..1000u64).map(|i| (i.wrapping_mul(2654435761)) % 9973).collect();
        for k in [0usize, 1, 5, 50, 1000, 2000] {
            assert_eq!(top_k_u64(&data, k), brute_top_k(&data, k), "k={k}");
        }
    }

    #[test]
    fn handles_duplicates_and_small_input() {
        assert_eq!(top_k_u64(&[5, 5, 5, 1], 2), vec![5, 5]);
        assert_eq!(top_k_u64(&[], 3), Vec::<u64>::new());
        assert_eq!(top_k_u64(&[7], 3), vec![7]);
    }
}
