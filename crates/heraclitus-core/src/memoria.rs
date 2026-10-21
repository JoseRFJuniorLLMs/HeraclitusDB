//! Estimativas de memória residente dos contentores da `std`, para os índices
//! reportarem os seus bytes sem um alocador que os atribua.
//!
//! Contam a ALOCAÇÃO pela capacidade, não pelo comprimento: um `Vec` com
//! capacidade 1 024 e 3 elementos ocupa 1 024 posições. Não contam a
//! fragmentação nem a sobrecarga do alocador, que o RSS inclui. A calibração
//! contra um `GlobalAlloc` contador está em
//! `crates/heraclitus-server/tests/memoria_por_indice.rs`.

use std::mem::size_of;

/// Bytes de um `Vec<T>` com esta capacidade.
pub fn de_vec<T>(capacidade: usize) -> u64 {
    capacidade as u64 * size_of::<T>() as u64
}

/// Bytes da tabela de um `HashMap<K, V>`/`HashSet` (hashbrown) com esta
/// `capacity()`: `buckets × (entrada + 1 byte de controlo)`, com os buckets na
/// potência de 2 que dá a carga máxima de 7/8.
pub fn de_hashmap<K, V>(capacidade: usize) -> u64 {
    if capacidade == 0 {
        return 0;
    }
    let buckets = if capacidade < 8 {
        (capacidade + 1).next_power_of_two()
    } else {
        (capacidade * 8 / 7).next_power_of_two()
    };
    buckets as u64 * (size_of::<(K, V)>() as u64 + 1)
}

/// Bytes de um `BTreeMap<K, V>`/`BTreeSet<K>` com `n` entradas: nós com até 11
/// entradas, cheios a ~2/3 em média, mais o cabeçalho de cada nó.
pub fn de_btree<K, V>(n: usize) -> u64 {
    if n == 0 {
        return 0;
    }
    let entrada = (size_of::<K>() + size_of::<V>()) as u64;
    let nos = (n as u64).div_ceil(7);
    n as u64 * entrada * 3 / 2 + nos * 16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashmap_cresce_em_potencias_de_dois_com_a_carga_maxima() {
        assert_eq!(de_hashmap::<u64, u64>(0), 0);
        // 3 elementos → 4 buckets de 16 + 1 bytes.
        assert_eq!(de_hashmap::<u64, u64>(3), 4 * 17);
        // 14 cabem em 16 buckets (16 × 7/8 = 14).
        assert_eq!(de_hashmap::<u64, u64>(14), 16 * 17);
    }

    #[test]
    fn vec_e_btree() {
        assert_eq!(de_vec::<u32>(10), 40);
        assert_eq!(de_btree::<u64, ()>(0), 0);
        assert!(de_btree::<u64, ()>(100) > 100 * 8);
    }
}
