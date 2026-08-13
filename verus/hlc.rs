use builtin::*;
use builtin_macros::*;

verus! {

pub struct HLCTime {
    pub l: u64,
    pub c: u64,
}

impl HLCTime {
    /// Relação de ordem estrita (<) no HLC
    pub spec fn lt(self, other: HLCTime) -> bool {
        self.l < other.l || (self.l == other.l && self.c < other.c)
    }

    /// Relação de ordem não-estrita (<=) no HLC
    pub spec fn le(self, other: HLCTime) -> bool {
        self.l < other.l || (self.l == other.l && self.c <= other.c)
    }
}

/// Gera um novo timestamp local a partir do tempo físico atual e do timestamp anterior.
/// O Verus provará matematicamente que o novo timestamp é estritamente maior que o anterior (`ensures prev.lt(res)`).
pub fn now(physical_now: u64, prev: HLCTime) -> (res: HLCTime)
    ensures
        prev.lt(res),
        physical_now <= res.l
{
    let new_l = if physical_now > prev.l { physical_now } else { prev.l };
    let new_c = if new_l == prev.l { prev.c + 1 } else { 0 };
    HLCTime { l: new_l, c: new_c }
}

/// Atualiza o relógio HLC do nó ao receber uma mensagem contendo um timestamp remoto `msg`.
/// O Verus atestará que o resultado (`res`) é estritamente posterior tanto a `prev` quanto a `msg`.
pub fn receive(physical_now: u64, prev: HLCTime, msg: HLCTime) -> (res: HLCTime)
    ensures
        prev.lt(res),
        msg.lt(res)
{
    let max_phys = if physical_now > prev.l { physical_now } else { prev.l };
    let new_l = if max_phys > msg.l { max_phys } else { msg.l };
    
    let new_c = if new_l == prev.l && new_l == msg.l {
        let max_c = if prev.c > msg.c { prev.c } else { msg.c };
        max_c + 1
    } else if new_l == prev.l {
        prev.c + 1
    } else if new_l == msg.l {
        msg.c + 1
    } else {
        0
    };
    
    HLCTime { l: new_l, c: new_c }
}

} // verus!
