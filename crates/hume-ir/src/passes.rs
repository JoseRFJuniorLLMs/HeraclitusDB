//! Passes de otimização sobre o HUME-IR (SPEC-0039 §3 — motor de reescrita).
//!
//! Implementa dois passes reais de reescrita, o núcleo de qualquer pipeline de
//! compilação:
//!
//! - [`constant_fold`] — avalia em tempo de compilação toda a subexpressão cujos
//!   operandos são constantes (`2 + 3 → 5`).
//! - [`dead_code_elimination`] — remove instruções cujo resultado nunca alcança
//!   o valor de retorno, renumerando a IR para manter a forma SSA densa.
//! - [`optimize`] — `constant_fold` seguido de `dead_code_elimination`.
//!
//! O resultado é sempre semanticamente equivalente ao original (testado por
//! interpretação). Um motor genérico de `RewriteRule { pattern, replacement }`
//! declarativo é o passo seguinte; estes dois passes concretos são a base.

use crate::{Const, Function, Inst, Op, Ty, ValueId};

fn const_ty(c: Const) -> Ty {
    match c {
        Const::I64(_) => Ty::I64,
        Const::F64(_) => Ty::F64,
        Const::Bool(_) => Ty::Bool,
    }
}

/// Tenta reduzir uma operação binária de dois operandos constantes.
fn fold_binop(op: &Op, a: Const, b: Const) -> Option<Const> {
    use Const::*;
    Some(match (op, a, b) {
        (Op::Add(..), I64(x), I64(y)) => I64(x + y),
        (Op::Add(..), F64(x), F64(y)) => F64(x + y),
        (Op::Sub(..), I64(x), I64(y)) => I64(x - y),
        (Op::Sub(..), F64(x), F64(y)) => F64(x - y),
        (Op::Mul(..), I64(x), I64(y)) => I64(x * y),
        (Op::Mul(..), F64(x), F64(y)) => F64(x * y),
        (Op::CmpGt(..), I64(x), I64(y)) => Bool(x > y),
        (Op::CmpGt(..), F64(x), F64(y)) => Bool(x > y),
        (Op::CmpLt(..), I64(x), I64(y)) => Bool(x < y),
        (Op::CmpLt(..), F64(x), F64(y)) => Bool(x < y),
        (Op::CmpEq(..), I64(x), I64(y)) => Bool(x == y),
        (Op::CmpEq(..), F64(x), F64(y)) => Bool(x == y),
        (Op::And(..), Bool(x), Bool(y)) => Bool(x && y),
        (Op::Or(..), Bool(x), Bool(y)) => Bool(x || y),
        _ => return None,
    })
    .filter(|_| const_ty(a) == const_ty(b))
}

/// Constant folding: substitui operações de operandos constantes pelo literal
/// resultante. Não remove os operandos (isso é a DCE).
pub fn constant_fold(f: &Function) -> Function {
    let mut known: Vec<Option<Const>> = vec![None; f.insts.len()];
    let mut insts = Vec::with_capacity(f.insts.len());
    for (i, inst) in f.insts.iter().enumerate() {
        let folded: Option<Const> = match &inst.op {
            Op::Const(c) => Some(*c),
            Op::Column(..) => None,
            Op::Not(a) => match known[*a as usize] {
                Some(Const::Bool(x)) => Some(Const::Bool(!x)),
                _ => None,
            },
            Op::Add(a, b)
            | Op::Sub(a, b)
            | Op::Mul(a, b)
            | Op::CmpGt(a, b)
            | Op::CmpLt(a, b)
            | Op::CmpEq(a, b)
            | Op::And(a, b)
            | Op::Or(a, b) => match (known[*a as usize], known[*b as usize]) {
                (Some(x), Some(y)) => fold_binop(&inst.op, x, y),
                _ => None,
            },
        };
        known[i] = folded;
        let op = match folded {
            Some(c) => Op::Const(c),
            None => inst.op.clone(),
        };
        insts.push(Inst { result: i as ValueId, op });
    }
    Function { n_columns: f.n_columns, insts, ret: f.ret }
}

/// Dead-code elimination: remove instruções cujo resultado não alcança `ret`,
/// renumerando para manter a forma SSA densa (`insts[i].result == i`).
pub fn dead_code_elimination(f: &Function) -> Function {
    // 1) Marca vivos de trás para a frente a partir de `ret`.
    let mut live = vec![false; f.insts.len()];
    live[f.ret as usize] = true;
    for i in (0..f.insts.len()).rev() {
        if !live[i] {
            continue;
        }
        for op in operands(&f.insts[i].op) {
            live[op as usize] = true;
        }
    }
    // 2) Remap old_id → new_id (densos, em ordem).
    let mut remap = vec![0u32; f.insts.len()];
    let mut next = 0u32;
    for i in 0..f.insts.len() {
        if live[i] {
            remap[i] = next;
            next += 1;
        }
    }
    // 3) Reconstrói os vivos com operandos remapeados.
    let mut insts = Vec::with_capacity(next as usize);
    for (i, inst) in f.insts.iter().enumerate() {
        if !live[i] {
            continue;
        }
        insts.push(Inst { result: remap[i], op: remap_op(&inst.op, &remap) });
    }
    Function { n_columns: f.n_columns, insts, ret: remap[f.ret as usize] }
}

/// `constant_fold` ⟶ `dead_code_elimination`.
pub fn optimize(f: &Function) -> Function {
    dead_code_elimination(&constant_fold(f))
}

fn operands(op: &Op) -> Vec<ValueId> {
    match op {
        Op::Const(_) | Op::Column(..) => vec![],
        Op::Not(a) => vec![*a],
        Op::Add(a, b)
        | Op::Sub(a, b)
        | Op::Mul(a, b)
        | Op::CmpGt(a, b)
        | Op::CmpLt(a, b)
        | Op::CmpEq(a, b)
        | Op::And(a, b)
        | Op::Or(a, b) => vec![*a, *b],
    }
}

fn remap_op(op: &Op, remap: &[u32]) -> Op {
    let m = |v: &ValueId| remap[*v as usize];
    match op {
        Op::Const(c) => Op::Const(*c),
        Op::Column(i, t) => Op::Column(*i, *t),
        Op::Not(a) => Op::Not(m(a)),
        Op::Add(a, b) => Op::Add(m(a), m(b)),
        Op::Sub(a, b) => Op::Sub(m(a), m(b)),
        Op::Mul(a, b) => Op::Mul(m(a), m(b)),
        Op::CmpGt(a, b) => Op::CmpGt(m(a), m(b)),
        Op::CmpLt(a, b) => Op::CmpLt(m(a), m(b)),
        Op::CmpEq(a, b) => Op::CmpEq(m(a), m(b)),
        Op::And(a, b) => Op::And(m(a), m(b)),
        Op::Or(a, b) => Op::Or(m(a), m(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{interpret, verify, Builder, ColumnData, Val};

    #[test]
    fn folds_constant_subexpression() {
        // (2 + 3) * col0  →  5 * col0
        let mut b = Builder::new();
        let two = b.constant(Const::I64(2));
        let three = b.constant(Const::I64(3));
        let sum = b.add(two, three);
        let c0 = b.column(0, Ty::I64);
        let prod = b.mul(sum, c0);
        let f = b.finish(1, prod);

        let folded = constant_fold(&f);
        // A instrução `sum` passou a Const(5).
        assert!(matches!(folded.insts[sum as usize].op, Op::Const(Const::I64(5))));
    }

    #[test]
    fn dce_removes_dead_and_stays_valid() {
        // col0 + col1, mas com uma instrução morta pelo meio.
        let mut b = Builder::new();
        let c0 = b.column(0, Ty::I64);
        let c1 = b.column(1, Ty::I64);
        let _dead = b.mul(c0, c1); // nunca usado
        let sum = b.add(c0, c1);
        let f = b.finish(2, sum);

        let opt = dead_code_elimination(&f);
        assert!(opt.insts.len() < f.insts.len(), "removeu a instrução morta");
        verify(&opt).unwrap(); // continua SSA densa e bem-tipada
    }

    #[test]
    fn optimize_preserves_semantics() {
        // ((10 - 4) < col0) AND NOT(false)  →  simplifica, mas dá o mesmo.
        let mut b = Builder::new();
        let ten = b.constant(Const::I64(10));
        let four = b.constant(Const::I64(4));
        let diff = b.sub(ten, four); // 6
        let c0 = b.column(0, Ty::I64);
        let lt = b.cmp_lt(diff, c0); // 6 < col0
        let f_false = b.constant(Const::Bool(false));
        let nt = b.not(f_false); // true
        let ret = b.and(lt, nt);
        let f = b.finish(1, ret);

        let opt = optimize(&f);
        let col0 = [3i64, 6, 7, 100];
        let cols = [ColumnData::I64(&col0)];
        let before = interpret(&f, &cols, 4).unwrap();
        let after = interpret(&opt, &cols, 4).unwrap();
        assert_eq!(before, after, "otimização preserva a semântica");
        // 6<3=F ; 6<6=F ; 6<7=T ; 6<100=T
        assert_eq!(after, vec![Val::Bool(false), Val::Bool(false), Val::Bool(true), Val::Bool(true)]);
        // E encolheu (dobrou constantes + limpou mortos).
        assert!(opt.insts.len() < f.insts.len());
    }
}
