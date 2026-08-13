//! HUME-IR — representação intermédia SSA para expressões escalares sobre dados
//! colunares (SPEC-000 §6, SPEC-0038 §1).
//!
//! É a fatia **fundacional** do "compilador" do HUME: a IR sobre a qual os
//! tiers de geração de código (interpretador → Cranelift → LLVM/GPU) operariam.
//! Este crate entrega, real e testado:
//!
//! - [`Function`] / [`Builder`] — uma IR linear em forma **Static Single
//!   Assignment** (cada [`ValueId`] é definido exatamente uma vez).
//! - [`verify`] — o **verificador de invariantes SSA** (definição única,
//!   dominância causal — uso após definição — e boa-tipagem), que habilita os
//!   tiers de compilação a assumir a IR válida sem revalidar (SPEC-000 §6).
//! - [`interpret`] — o **Vector Interpreter** (o "cold tier" do SPEC-0038 §3):
//!   zero overhead de compilação, avalia a IR linha a linha. É deliberadamente
//!   o tier mais lento; o custo de interpretação é exatamente o que um JIT
//!   removeria.
//!
//! ## Honestidade de escopo
//!
//! Os tiers **hot** (Cranelift baseline JIT) e **super-hot** (LLVM/GPU
//! vetorizado) do SPEC-0038 §3 **NÃO estão construídos** — puxam dependências
//! pesadas (cranelift-*, LLVM, CUDA/HIP) e são engenheiro-anos. Este crate é a
//! IR + verificador + interpretador de referência, não wired ao motor vivo
//! (que executa via kernels Arrow — invariante I4). Ver
//! `docs/md/SPEC-NEW/SPEC-HUME.md` §1 para o resto do backlog.

#[cfg(feature = "jit")]
pub mod jit;
pub mod passes;

/// Identificador SSA de um valor: definido exatamente uma vez.
pub type ValueId = u32;

/// Tipos escalares suportados pela IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    I64,
    F64,
    Bool,
}

/// Literal constante.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Const {
    I64(i64),
    F64(f64),
    Bool(bool),
}

impl Const {
    fn ty(self) -> Ty {
        match self {
            Const::I64(_) => Ty::I64,
            Const::F64(_) => Ty::F64,
            Const::Bool(_) => Ty::Bool,
        }
    }
    fn to_val(self) -> Val {
        match self {
            Const::I64(v) => Val::I64(v),
            Const::F64(v) => Val::F64(v),
            Const::Bool(v) => Val::Bool(v),
        }
    }
}

/// Operação de uma instrução SSA. Cada instrução produz um único valor.
#[derive(Debug, Clone)]
pub enum Op {
    /// Literal constante.
    Const(Const),
    /// Carrega o valor da coluna `idx` (tipada) na linha corrente — a entrada.
    Column(usize, Ty),
    Add(ValueId, ValueId),
    Sub(ValueId, ValueId),
    Mul(ValueId, ValueId),
    /// Comparações numéricas → `Bool`.
    CmpGt(ValueId, ValueId),
    CmpLt(ValueId, ValueId),
    CmpEq(ValueId, ValueId),
    /// Lógicas sobre `Bool`.
    And(ValueId, ValueId),
    Or(ValueId, ValueId),
    Not(ValueId),
}

/// Uma instrução SSA: `result = op`.
#[derive(Debug, Clone)]
pub struct Inst {
    pub result: ValueId,
    pub op: Op,
}

/// Uma função escalar: bloco básico linear em SSA + valor de retorno.
#[derive(Debug, Clone)]
pub struct Function {
    /// Número de colunas de entrada disponíveis (`Op::Column` refere-se a estas).
    pub n_columns: usize,
    /// Instruções em ordem linear; `insts[i].result == i` (numeração densa SSA).
    pub insts: Vec<Inst>,
    /// O valor devolvido pela função.
    pub ret: ValueId,
}

/// Construtor incremental que garante a numeração SSA densa (0,1,2,…).
#[derive(Debug, Default)]
pub struct Builder {
    insts: Vec<Inst>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, op: Op) -> ValueId {
        let id = self.insts.len() as ValueId;
        self.insts.push(Inst { result: id, op });
        id
    }

    pub fn constant(&mut self, c: Const) -> ValueId {
        self.push(Op::Const(c))
    }
    pub fn column(&mut self, idx: usize, ty: Ty) -> ValueId {
        self.push(Op::Column(idx, ty))
    }
    pub fn add(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::Add(a, b))
    }
    pub fn sub(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::Sub(a, b))
    }
    pub fn mul(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::Mul(a, b))
    }
    pub fn cmp_gt(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::CmpGt(a, b))
    }
    pub fn cmp_lt(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::CmpLt(a, b))
    }
    pub fn cmp_eq(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::CmpEq(a, b))
    }
    pub fn and(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::And(a, b))
    }
    pub fn or(&mut self, a: ValueId, b: ValueId) -> ValueId {
        self.push(Op::Or(a, b))
    }
    pub fn not(&mut self, a: ValueId) -> ValueId {
        self.push(Op::Not(a))
    }

    /// Fecha a função. `n_columns` = colunas de entrada; `ret` = valor devolvido.
    pub fn finish(self, n_columns: usize, ret: ValueId) -> Function {
        Function { n_columns, insts: self.insts, ret }
    }
}

/// Erros de verificação da IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrError {
    /// A numeração SSA não é densa/única: `insts[i].result != i`.
    BadNumbering { index: usize, result: ValueId },
    /// Uso de um valor antes (ou fora) da sua definição (viola a dominância).
    UseBeforeDef { at: ValueId, used: ValueId },
    /// Tipos incompatíveis para a operação.
    TypeMismatch { at: ValueId, detail: &'static str },
    /// `Op::Column` refere uma coluna fora do intervalo.
    ColumnOob { at: ValueId, idx: usize, n_columns: usize },
    /// O valor de retorno não existe.
    RetOob { ret: ValueId, n_values: usize },
}

/// Verifica os invariantes SSA (SPEC-000 §6) e devolve o tipo de cada valor.
///
/// 1. **Definição única + numeração densa:** `insts[i].result == i`.
/// 2. **Dominância causal:** cada operando é um valor com id `< i` (definido
///    antes na linha linear).
/// 3. **Boa-tipagem:** aritmética entre numéricos do mesmo tipo; comparações
///    numéricas → `Bool`; lógicas sobre `Bool`.
pub fn verify(f: &Function) -> Result<Vec<Ty>, IrError> {
    let mut types: Vec<Ty> = Vec::with_capacity(f.insts.len());
    for (i, inst) in f.insts.iter().enumerate() {
        let i = i as ValueId;
        if inst.result != i {
            return Err(IrError::BadNumbering { index: i as usize, result: inst.result });
        }
        // Operando tem de estar definido antes (id < i).
        let operand_ty = |v: ValueId| -> Result<Ty, IrError> {
            if v >= i {
                Err(IrError::UseBeforeDef { at: i, used: v })
            } else {
                Ok(types[v as usize])
            }
        };
        let ty = match &inst.op {
            Op::Const(c) => c.ty(),
            Op::Column(idx, ty) => {
                if *idx >= f.n_columns {
                    return Err(IrError::ColumnOob { at: i, idx: *idx, n_columns: f.n_columns });
                }
                *ty
            }
            Op::Add(a, b) | Op::Sub(a, b) | Op::Mul(a, b) => {
                let (ta, tb) = (operand_ty(*a)?, operand_ty(*b)?);
                if ta != tb || ta == Ty::Bool {
                    return Err(IrError::TypeMismatch { at: i, detail: "aritmética exige numéricos do mesmo tipo" });
                }
                ta
            }
            Op::CmpGt(a, b) | Op::CmpLt(a, b) | Op::CmpEq(a, b) => {
                let (ta, tb) = (operand_ty(*a)?, operand_ty(*b)?);
                if ta != tb || ta == Ty::Bool {
                    return Err(IrError::TypeMismatch { at: i, detail: "comparação exige numéricos do mesmo tipo" });
                }
                Ty::Bool
            }
            Op::And(a, b) | Op::Or(a, b) => {
                let (ta, tb) = (operand_ty(*a)?, operand_ty(*b)?);
                if ta != Ty::Bool || tb != Ty::Bool {
                    return Err(IrError::TypeMismatch { at: i, detail: "lógica exige Bool" });
                }
                Ty::Bool
            }
            Op::Not(a) => {
                if operand_ty(*a)? != Ty::Bool {
                    return Err(IrError::TypeMismatch { at: i, detail: "Not exige Bool" });
                }
                Ty::Bool
            }
        };
        types.push(ty);
    }
    if (f.ret as usize) >= types.len() {
        return Err(IrError::RetOob { ret: f.ret, n_values: types.len() });
    }
    Ok(types)
}

/// Valor de runtime durante a interpretação.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Val {
    I64(i64),
    F64(f64),
    Bool(bool),
}

impl Val {
    fn as_bool(self) -> bool {
        matches!(self, Val::Bool(true))
    }
}

/// Coluna de entrada para o interpretador (fatia tipada contígua).
#[derive(Debug, Clone, Copy)]
pub enum ColumnData<'a> {
    I64(&'a [i64]),
    F64(&'a [f64]),
}

impl ColumnData<'_> {
    fn get(&self, row: usize) -> Val {
        match self {
            ColumnData::I64(s) => Val::I64(s[row]),
            ColumnData::F64(s) => Val::F64(s[row]),
        }
    }
}

fn arith(a: Val, b: Val, fi: impl Fn(i64, i64) -> i64, ff: impl Fn(f64, f64) -> f64) -> Val {
    match (a, b) {
        (Val::I64(x), Val::I64(y)) => Val::I64(fi(x, y)),
        (Val::F64(x), Val::F64(y)) => Val::F64(ff(x, y)),
        // Inalcançável em IR verificada (aritmética é do mesmo tipo numérico).
        _ => Val::Bool(false),
    }
}

fn compare(a: Val, b: Val, fi: impl Fn(&i64, &i64) -> bool, ff: impl Fn(&f64, &f64) -> bool) -> Val {
    match (a, b) {
        (Val::I64(x), Val::I64(y)) => Val::Bool(fi(&x, &y)),
        (Val::F64(x), Val::F64(y)) => Val::Bool(ff(&x, &y)),
        _ => Val::Bool(false),
    }
}

/// Interpreta (Vector Interpreter / cold tier, SPEC-0038 §3) a função `f` sobre
/// `n` linhas das colunas `cols`, devolvendo o valor de retorno por linha.
///
/// Assume a função **válida** ([`verify`]) e `cols.len() >= f.n_columns`, cada
/// coluna com pelo menos `n` linhas.
pub fn interpret(f: &Function, cols: &[ColumnData], n: usize) -> Result<Vec<Val>, IrError> {
    // Valida uma vez (barato) antes do laço quente por linha.
    verify(f)?;
    let mut out = Vec::with_capacity(n);
    let mut env: Vec<Val> = vec![Val::Bool(false); f.insts.len()];
    for row in 0..n {
        for inst in &f.insts {
            let v = match &inst.op {
                Op::Const(c) => c.to_val(),
                Op::Column(idx, _) => cols[*idx].get(row),
                Op::Add(a, b) => arith(env[*a as usize], env[*b as usize], |x, y| x + y, |x, y| x + y),
                Op::Sub(a, b) => arith(env[*a as usize], env[*b as usize], |x, y| x - y, |x, y| x - y),
                Op::Mul(a, b) => arith(env[*a as usize], env[*b as usize], |x, y| x * y, |x, y| x * y),
                Op::CmpGt(a, b) => compare(env[*a as usize], env[*b as usize], |x, y| x > y, |x, y| x > y),
                Op::CmpLt(a, b) => compare(env[*a as usize], env[*b as usize], |x, y| x < y, |x, y| x < y),
                Op::CmpEq(a, b) => compare(env[*a as usize], env[*b as usize], |x, y| x == y, |x, y| x == y),
                Op::And(a, b) => Val::Bool(env[*a as usize].as_bool() && env[*b as usize].as_bool()),
                Op::Or(a, b) => Val::Bool(env[*a as usize].as_bool() || env[*b as usize].as_bool()),
                Op::Not(a) => Val::Bool(!env[*a as usize].as_bool()),
            };
            env[inst.result as usize] = v;
        }
        out.push(env[f.ret as usize]);
    }
    Ok(out)
}

/// Conveniência: interpreta uma função que devolve `Bool` como máscara de
/// seleção (índices das linhas sobreviventes) — a ponte natural para o
/// `SelectionVector`/`take` do motor.
pub fn interpret_mask(f: &Function, cols: &[ColumnData], n: usize) -> Result<Vec<u32>, IrError> {
    let vals = interpret(f, cols, n)?;
    Ok(vals
        .into_iter()
        .enumerate()
        .filter_map(|(i, v)| v.as_bool().then_some(i as u32))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constrói `(col0 > 900) AND (col1 == 5)`.
    fn score_and_kind() -> Function {
        let mut b = Builder::new();
        let c0 = b.column(0, Ty::I64);
        let k900 = b.constant(Const::I64(900));
        let gt = b.cmp_gt(c0, k900);
        let c1 = b.column(1, Ty::I64);
        let k5 = b.constant(Const::I64(5));
        let eq = b.cmp_eq(c1, k5);
        let ret = b.and(gt, eq);
        b.finish(2, ret)
    }

    #[test]
    fn verifies_well_formed_ssa() {
        let f = score_and_kind();
        let types = verify(&f).unwrap();
        assert_eq!(types[f.ret as usize], Ty::Bool);
        // Numeração densa: 7 valores (0..6).
        assert_eq!(f.insts.len(), 7);
    }

    #[test]
    fn interpreter_evaluates_expression() {
        let f = score_and_kind();
        let col0 = [901i64, 5, 950, 1000];
        let col1 = [5i64, 5, 3, 5];
        let cols = [ColumnData::I64(&col0), ColumnData::I64(&col1)];
        let out = interpret(&f, &cols, 4).unwrap();
        // 901>900&5==5=T ; 5>900=F ; 950>900&3==5=F ; 1000>900&5==5=T
        assert_eq!(out, vec![Val::Bool(true), Val::Bool(false), Val::Bool(false), Val::Bool(true)]);
        assert_eq!(interpret_mask(&f, &cols, 4).unwrap(), vec![0, 3]);
    }

    #[test]
    fn arithmetic_and_float() {
        // (col0 * 2) < 10.0  sobre F64
        let mut b = Builder::new();
        let c0 = b.column(0, Ty::F64);
        let two = b.constant(Const::F64(2.0));
        let prod = b.mul(c0, two);
        let ten = b.constant(Const::F64(10.0));
        let lt = b.cmp_lt(prod, ten);
        let f = b.finish(1, lt);
        let col0 = [1.0f64, 4.0, 6.0];
        let out = interpret(&f, &[ColumnData::F64(&col0)], 3).unwrap();
        // 2<10=T ; 8<10=T ; 12<10=F
        assert_eq!(out, vec![Val::Bool(true), Val::Bool(true), Val::Bool(false)]);
    }

    #[test]
    fn rejects_use_before_def() {
        // Instrução 0 usa o valor 1 (ainda não definido).
        let f = Function {
            n_columns: 1,
            insts: vec![Inst { result: 0, op: Op::Not(1) }],
            ret: 0,
        };
        assert_eq!(verify(&f), Err(IrError::UseBeforeDef { at: 0, used: 1 }));
    }

    #[test]
    fn rejects_bad_numbering() {
        let f = Function {
            n_columns: 0,
            insts: vec![Inst { result: 5, op: Op::Const(Const::Bool(true)) }],
            ret: 5,
        };
        assert_eq!(verify(&f), Err(IrError::BadNumbering { index: 0, result: 5 }));
    }

    #[test]
    fn rejects_type_mismatch() {
        // And sobre dois I64 (devia ser Bool).
        let mut b = Builder::new();
        let a = b.constant(Const::I64(1));
        let c = b.constant(Const::I64(2));
        let bad = b.and(a, c);
        let f = b.finish(0, bad);
        assert!(matches!(verify(&f), Err(IrError::TypeMismatch { .. })));
    }

    #[test]
    fn rejects_column_oob() {
        let mut b = Builder::new();
        let _ = b.column(3, Ty::I64); // só há 1 coluna
        let f = b.finish(1, 0);
        assert!(matches!(verify(&f), Err(IrError::ColumnOob { .. })));
    }
}
