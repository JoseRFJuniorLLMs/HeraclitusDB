//! Hot tier: JIT do HUME-IR para código de máquina nativo via **Cranelift**
//! (SPEC-0038 §3). Pure-Rust — sem LLVM nem CUDA.
//!
//! Compila uma [`Function`] (que devolve `Bool`) num loop nativo sobre as `n`
//! linhas das colunas, escrevendo a máscara de sobrevivência (`u8` por linha).
//! É o tier que remove o overhead de interpretação do [`crate::interpret`].

use cranelift::codegen::ir::{types, AbiParam, InstBuilder, MemFlags, Value};
use cranelift::codegen::settings::{self, Configurable};
use cranelift::frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift::prelude::{FloatCC, IntCC};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, Linkage, Module};

use crate::{verify, ColumnData, Const, Function, IrError, Op, Ty};

type CompiledFn = unsafe extern "C" fn(i64, *const *const u8, *mut u8);

/// Uma expressão do HUME-IR compilada para código nativo.
pub struct JitFilter {
    // A ordem importa: `func` aponta para memória possuída por `_module`; o
    // módulo tem de sobreviver enquanto a função existir.
    func: CompiledFn,
    _module: JITModule,
}

impl JitFilter {
    /// Compila `f` (tem de ser válida e devolver `Bool`).
    pub fn compile(f: &Function) -> Result<Self, String> {
        let types_of = verify(f).map_err(|e| format!("IR inválida: {e:?}"))?;
        if types_of[f.ret as usize] != Ty::Bool {
            return Err("a função do filtro tem de devolver Bool".into());
        }

        let mut flags = settings::builder();
        flags.set("use_colocated_libcalls", "false").unwrap();
        flags.set("is_pic", "false").unwrap();
        let isa_flags = settings::Flags::new(flags);
        let builder = JITBuilder::new(default_libcall_names())
            .map_err(|e| format!("JITBuilder: {e}"))?;
        let _ = &isa_flags; // ISA vem do host via JITBuilder::new
        let mut module = JITModule::new(builder);
        let ptr = module.target_config().pointer_type();

        let mut ctx = module.make_context();
        ctx.func.signature.params.push(AbiParam::new(types::I64)); // n
        ctx.func.signature.params.push(AbiParam::new(ptr)); // cols: *const *const u8
        ctx.func.signature.params.push(AbiParam::new(ptr)); // out:  *mut u8

        let mut fb_ctx = FunctionBuilderContext::new();
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);

        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        let n = b.block_params(entry)[0];
        let cols = b.block_params(entry)[1];
        let out = b.block_params(entry)[2];

        // row: i64 = 0
        let row_var = Variable::from_u32(0);
        b.declare_var(row_var, types::I64);
        let zero = b.ins().iconst(types::I64, 0);
        b.def_var(row_var, zero);

        let header = b.create_block();
        let body = b.create_block();
        let exit = b.create_block();
        b.ins().jump(header, &[]);

        // header: if row < n goto body else exit
        b.switch_to_block(header);
        let row = b.use_var(row_var);
        let cond = b.ins().icmp(IntCC::SignedLessThan, row, n);
        b.ins().brif(cond, body, &[], exit, &[]);

        // body: out[row] = expr(row); row += 1; goto header
        b.switch_to_block(body);
        let row = b.use_var(row_var);
        let ptr_bytes = ptr.bytes() as i64;
        let res = emit_expr(&mut b, f, &types_of, cols, row, ptr, ptr_bytes);
        let res8 = b.ins().ireduce(types::I8, res);
        let addr = b.ins().iadd(out, row); // out + row (1 byte por linha)
        b.ins().store(MemFlags::new(), res8, addr, 0);
        let one = b.ins().iconst(types::I64, 1);
        let next = b.ins().iadd(row, one);
        b.def_var(row_var, next);
        b.ins().jump(header, &[]);

        // exit
        b.switch_to_block(exit);
        b.ins().return_(&[]);

        b.seal_all_blocks();
        b.finalize();

        let id = module
            .declare_function("hume_filter", Linkage::Export, &ctx.func.signature)
            .map_err(|e| format!("declare: {e}"))?;
        module
            .define_function(id, &mut ctx)
            .map_err(|e| format!("define: {e}"))?;
        module.clear_context(&mut ctx);
        module
            .finalize_definitions()
            .map_err(|e| format!("finalize: {e}"))?;
        let code = module.get_finalized_function(id);
        // SAFETY: assinatura acima corresponde exatamente a `CompiledFn`.
        let func: CompiledFn = unsafe { std::mem::transmute::<*const u8, CompiledFn>(code) };
        Ok(Self { func, _module: module })
    }

    /// Executa o filtro sobre `n` linhas, devolvendo os índices sobreviventes.
    ///
    /// # Safety (contrato do chamador)
    /// `cols` tem de cobrir todas as colunas referenciadas pela IR, cada uma com
    /// pelo menos `n` elementos.
    pub fn run(&self, cols: &[ColumnData], n: usize) -> Vec<u32> {
        let ptrs: Vec<*const u8> = cols
            .iter()
            .map(|c| match c {
                ColumnData::I64(s) => s.as_ptr() as *const u8,
                ColumnData::F64(s) => s.as_ptr() as *const u8,
            })
            .collect();
        let mut out = vec![0u8; n];
        // SAFETY: ver contrato acima; ponteiros vivos durante a chamada.
        unsafe { (self.func)(n as i64, ptrs.as_ptr(), out.as_mut_ptr()) };
        out.iter()
            .enumerate()
            .filter_map(|(i, &x)| (x != 0).then_some(i as u32))
            .collect()
    }
}

/// Emite a expressão SSA como valores Cranelift; devolve o valor de retorno
/// (booleano representado em `I64` 0/1).
#[allow(clippy::too_many_arguments)]
fn emit_expr(
    b: &mut FunctionBuilder,
    f: &Function,
    types_of: &[Ty],
    cols: Value,
    row: Value,
    ptr_ty: cranelift::codegen::ir::Type,
    ptr_bytes: i64,
) -> Value {
    let flags = MemFlags::new();
    let mut vals: Vec<Value> = Vec::with_capacity(f.insts.len());
    for (i, inst) in f.insts.iter().enumerate() {
        let v = match &inst.op {
            Op::Const(Const::I64(c)) => b.ins().iconst(types::I64, *c),
            Op::Const(Const::F64(c)) => b.ins().f64const(*c),
            Op::Const(Const::Bool(c)) => b.ins().iconst(types::I64, *c as i64),
            Op::Column(idx, ty) => {
                // col_ptr = *(cols + idx*ptr_bytes)
                let coff = b.ins().iconst(types::I64, *idx as i64 * ptr_bytes);
                let caddr = b.ins().iadd(cols, coff);
                let col_ptr = b.ins().load(ptr_ty, flags, caddr, 0);
                // elem = col_ptr[row]
                let esz = b.ins().iconst(types::I64, 8); // I64/F64 = 8 bytes
                let eoff = b.ins().imul(row, esz);
                let eaddr = b.ins().iadd(col_ptr, eoff);
                match ty {
                    Ty::I64 => b.ins().load(types::I64, flags, eaddr, 0),
                    Ty::F64 => b.ins().load(types::F64, flags, eaddr, 0),
                    Ty::Bool => b.ins().iconst(types::I64, 0), // colunas não são Bool
                }
            }
            Op::Add(x, y) => arith(b, types_of[i], vals[*x as usize], vals[*y as usize], Arith::Add),
            Op::Sub(x, y) => arith(b, types_of[i], vals[*x as usize], vals[*y as usize], Arith::Sub),
            Op::Mul(x, y) => arith(b, types_of[i], vals[*x as usize], vals[*y as usize], Arith::Mul),
            Op::CmpGt(x, y) => cmp(b, types_of[*x as usize], vals[*x as usize], vals[*y as usize], Cmp::Gt),
            Op::CmpLt(x, y) => cmp(b, types_of[*x as usize], vals[*x as usize], vals[*y as usize], Cmp::Lt),
            Op::CmpEq(x, y) => cmp(b, types_of[*x as usize], vals[*x as usize], vals[*y as usize], Cmp::Eq),
            Op::And(x, y) => b.ins().band(vals[*x as usize], vals[*y as usize]),
            Op::Or(x, y) => b.ins().bor(vals[*x as usize], vals[*y as usize]),
            Op::Not(x) => {
                let one = b.ins().iconst(types::I64, 1);
                b.ins().bxor(vals[*x as usize], one)
            }
        };
        vals.push(v);
    }
    vals[f.ret as usize]
}

enum Arith {
    Add,
    Sub,
    Mul,
}
enum Cmp {
    Gt,
    Lt,
    Eq,
}

fn arith(b: &mut FunctionBuilder, ty: Ty, x: Value, y: Value, op: Arith) -> Value {
    match ty {
        Ty::F64 => match op {
            Arith::Add => b.ins().fadd(x, y),
            Arith::Sub => b.ins().fsub(x, y),
            Arith::Mul => b.ins().fmul(x, y),
        },
        _ => match op {
            Arith::Add => b.ins().iadd(x, y),
            Arith::Sub => b.ins().isub(x, y),
            Arith::Mul => b.ins().imul(x, y),
        },
    }
}

/// Comparação → booleano em `I64` (0/1). `operand_ty` = tipo dos operandos.
fn cmp(b: &mut FunctionBuilder, operand_ty: Ty, x: Value, y: Value, op: Cmp) -> Value {
    let raw = match operand_ty {
        Ty::F64 => {
            let cc = match op {
                Cmp::Gt => FloatCC::GreaterThan,
                Cmp::Lt => FloatCC::LessThan,
                Cmp::Eq => FloatCC::Equal,
            };
            b.ins().fcmp(cc, x, y)
        }
        _ => {
            let cc = match op {
                Cmp::Gt => IntCC::SignedGreaterThan,
                Cmp::Lt => IntCC::SignedLessThan,
                Cmp::Eq => IntCC::Equal,
            };
            b.ins().icmp(cc, x, y)
        }
    };
    b.ins().uextend(types::I64, raw)
}

impl From<IrError> for String {
    fn from(e: IrError) -> Self {
        format!("{e:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{interpret_mask, Builder};

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
    fn jit_matches_interpreter() {
        let f = score_and_kind();
        let col0: Vec<i64> = (0..1000).map(|i| (i * 7 % 1100) as i64).collect();
        let col1: Vec<i64> = (0..1000).map(|i| (i % 8) as i64).collect();
        let cols = [ColumnData::I64(&col0), ColumnData::I64(&col1)];

        let jit = JitFilter::compile(&f).unwrap();
        let jit_out = jit.run(&cols, 1000);
        let interp_out = interpret_mask(&f, &cols, 1000).unwrap();
        assert_eq!(jit_out, interp_out, "JIT ≡ interpretador (bit a bit)");
        assert!(!jit_out.is_empty(), "há sobreviventes");
    }

    #[test]
    fn jit_float_arithmetic() {
        // (col0 * 2.0) < 10.0
        let mut b = Builder::new();
        let c0 = b.column(0, Ty::F64);
        let two = b.constant(Const::F64(2.0));
        let prod = b.mul(c0, two);
        let ten = b.constant(Const::F64(10.0));
        let lt = b.cmp_lt(prod, ten);
        let f = b.finish(1, lt);

        let col0 = [1.0f64, 4.0, 6.0, 4.9];
        let cols = [ColumnData::F64(&col0)];
        let jit = JitFilter::compile(&f).unwrap();
        assert_eq!(jit.run(&cols, 4), interpret_mask(&f, &cols, 4).unwrap());
        assert_eq!(jit.run(&cols, 4), vec![0, 1, 3]); // 2<10, 8<10, 12>=10, 9.8<10
    }
}
