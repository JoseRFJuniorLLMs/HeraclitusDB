//! heraclitus-gpu — heterogeneous acceleration for batch distance (M20.3).
//!
//! The pattern (SPEC-HVM-001 §C / `docs/md/M20_hvm_fractal_gpu.md`): a GPU does
//! the brute-force math — batch distance over many candidate vectors — and emits
//! a Top-M stream; the CPU then arbitrates exactly. The GPU **never** decides the
//! ledger. To keep the result stable across different GPUs, every approximate
//! distance passes through `OP_QUANTIZE` (from `heraclitus-core::vm`, M20.0)
//! before ranking, so sub-quantum float jitter cannot reorder candidates
//! (*ordinal invariance*).
//!
//! Two metrics are provided:
//! - **Euclidean** (M20.3.0/.1a): [`batch_sqdist_cpu`] / [`topm`] with the
//!   [`PRODUCT_SQDIST_WGSL`] kernel — the foundation, validated on hardware.
//! - **Product manifold** (M20.3.1b): [`product_dist_cpu`] / [`topm_product`]
//!   with [`PRODUCT_MANIFOLD_DIST_WGSL`] — the real index metric
//!   `H^a(k1) x S^b(k2) x E^c`, `dist = sqrt(w1*d_H^2 + w2*d_S^2 + w3*d_E^2)`,
//!   a port of `heraclitus_manifold::ProductMetric::dist` (GPU in f32; CPU
//!   reference in f64; the quantization absorbs the f32/f64 gap). Que o porte
//!   continua equivalente ao original NAO se afirma aqui -- prova-se no modulo
//!   `testes_equivalencia_manifold` (auditoria 2026-09-05, vaga 2: a copia
//!   dizia-se "1:1" e tinha divergido em silencio).
//!
//! The real wgpu dispatch is gated behind the `gpu` feature and always keeps the
//! CPU reference as fallback; it self-validates against the CPU on real hardware
//! (`gpu_matches_cpu_on_hardware`, `product_gpu_matches_cpu_on_hardware`).

use heraclitus_core::vm::execute_op_quantize;

/// A ranked candidate: the quantized distance (the stable integer key) and the
/// row index. Ordered by `qdist` then `index` — a total, deterministic order
/// (nearest = smallest), so the Top-M is reproducible across hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Candidate {
    pub qdist: u64,
    pub index: u32,
}

// ============================================================================
// Euclidean (M20.3.0 / M20.3.1a) — foundation, validated on hardware
// ============================================================================

/// The WGSL compute shader: one invocation per candidate row computes the
/// squared-Euclidean distance to the query. This is the GPU expression of
/// [`batch_sqdist_cpu`].
pub const PRODUCT_SQDIST_WGSL: &str = r#"
@group(0) @binding(0) var<storage, read>       query:     array<f32>;
@group(0) @binding(1) var<storage, read>       vectors:   array<f32>;
@group(0) @binding(2) var<storage, read_write> distances: array<f32>;
@group(0) @binding(3) var<uniform>             params:    vec2<u32>; // (dim, n)

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x;
    let dim = params.x;
    let n   = params.y;
    if (row >= n) { return; }
    var acc: f32 = 0.0;
    let base = row * dim;
    for (var j: u32 = 0u; j < dim; j = j + 1u) {
        let d = vectors[base + j] - query[j];
        acc = acc + d * d;
    }
    distances[row] = acc;
}
"#;

/// Squared-Euclidean distance from `query` to each row of `vectors` (flat,
/// row-major, `dim` floats per row). The reference the WGSL kernel must match.
pub fn batch_sqdist_cpu(query: &[f32], vectors: &[f32], dim: usize) -> Vec<f32> {
    assert!(dim > 0, "dim must be > 0");
    assert_eq!(query.len(), dim, "query length must equal dim");
    assert_eq!(
        vectors.len() % dim,
        0,
        "vectors length must be a multiple of dim"
    );
    vectors
        .chunks_exact(dim)
        .map(|row| row.iter().zip(query).map(|(a, b)| (a - b) * (a - b)).sum())
        .collect()
}

/// Quantized Top-M nearest rows by squared distance.
pub fn topm_cpu(
    query: &[f32],
    vectors: &[f32],
    dim: usize,
    m: usize,
    scale: f32,
) -> Vec<Candidate> {
    let dists = batch_sqdist_cpu(query, vectors, dim);
    rank(dists.into_iter(), m, scale)
}

// ============================================================================
// Product manifold (M20.3.1b) — the real index metric H^a x S^b x E^c
// ============================================================================

/// Signature of the product manifold (mirrors `heraclitus_manifold::Signature`).
/// `c1 = -k1 > 0` is the (positive) hyperbolic curvature magnitude.
#[derive(Clone, Copy, Debug)]
pub struct ProductSig {
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub c1: f32,
    pub k2: f32,
    pub weights: [f32; 3],
    pub ball_eps: f32,
}

impl Default for ProductSig {
    fn default() -> Self {
        // Matches heraclitus_manifold::Signature::default + BALL_EPS.
        Self {
            a: 32,
            b: 8,
            c: 8,
            c1: 1.0,
            k2: 1.0,
            weights: [1.0, 1.0, 1.0],
            ball_eps: 1e-5,
        }
    }
}

fn norm64(a: &[f64]) -> f64 {
    a.iter().map(|x| x * x).sum::<f64>().sqrt()
}

/// Poincaré-ball geodesic distance (curvature -c).
///
/// Esta e a referencia f64 que o kernel WGSL tem de igualar. A equivalencia com
/// `heraclitus_manifold::dist_hyp` NAO e uma afirmacao do comentario: e provada
/// pelo teste `testes_equivalencia_manifold::cpu_do_gpu_e_1_1_com_o_manifold`.
/// (Auditoria 2026-09-05, vaga 2: o comentario anterior dizia "1:1 with
/// `manifold::dist_hyp`" e era falso -- faltavam aqui as duas recusas abaixo.)
fn dist_hyp_cpu(u: &[f32], v: &[f32], c: f64, ball_eps: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    // Auditoria 2026-09-05, vaga 2 (R59): informacao incomparavel = infinitamente
    // longe. O `zip` mais abaixo TRUNCA pelo mais curto, e um candidato mais
    // curto dava diff2 = 0 -> arg = 1.0 -> acosh(1) = 0: distancia ZERO de toda
    // a gente. A guarda de vazio corre PRIMEIRO de proposito -- uma consulta
    // parcial (so `hyp` preenchido) e legitima e continua a nao contribuir.
    if u.len() != v.len() {
        return f64::INFINITY;
    }
    let to64 = |x: &[f32]| -> Vec<f64> { x.iter().map(|&z| z as f64).collect() };
    let max_norm = (1.0 - ball_eps) / c.sqrt();
    let clamp = |w: Vec<f64>| -> Vec<f64> {
        let n = norm64(&w);
        if n > max_norm {
            w.iter().map(|z| z * (max_norm / n)).collect()
        } else {
            w
        }
    };
    let u = clamp(to64(u));
    let v = clamp(to64(v));
    let nu = norm64(&u);
    let nv = norm64(&v);
    let diff2: f64 = u.iter().zip(&v).map(|(a, b)| (a - b) * (a - b)).sum();
    let denom = (1.0 - c * nu * nu) * (1.0 - c * nv * nv);
    let arg = 1.0 + (2.0 * c * diff2 / denom);
    // Auditoria 2026-09-05, vaga 2 (R59): guarda anti-NaN. Um embedding com NaN
    // sobrevive a ingestao (`project_to_ball` so recorta a norma, e `n > max_norm`
    // e falso para NaN) e dava aqui arg = NaN; como `NaN.max(1.0) == 1.0` em Rust
    // e `acosh(1) = 0`, o vector corrompido ficava a distancia ZERO de tudo. Como
    // `execute_op_quantize` converte NaN em 0 -- a chave MINIMA --, um NaN sem
    // guarda GANHA o Top-M e expulsa os vizinhos verdadeiros do oversample.
    if !arg.is_finite() {
        return f64::INFINITY;
    }
    (1.0 / c.sqrt()) * arg.max(1.0).acosh()
}

/// Spherical geodesic distance (radius 1/sqrt(k2)).
///
/// Referencia f64 do kernel WGSL; a equivalencia com
/// `heraclitus_manifold::dist_sph` e provada por
/// `testes_equivalencia_manifold::cpu_do_gpu_e_1_1_com_o_manifold`.
fn dist_sph_cpu(u: &[f32], v: &[f32], k2: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    // Auditoria 2026-09-05, vaga 2 (R59): ver `dist_hyp_cpu` -- comprimentos
    // diferentes sao incomparaveis, nao "iguais na parte comum".
    if u.len() != v.len() {
        return f64::INFINITY;
    }
    let to64 = |x: &[f32]| -> Vec<f64> { x.iter().map(|&z| z as f64).collect() };
    let (u, v) = (to64(u), to64(v));
    let (nu, nv) = (norm64(&u), norm64(&v));
    if nu == 0.0 || nv == 0.0 {
        return 0.0;
    }
    let dotp: f64 = u.iter().zip(&v).map(|(a, b)| a * b).sum();
    let cos = (dotp / (nu * nv)).clamp(-1.0, 1.0);
    // Auditoria 2026-09-05, vaga 2 (R59): com NaN, `clamp(-1, 1)` devolve NaN e
    // `acos(NaN) = NaN` -- e um NaN quantiza para 0, a chave minima. Recusar.
    if !cos.is_finite() {
        return f64::INFINITY;
    }
    cos.acos() / k2.sqrt()
}

/// Euclidean distance.
///
/// Referencia f64 do kernel WGSL; a equivalencia com
/// `heraclitus_manifold::dist_euc` e provada por
/// `testes_equivalencia_manifold::cpu_do_gpu_e_1_1_com_o_manifold`.
fn dist_euc_cpu(u: &[f32], v: &[f32]) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    // Auditoria 2026-09-05, vaga 2 (R59): ver `dist_hyp_cpu` -- o `zip` truncava
    // pelo mais curto e um candidato mais curto ficava a distancia zero de tudo.
    if u.len() != v.len() {
        return f64::INFINITY;
    }
    // Auditoria 2026-09-05, vaga 2 (R59): a diferenca e feita em f64, nao em f32.
    // `(a - b) as f64` arredondava a subtraccao para f32 ANTES de a promover, o
    // que afastava esta "referencia f64" do `manifold::dist_euc` em ~7e-9
    // relativo (medido) -- pequeno, mas suficiente para a palavra "1:1" ser
    // falsa e para o teste de equivalencia nao poder ser estrito.
    let s: f64 = u
        .iter()
        .zip(v)
        .map(|(a, b)| {
            let t = *a as f64 - *b as f64;
            t * t
        })
        .sum();
    // Guarda anti-NaN/infinito: `sqrt(NaN) = NaN` e NaN quantiza para 0.
    if !s.is_finite() {
        return f64::INFINITY;
    }
    s.sqrt()
}

/// Batch product-manifold distance: the f64 reference the WGSL kernel must match.
/// Each row is laid out `[hyp(a) | sph(b) | euc(c)]`, same as the query.
pub fn product_dist_cpu(query: &[f32], vectors: &[f32], sig: &ProductSig) -> Vec<f64> {
    let dim = sig.a + sig.b + sig.c;
    assert!(dim > 0, "dim must be > 0");
    assert_eq!(query.len(), dim, "query length must equal a+b+c");
    assert_eq!(
        vectors.len() % dim,
        0,
        "vectors length must be a multiple of a+b+c"
    );
    let c1 = sig.c1 as f64;
    let k2 = sig.k2 as f64;
    let ball_eps = sig.ball_eps as f64;
    let (w1, w2, w3) = (
        sig.weights[0] as f64,
        sig.weights[1] as f64,
        sig.weights[2] as f64,
    );
    let (qh, qs, qe) = (
        &query[..sig.a],
        &query[sig.a..sig.a + sig.b],
        &query[sig.a + sig.b..],
    );
    vectors
        .chunks_exact(dim)
        .map(|row| {
            let (rh, rs, re) = (
                &row[..sig.a],
                &row[sig.a..sig.a + sig.b],
                &row[sig.a + sig.b..],
            );
            let dh = dist_hyp_cpu(qh, rh, c1, ball_eps);
            let ds = dist_sph_cpu(qs, rs, k2);
            let de = dist_euc_cpu(qe, re);
            // Auditoria 2026-09-05, vaga 2 (R59): propagar o nao-finito ANTES de
            // aplicar os pesos. Com um peso a 0.0, `0.0 * inf` da NaN e o
            // candidato recusado voltava a ordenar como o MELHOR de todos (NaN
            // quantiza para 0). Mesma politica de `ProductMetric::dist`.
            if !dh.is_finite() || !ds.is_finite() || !de.is_finite() {
                return f64::INFINITY;
            }
            (w1 * dh * dh + w2 * ds * ds + w3 * de * de).sqrt()
        })
        .collect()
}

/// Quantized Top-M nearest rows by product-manifold distance (CPU reference).
pub fn topm_product_cpu(
    query: &[f32],
    vectors: &[f32],
    sig: &ProductSig,
    m: usize,
    scale: f32,
) -> Vec<Candidate> {
    let dists = product_dist_cpu(query, vectors, sig);
    rank(dists.into_iter().map(|d| d as f32), m, scale)
}

/// The WGSL port of [`product_dist_cpu`] — `dist = sqrt(w1*d_H^2 + w2*d_S^2 +
/// w3*d_E^2)` over `[hyp(a) | sph(b) | euc(c)]`. All math in f32; the
/// quantization on the CPU side absorbs the f32/f64 divergence.
pub const PRODUCT_MANIFOLD_DIST_WGSL: &str = r#"
struct Params {
    a: u32, b: u32, c: u32, n: u32,
    c1: f32, k2: f32, w1: f32, w2: f32, w3: f32, ball_eps: f32,
    pad0: f32, pad1: f32,
};
@group(0) @binding(0) var<storage, read>       query:     array<f32>;
@group(0) @binding(1) var<storage, read>       vectors:   array<f32>;
@group(0) @binding(2) var<storage, read_write> distances: array<f32>;
@group(0) @binding(3) var<uniform>             params:    Params;

// acosh(x) = ln(x + sqrt(x^2 - 1)), x >= 1.
fn acosh_approx(x: f32) -> f32 { return log(x + sqrt(x * x - 1.0)); }

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let row = gid.x;
    if (row >= params.n) { return; }
    let dim = params.a + params.b + params.c;
    let base = row * dim;

    // --- hyperbolic (Poincaré ball, curvature -c1) ---
    var dh: f32 = 0.0;
    if (params.a > 0u) {
        var nq2: f32 = 0.0; var nv2: f32 = 0.0;
        for (var i: u32 = 0u; i < params.a; i = i + 1u) {
            let q = query[i]; let v = vectors[base + i];
            nq2 = nq2 + q * q; nv2 = nv2 + v * v;
        }
        let nq = sqrt(nq2); let nvn = sqrt(nv2);
        let max_norm = (1.0 - params.ball_eps) / sqrt(params.c1);
        var sq: f32 = 1.0; if (nq  > max_norm) { sq = max_norm / nq; }
        var sv: f32 = 1.0; if (nvn > max_norm) { sv = max_norm / nvn; }
        let nu = nq * sq; let nv = nvn * sv;
        var diff2: f32 = 0.0;
        for (var i: u32 = 0u; i < params.a; i = i + 1u) {
            let d = query[i] * sq - vectors[base + i] * sv;
            diff2 = diff2 + d * d;
        }
        let denom = (1.0 - params.c1 * nu * nu) * (1.0 - params.c1 * nv * nv);
        let arg = 1.0 + (2.0 * params.c1 * diff2 / denom);
        dh = (1.0 / sqrt(params.c1)) * acosh_approx(max(arg, 1.0));
    }

    // --- spherical ---
    var ds: f32 = 0.0;
    if (params.b > 0u) {
        var sdot: f32 = 0.0; var snu2: f32 = 0.0; var snv2: f32 = 0.0;
        for (var i: u32 = 0u; i < params.b; i = i + 1u) {
            let q = query[params.a + i]; let v = vectors[base + params.a + i];
            sdot = sdot + q * v; snu2 = snu2 + q * q; snv2 = snv2 + v * v;
        }
        let snu = sqrt(snu2); let snv = sqrt(snv2);
        if (snu > 0.0 && snv > 0.0) {
            let cosv = clamp(sdot / (snu * snv), -1.0, 1.0);
            ds = acos(cosv) / sqrt(params.k2);
        }
    }

    // --- euclidean ---
    var de2: f32 = 0.0;
    if (params.c > 0u) {
        let off = params.a + params.b;
        for (var i: u32 = 0u; i < params.c; i = i + 1u) {
            let d = query[off + i] - vectors[base + off + i];
            de2 = de2 + d * d;
        }
    }
    let de = sqrt(de2);

    let dist2 = params.w1 * dh * dh + params.w2 * ds * ds + params.w3 * de * de;
    distances[row] = sqrt(dist2);
}
"#;

/// Shared ranking: quantize each distance and keep the Top-M (nearest = smallest).
fn rank(dists: impl Iterator<Item = f32>, m: usize, scale: f32) -> Vec<Candidate> {
    let mut cands: Vec<Candidate> = dists
        .enumerate()
        .map(|(i, d)| Candidate {
            qdist: execute_op_quantize(d, scale),
            index: i as u32,
        })
        .collect();
    cands.sort_unstable();
    cands.truncate(m);
    cands
}

// ============================================================================
// GPU runtime (feature `gpu`) — real wgpu dispatch, CPU fallback
// ============================================================================

/// Lazily-initialised wgpu context (device + queue + both compute pipelines),
/// cached for the process. `None` if no GPU adapter is available — then every
/// caller transparently falls back to the CPU reference.
#[cfg(feature = "gpu")]
mod gpu_rt {
    use std::sync::OnceLock;

    pub struct Ctx {
        pub device: wgpu::Device,
        pub queue: wgpu::Queue,
        pub sqdist: wgpu::ComputePipeline,
        pub sqdist_bgl: wgpu::BindGroupLayout,
        pub product: wgpu::ComputePipeline,
        pub product_bgl: wgpu::BindGroupLayout,
    }

    static CTX: OnceLock<Option<Ctx>> = OnceLock::new();

    pub fn ctx() -> Option<&'static Ctx> {
        CTX.get_or_init(|| pollster::block_on(init())).as_ref()
    }

    fn pipeline(
        device: &wgpu::Device,
        label: &str,
        src: &str,
    ) -> (wgpu::ComputePipeline, wgpu::BindGroupLayout) {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some(label),
            source: wgpu::ShaderSource::Wgsl(src.into()),
        });
        let p = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some(label),
            layout: None,
            module: &module,
            entry_point: Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });
        let bgl = p.get_bind_group_layout(0);
        (p, bgl)
    }

    async fn init() -> Option<Ctx> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions::default())
            .await?;
        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("heraclitus-gpu"),
                    ..Default::default()
                },
                None,
            )
            .await
            .ok()?;
        let (sqdist, sqdist_bgl) = pipeline(&device, "sqdist", super::PRODUCT_SQDIST_WGSL);
        let (product, product_bgl) =
            pipeline(&device, "product", super::PRODUCT_MANIFOLD_DIST_WGSL);
        Some(Ctx {
            device,
            queue,
            sqdist,
            sqdist_bgl,
            product,
            product_bgl,
        })
    }
}

/// Dispatch a distance kernel on the GPU and read back the `n` f32 distances.
/// `param_bytes` is the uniform buffer the kernel expects at binding 3.
#[cfg(feature = "gpu")]
fn run_dist(
    ctx: &gpu_rt::Ctx,
    pipeline: &wgpu::ComputePipeline,
    bgl: &wgpu::BindGroupLayout,
    query: &[f32],
    vectors: &[f32],
    n: usize,
    param_bytes: &[u8],
) -> Option<Vec<f32>> {
    use wgpu::util::DeviceExt;
    let device = &ctx.device;

    let query_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("query"),
        contents: bytemuck::cast_slice(query),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let vectors_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("vectors"),
        contents: bytemuck::cast_slice(vectors),
        usage: wgpu::BufferUsages::STORAGE,
    });
    let dist_size = (n * std::mem::size_of::<f32>()) as wgpu::BufferAddress;
    let dist_buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("distances"),
        size: dist_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });
    let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("params"),
        contents: param_bytes,
        usage: wgpu::BufferUsages::UNIFORM,
    });
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("readback"),
        size: dist_size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("dist-bg"),
        layout: bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: query_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: vectors_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: dist_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: params_buf.as_entire_binding(),
            },
        ],
    });

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
        pass.set_pipeline(pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups((n as u32).div_ceil(64), 1, 1);
    }
    encoder.copy_buffer_to_buffer(&dist_buf, 0, &readback, 0, dist_size);
    ctx.queue.submit(Some(encoder.finish()));

    let slice = readback.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| {
        let _ = tx.send(r);
    });
    let _ = device.poll(wgpu::Maintain::Wait);
    rx.recv().ok()?.ok()?;
    let data = slice.get_mapped_range();
    let out: Vec<f32> = bytemuck::cast_slice::<u8, f32>(&data).to_vec();
    drop(data);
    readback.unmap();
    Some(out)
}

/// GPU Top-M by squared-Euclidean distance. `None` if no GPU → CPU fallback.
#[cfg(feature = "gpu")]
pub fn topm_gpu(
    query: &[f32],
    vectors: &[f32],
    dim: usize,
    m: usize,
    scale: f32,
) -> Option<Vec<Candidate>> {
    if dim == 0 || query.len() != dim || vectors.is_empty() || !vectors.len().is_multiple_of(dim) {
        return None;
    }
    let n = vectors.len() / dim;
    let ctx = gpu_rt::ctx()?;
    let params: [u32; 4] = [dim as u32, n as u32, 0, 0];
    let dists = run_dist(
        ctx,
        &ctx.sqdist,
        &ctx.sqdist_bgl,
        query,
        vectors,
        n,
        bytemuck::cast_slice(&params),
    )?;
    Some(rank(dists.into_iter(), m, scale))
}

/// GPU Top-M by product-manifold distance. `None` if no GPU → CPU fallback.
/// Validated against [`product_dist_cpu`] by `product_gpu_matches_cpu_on_hardware`.
#[cfg(feature = "gpu")]
pub fn topm_product_gpu(
    query: &[f32],
    vectors: &[f32],
    sig: &ProductSig,
    m: usize,
    scale: f32,
) -> Option<Vec<Candidate>> {
    let dim = sig.a + sig.b + sig.c;
    if dim == 0 || query.len() != dim || vectors.is_empty() || !vectors.len().is_multiple_of(dim) {
        return None;
    }
    let n = vectors.len() / dim;
    let ctx = gpu_rt::ctx()?;
    // Params struct layout (std140): 4 u32 + 6 f32 + 2 pad = 48 bytes.
    let params: [u32; 12] = [
        sig.a as u32,
        sig.b as u32,
        sig.c as u32,
        n as u32,
        sig.c1.to_bits(),
        sig.k2.to_bits(),
        sig.weights[0].to_bits(),
        sig.weights[1].to_bits(),
        sig.weights[2].to_bits(),
        sig.ball_eps.to_bits(),
        0,
        0,
    ];
    let dists = run_dist(
        ctx,
        &ctx.product,
        &ctx.product_bgl,
        query,
        vectors,
        n,
        bytemuck::cast_slice(&params),
    )?;
    Some(rank(dists.into_iter(), m, scale))
}

/// Euclidean Top-M: GPU (feature `gpu`) with CPU fallback. Always CPU today
/// unless `gpu` is enabled and an adapter exists.
pub fn topm(query: &[f32], vectors: &[f32], dim: usize, m: usize, scale: f32) -> Vec<Candidate> {
    #[cfg(feature = "gpu")]
    if let Some(r) = topm_gpu(query, vectors, dim, m, scale) {
        return r;
    }
    topm_cpu(query, vectors, dim, m, scale)
}

/// Product-manifold Top-M: GPU (feature `gpu`) with CPU fallback. This is the
/// drop-in the index RECALL path calls; the GPU does the brute-force scan and
/// the CPU arbitrates the quantized order.
pub fn topm_product(
    query: &[f32],
    vectors: &[f32],
    sig: &ProductSig,
    m: usize,
    scale: f32,
) -> Vec<Candidate> {
    #[cfg(feature = "gpu")]
    {
        let dim = sig.a + sig.b + sig.c;
        let n = vectors.len().checked_div(dim).unwrap_or(0);
        // Abaixo do ponto de cruzamento a GPU PERDE: o custo de transferir os
        // vetores e despachar o shader não é amortizado. Medido em
        // `benches/gpu_vs_cpu.rs` (H32xS8xE8, 48 dims):
        //
        //     1.000 vetores  0.19x   <- GPU 5x MAIS LENTA
        //    10.000          1.50x
        //    50.000          1.67x
        //   200.000          3.05x
        //   500.000          3.46x
        //
        // Sem esta guarda, ligar a feature `gpu` degradava toda a instalação com
        // coleções pequenas — que são a maioria antes de haver volume. O
        // fallback deixava de ser rede de segurança e passava a ser a via
        // rápida que ninguém tomava.
        if n >= GPU_MIN_VECTORS {
            if let Some(r) = topm_product_gpu(query, vectors, sig, m, scale) {
                return r;
            }
        }
    }
    topm_product_cpu(query, vectors, sig, m, scale)
}

/// Ponto de cruzamento CPU→GPU, em número de vetores.
///
/// Conservador de propósito: a 10.000 a GPU já ganha 1,5x, mas o ganho só se
/// torna material (>3x) na ordem das centenas de milhares. Escolher 8.000 põe o
/// limiar logo acima da zona onde a GPU perde, sem prometer ganho onde ele é
/// ruído. Reveja com `cargo bench -p heraclitus-gpu --bench gpu_vs_cpu` no
/// hardware de destino — este número é da máquina onde foi medido, não uma
/// constante universal.
#[cfg(feature = "gpu")]
pub const GPU_MIN_VECTORS: usize = 8_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqdist_matches_manual() {
        let q = vec![1.0, 2.0];
        let v = vec![1.0, 2.0, 4.0, 6.0]; // row0 → 0; row1 → 3²+4² = 25
        assert_eq!(batch_sqdist_cpu(&q, &v, 2), vec![0.0, 25.0]);
    }

    #[test]
    fn topm_picks_nearest() {
        let q = vec![0.0];
        let v = vec![3.0, 1.0, 2.0, 0.5]; // sqdist: 9, 1, 4, 0.25
        let top = topm_cpu(&q, &v, 1, 2, 1e3);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].index, 3, "0.5 is nearest");
        assert_eq!(top[1].index, 1, "1.0 is next");
    }

    /// THE M20.3 GATE (ordinal invariance): sub-quantum jitter must not reorder
    /// the quantized Top-M.
    #[test]
    fn quantization_gives_ordinal_invariance() {
        let dim = 1;
        let query = vec![0.0f32];
        let vectors: Vec<f32> = (0..50u32).map(|i| i as f32 * 0.1).collect();
        let scale = 1e4;
        let a = topm_cpu(&query, &vectors, dim, 10, scale);
        let jittered: Vec<f32> = vectors.iter().map(|x| x + 1e-7).collect();
        let b = topm_cpu(&query, &jittered, dim, 10, scale);
        let ia: Vec<u32> = a.iter().map(|c| c.index).collect();
        let ib: Vec<u32> = b.iter().map(|c| c.index).collect();
        assert_eq!(ia, ib, "sub-quantum jitter must not reorder the Top-M");
        assert_eq!(
            ia,
            (0..10).collect::<Vec<u32>>(),
            "nearest are the smallest-norm rows"
        );
    }

    #[test]
    fn dispatch_falls_back_to_cpu() {
        let q = vec![0.0];
        let v = vec![2.0, 1.0, 3.0];
        assert_eq!(topm(&q, &v, 1, 2, 1e3), topm_cpu(&q, &v, 1, 2, 1e3));
    }

    #[test]
    fn wgsl_source_is_a_compute_shader() {
        assert!(PRODUCT_SQDIST_WGSL.contains("@compute"));
        assert!(PRODUCT_SQDIST_WGSL.contains("distances[row]"));
        assert!(PRODUCT_MANIFOLD_DIST_WGSL.contains("acosh_approx"));
        assert!(PRODUCT_MANIFOLD_DIST_WGSL.contains("acos(cosv)"));
    }

    /// Build well-separated product points so the quantized order is obvious,
    /// and check the CPU product metric ranks them by construction order.
    #[test]
    fn product_cpu_ranks_by_distance() {
        let sig = ProductSig::default();
        let dim = sig.a + sig.b + sig.c;
        let query = make_query(&sig);
        let n = 20usize;
        let mut vectors = Vec::with_capacity(n * dim);
        for i in 0..n {
            vectors.extend_from_slice(&make_point(&sig, i));
        }
        let top = topm_product_cpu(&query, &vectors, &sig, 5, 1e3);
        let idx: Vec<u32> = top.iter().map(|c| c.index).collect();
        assert_eq!(
            idx,
            vec![0, 1, 2, 3, 4],
            "nearest are the smallest-i points"
        );
    }

    pub(super) fn make_query(sig: &ProductSig) -> Vec<f32> {
        let mut q = vec![0.0f32; sig.a + sig.b + sig.c];
        q[sig.a] = 1.0; // unit sphere vector along axis 0
        q
    }

    /// Point i: hyperbolic part grows, sphere rotates, euclidean grows — all
    /// monotone in i, so the product distance is well-separated.
    pub(super) fn make_point(sig: &ProductSig, i: usize) -> Vec<f32> {
        let dim = sig.a + sig.b + sig.c;
        let mut p = vec![0.0f32; dim];
        let fi = i as f32;
        for slot in p.iter_mut().take(sig.a) {
            *slot = fi * 0.004;
        }
        let ang = fi * 0.02;
        p[sig.a] = ang.cos();
        if sig.b > 1 {
            p[sig.a + 1] = ang.sin();
        }
        for slot in p.iter_mut().skip(sig.a + sig.b).take(sig.c) {
            *slot = fi * 0.2;
        }
        p
    }
}

#[cfg(all(test, feature = "gpu"))]
mod gpu_tests {
    use super::*;

    /// M20.3.1a HARDWARE GATE (Euclidean): GPU Top-M == CPU reference.
    #[test]
    fn gpu_matches_cpu_on_hardware() {
        let dim = 8usize;
        let n = 200usize;
        let query = vec![0.0f32; dim];
        let mut vectors = Vec::with_capacity(n * dim);
        for i in 0..n {
            for _ in 0..dim {
                vectors.push(i as f32 * 0.5);
            }
        }
        let scale = 1e3;
        match topm_gpu(&query, &vectors, dim, 10, scale) {
            Some(gpu) => {
                assert_eq!(
                    gpu,
                    topm_cpu(&query, &vectors, dim, 10, scale),
                    "Euclidean GPU == CPU"
                );
                eprintln!(
                    "[M20.3.1a] Euclidean GPU validated: {} candidates == CPU",
                    gpu.len()
                );
            }
            None => eprintln!("[M20.3.1a] no GPU adapter; CPU fallback (skipped)"),
        }
    }

    /// M20.3.1b HARDWARE GATE (product manifold): the WGSL port of the product
    /// metric must rank identically to the f64 CPU reference on real hardware.
    #[test]
    fn product_gpu_matches_cpu_on_hardware() {
        let sig = ProductSig::default();
        let dim = sig.a + sig.b + sig.c;
        let query = tests::make_query(&sig);
        let n = 128usize;
        let mut vectors = Vec::with_capacity(n * dim);
        for i in 0..n {
            vectors.extend_from_slice(&tests::make_point(&sig, i));
        }
        let scale = 1e3;
        match topm_product_gpu(&query, &vectors, &sig, 12, scale) {
            Some(gpu) => {
                let cpu = topm_product_cpu(&query, &vectors, &sig, 12, scale);
                assert_eq!(
                    gpu, cpu,
                    "product-metric GPU Top-M must equal CPU reference"
                );
                eprintln!(
                    "[M20.3.1b] product-metric GPU validated on hardware: {} == CPU",
                    gpu.len()
                );
            }
            None => eprintln!("[M20.3.1b] no GPU adapter; CPU fallback (skipped)"),
        }
    }
}

#[cfg(all(test, feature = "gpu"))]
mod limiar_tests {
    use super::*;

    /// Regressao do defeito que a medicao expos: o `topm_product` tentava a GPU
    /// SEMPRE que a feature estava ligada, sem olhar ao tamanho. Numa colecao
    /// pequena isso e 5x mais lento -- e colecoes pequenas sao a maioria antes
    /// de haver volume. Abaixo do limiar tem de ficar na CPU.
    #[test]
    fn colecao_pequena_fica_na_cpu_e_da_o_mesmo_resultado() {
        let sig = ProductSig::default();
        let dim = sig.a + sig.b + sig.c;
        let n = 200; // muito abaixo de GPU_MIN_VECTORS

        let query: Vec<f32> = (0..dim).map(|i| (i as f32) * 0.001).collect();
        let vectors: Vec<f32> = (0..n * dim).map(|i| (i as f32) * 0.0001).collect();

        let via_dispatch = topm_product(&query, &vectors, &sig, 5, 10_000.0);
        let via_cpu = topm_product_cpu(&query, &vectors, &sig, 5, 10_000.0);
        assert_eq!(
            via_dispatch, via_cpu,
            "abaixo do limiar o despacho tem de ser exatamente o caminho CPU"
        );
    }

    /// O limiar tem de estar ACIMA da zona medida onde a GPU perde (1.000 =
    /// 0.19x) e nao tao alto que desperdice o ganho real. Verificado em tempo de
    /// COMPILACAO: se alguem mexer na constante para fora desta janela, o crate
    /// nem chega a compilar -- mais forte do que um teste que pode ser saltado.
    const _: () = assert!(
        GPU_MIN_VECTORS > 1_000,
        "a 1.000 vetores a GPU mede 0.19x -- o limiar nao pode incluir essa zona"
    );
    const _: () = assert!(
        GPU_MIN_VECTORS <= 50_000,
        "a 10.000 a GPU ja ganha 1.5x -- um limiar alto demais desperdica isso"
    );
}

// ============================================================================
// Auditoria recursiva 2026-09-05, vaga 2 (R59)
// ----------------------------------------------------------------------------
// As copias privadas da metrica (`dist_hyp_cpu`/`dist_sph_cpu`/`dist_euc_cpu`)
// diziam ser "1:1 with manifold::dist_*" sem que nada o verificasse -- e nao
// eram. Este modulo e a prova: enquanto ele existir, a copia nao pode voltar a
// divergir do `heraclitus_manifold` em silencio. APAGA-LO E A MUTACAO A EVITAR.
// ============================================================================
#[cfg(test)]
mod testes_equivalencia_manifold {
    use super::*;
    use heraclitus_core::ProductPoint;
    use heraclitus_manifold::{dist_euc, dist_hyp, dist_sph, ProductMetric, BALL_EPS};

    /// Gerador congruencial linear (Numerical Recipes). Deterministico e sem
    /// dependencia nova: o caso de teste tem de ser reproduzivel byte a byte.
    struct Lcg(u32);

    impl Lcg {
        fn passo(&mut self) -> u32 {
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            self.0
        }
        /// Uniforme em `[-amp, amp]`.
        fn uniforme(&mut self, amp: f32) -> f32 {
            let u = (self.passo() >> 8) as f32 / (1u32 << 24) as f32; // [0,1)
            (u * 2.0 - 1.0) * amp
        }
    }

    /// (a) mesma CLASSIFICACAO finito/nao-finito e (b) mesmo valor no caso
    /// finito. A classificacao e comparada por `is_finite` (e nao por igualdade)
    /// porque o manifold devolve NaN nalguns ramos onde nos devolvemos INFINITY:
    /// ambos significam "recusado". O que conta para o ranking -- o valor da
    /// recusa depois dos pesos -- e verificado a parte, em
    /// `product_dist_cpu_e_1_1_com_product_metric`.
    fn compara(componente: &str, i: usize, nosso: f64, manifold: f64) {
        assert_eq!(
            nosso.is_finite(),
            manifold.is_finite(),
            "[{componente} i={i}] classificacao divergente: copia do gpu = {nosso}, \
             heraclitus_manifold = {manifold}"
        );
        if nosso.is_finite() {
            // Tolerancia: o manifold dobra o clamp da bola em factores de escala
            // sobre os f32 crus, a copia materializa vectores f64 ja clampados.
            // Matematicamente identico, ultimos bits diferentes.
            assert!(
                (nosso - manifold).abs() <= 1e-9 * (1.0 + nosso.abs()),
                "[{componente} i={i}] valor divergente: copia do gpu = {nosso}, \
                 heraclitus_manifold = {manifold}"
            );
        }
    }

    #[test]
    fn cpu_do_gpu_e_1_1_com_o_manifold() {
        const C1: f64 = 1.0;
        const K2: f64 = 1.0;
        let sig = ProductSig::default();
        let mut rng = Lcg(0x5EED_1234);

        for i in 0..200usize {
            // Amplitude variavel: acima de ~0.31 a norma esperada de 32
            // coordenadas passa `max_norm`, portanto boa parte dos casos exerce
            // o clamp da bola de Poincare (o ramo onde as duas implementacoes
            // mais podem divergir).
            let amp = 0.05 + (i % 10) as f32 * 0.09;
            let hu: Vec<f32> = (0..sig.a).map(|_| rng.uniforme(amp)).collect();
            let mut hv: Vec<f32> = (0..sig.a).map(|_| rng.uniforme(amp)).collect();
            let mut su: Vec<f32> = (0..sig.b).map(|_| rng.uniforme(1.0)).collect();
            let mut sv: Vec<f32> = (0..sig.b).map(|_| rng.uniforme(1.0)).collect();
            let eu: Vec<f32> = (0..sig.c).map(|_| rng.uniforme(3.0)).collect();
            let mut ev: Vec<f32> = (0..sig.c).map(|_| rng.uniforme(3.0)).collect();

            // Casos-limite deterministas, um por iteracao.
            match i % 13 {
                1 => hv[i % sig.a] = f32::NAN,
                2 => sv[i % sig.b] = f32::NAN,
                3 => ev[i % sig.c] = f32::NAN,
                4 => hv[i % sig.a] = f32::INFINITY,
                5 => sv[i % sig.b] = f32::INFINITY,
                6 => ev[i % sig.c] = f32::INFINITY,
                7 => su = vec![0.0; sig.b], // vector nulo na esfera
                8 => sv = vec![0.0; sig.b],
                _ => {}
            }

            // BALL_EPS exacto (f64): `ProductSig::ball_eps` e f32 e
            // `1e-5f32 as f64 != BALL_EPS`, o que deslocaria o raio do clamp no
            // 13.o digito -- ruido que nada tem a ver com a equivalencia.
            compara(
                "hyp",
                i,
                dist_hyp_cpu(&hu, &hv, C1, BALL_EPS),
                dist_hyp(&hu, &hv, C1),
            );
            compara("sph", i, dist_sph_cpu(&su, &sv, K2), dist_sph(&su, &sv, K2));
            compara("euc", i, dist_euc_cpu(&eu, &ev), dist_euc(&eu, &ev));
        }
    }

    #[test]
    fn product_dist_cpu_e_1_1_com_product_metric() {
        let sig = ProductSig::default();
        let dim = sig.a + sig.b + sig.c;
        let metrica = ProductMetric::default();
        let mut rng = Lcg(0x0BAD_F00D);

        for i in 0..200usize {
            // Amplitude pequena na componente hiperbolica DE PROPOSITO: aqui o
            // `ball_eps` entra em f32 (via `ProductSig`) e o clamp seria a unica
            // fonte de divergencia; o clamp ja e exercido com o eps exacto em
            // `cpu_do_gpu_e_1_1_com_o_manifold`.
            let ponto = |rng: &mut Lcg| ProductPoint {
                hyp: (0..sig.a).map(|_| rng.uniforme(0.12)).collect(),
                sph: (0..sig.b).map(|_| rng.uniforme(1.0)).collect(),
                euc: (0..sig.c).map(|_| rng.uniforme(3.0)).collect(),
            };
            let q = ponto(&mut rng);
            let mut r = ponto(&mut rng);
            match i % 7 {
                1 => r.hyp[i % sig.a] = f32::NAN,
                2 => r.sph[i % sig.b] = f32::NAN,
                3 => r.euc[i % sig.c] = f32::NAN,
                _ => {}
            }

            let mut query = Vec::with_capacity(dim);
            query.extend_from_slice(&q.hyp);
            query.extend_from_slice(&q.sph);
            query.extend_from_slice(&q.euc);
            let mut linha = Vec::with_capacity(dim);
            linha.extend_from_slice(&r.hyp);
            linha.extend_from_slice(&r.sph);
            linha.extend_from_slice(&r.euc);

            let nosso = product_dist_cpu(&query, &linha, &sig)[0];
            let deles = metrica.dist(&q, &r);
            assert_eq!(
                nosso.is_infinite(),
                deles.is_infinite(),
                "[produto i={i}] recusa divergente: copia do gpu = {nosso}, \
                 ProductMetric::dist = {deles}"
            );
            if nosso.is_finite() {
                assert!(
                    (nosso - deles).abs() <= 1e-9 * (1.0 + nosso.abs()),
                    "[produto i={i}] valor divergente: copia do gpu = {nosso}, \
                     ProductMetric::dist = {deles}"
                );
            }
        }
    }
}

// ============================================================================
// Auditoria recursiva 2026-09-05, vaga 2 (R59) — recusa de candidatos
// incomparaveis (NaN/infinito) e de dimensoes diferentes.
// ============================================================================
#[cfg(test)]
mod testes_recusa {
    use super::*;
    use heraclitus_manifold::BALL_EPS;

    /// Consulta valida + duas linhas: uma comparavel e afastada, outra igual a
    /// consulta em tudo EXCEPTO um NaN numa coordenada hiperbolica -- assim so a
    /// componente hyp decide o ranking.
    fn cenario(sig: &ProductSig) -> (Vec<f32>, Vec<f32>) {
        let dim = sig.a + sig.b + sig.c;
        let mut query = vec![0.0f32; dim];
        query[0] = 0.10;
        query[sig.a] = 1.0; // esfera unitaria
        query[sig.a + sig.b] = 0.5;

        let mut boa = vec![0.0f32; dim];
        boa[0] = 0.40;
        boa[sig.a] = 1.0;
        boa[sig.a + sig.b] = 0.9;

        let mut envenenada = query.clone();
        envenenada[1] = f32::NAN;

        let mut vectors = Vec::with_capacity(2 * dim);
        vectors.extend_from_slice(&boa); // indice 0
        vectors.extend_from_slice(&envenenada); // indice 1
        (query, vectors)
    }

    /// Sem a guarda anti-NaN, `arg` = NaN, `NaN.max(1.0) == 1.0` em Rust e
    /// `acosh(1) = 0`: o vector envenenado ficava a distancia ZERO. Pior, uma
    /// distancia final NaN quantiza para 0 (`execute_op_quantize`), a chave
    /// MINIMA -- o envenenado ficava em PRIMEIRO lugar do Top-M e expulsava os
    /// vizinhos verdadeiros do oversample antes de o rescore poder arbitrar.
    #[test]
    fn nan_no_candidato_nao_fica_a_distancia_zero() {
        let sig = ProductSig::default();
        let (query, vectors) = cenario(&sig);

        let d = product_dist_cpu(&query, &vectors, &sig);
        assert!(d[0].is_finite(), "a linha comparavel tem distancia finita");
        assert!(
            d[1].is_infinite(),
            "candidato com NaN tem de ser recusado (infinito), nao {}",
            d[1]
        );

        let top = topm_product_cpu(&query, &vectors, &sig, 1, 1e6);
        assert_eq!(
            top[0].index, 0,
            "o Top-1 tem de ser a linha comparavel, nao a envenenada com NaN"
        );
    }

    /// Um peso a 0.0 ressuscitava o candidato recusado: `0.0 * inf = NaN`, e NaN
    /// quantiza para 0 (primeiro lugar). Por isso o nao-finito propaga-se ANTES
    /// de os pesos serem aplicados -- mesma politica de `ProductMetric::dist`.
    #[test]
    fn peso_a_zero_nao_ressuscita_o_candidato_recusado() {
        let sig = ProductSig {
            weights: [0.0, 1.0, 1.0],
            ..ProductSig::default()
        };
        let (query, vectors) = cenario(&sig);

        let d = product_dist_cpu(&query, &vectors, &sig);
        assert!(d[0].is_finite(), "a linha comparavel tem distancia finita");
        assert!(
            d[1].is_infinite(),
            "com peso hyp a 0.0 o candidato recusado tem de continuar infinito, nao {}",
            d[1]
        );

        let top = topm_product_cpu(&query, &vectors, &sig, 1, 1e6);
        assert_eq!(
            top[0].index, 0,
            "um peso a zero nao pode devolver o primeiro lugar ao candidato com NaN"
        );
    }

    /// O ramo que a API publica de hoje nao alcanca (`product_dist_cpu` fatia
    /// query e linha com os mesmos offsets), mas que a copia tem de manter para
    /// nao voltar a divergir do manifold quando alguem lhe mudar os chamadores.
    #[test]
    fn dist_de_comprimentos_diferentes_e_infinita() {
        let u = [0.1f32, 0.2, 0.3];
        for v in [&[][..], &[0.9f32][..], &[0.1f32, 0.2][..]] {
            assert!(
                dist_hyp_cpu(&u, v, 1.0, BALL_EPS).is_infinite(),
                "hyp: comprimentos {} vs {} sao incomparaveis",
                u.len(),
                v.len()
            );
            assert!(
                dist_sph_cpu(&u, v, 1.0).is_infinite(),
                "sph: comprimentos {} vs {} sao incomparaveis",
                u.len(),
                v.len()
            );
            assert!(
                dist_euc_cpu(&u, v).is_infinite(),
                "euc: comprimentos {} vs {} sao incomparaveis",
                u.len(),
                v.len()
            );
        }
    }

    /// A guarda de vazio tem de correr ANTES da recusa por comprimento: uma
    /// consulta parcial (so uma das componentes preenchida, como a que
    /// `engine::nearest` constroi) e legitima e nao contribui com as componentes
    /// que nao tem.
    #[test]
    fn consulta_parcial_continua_a_nao_contribuir() {
        assert_eq!(dist_hyp_cpu(&[], &[0.1, 0.2], 1.0, BALL_EPS), 0.0);
        assert_eq!(dist_sph_cpu(&[], &[0.1, 0.2], 1.0), 0.0);
        assert_eq!(dist_euc_cpu(&[], &[0.1, 0.2]), 0.0);
    }

    /// A recusa tem de ser INFINITY e nao NaN. A diferenca nao e cosmetica: o
    /// `execute_op_quantize` leva NaN a 0 (a chave MINIMA, primeiro lugar do
    /// Top-M) e INFINITY a `u64::MAX` (ultimo lugar). Um `is_finite()` nao
    /// distingue os dois -- por isso este teste usa `is_infinite()`.
    #[test]
    fn componente_com_nan_e_recusada_com_infinito_e_nao_com_nan() {
        let u = [0.1f32, 0.2, 0.3];
        for (nome, v) in [
            ("NaN", [0.1f32, f32::NAN, 0.3]),
            ("infinito", [0.1f32, f32::INFINITY, 0.3]),
        ] {
            assert!(
                dist_hyp_cpu(&u, &v, 1.0, BALL_EPS).is_infinite(),
                "hyp com {nome} tem de dar INFINITY, deu {}",
                dist_hyp_cpu(&u, &v, 1.0, BALL_EPS)
            );
            assert!(
                dist_sph_cpu(&u, &v, 1.0).is_infinite(),
                "sph com {nome} tem de dar INFINITY, deu {}",
                dist_sph_cpu(&u, &v, 1.0)
            );
            assert!(
                dist_euc_cpu(&u, &v).is_infinite(),
                "euc com {nome} tem de dar INFINITY, deu {}",
                dist_euc_cpu(&u, &v)
            );
        }
    }
}
