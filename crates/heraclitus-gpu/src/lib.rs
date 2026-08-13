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
//!   a 1:1 port of `heraclitus_manifold::ProductMetric::dist` (GPU in f32; CPU
//!   reference in f64; the quantization absorbs the f32/f64 gap).
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

/// Poincaré-ball geodesic distance (curvature -c). 1:1 with `manifold::dist_hyp`.
fn dist_hyp_cpu(u: &[f32], v: &[f32], c: f64, ball_eps: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
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
    (1.0 / c.sqrt()) * arg.max(1.0).acosh()
}

/// Spherical geodesic distance (radius 1/sqrt(k2)). 1:1 with `manifold::dist_sph`.
fn dist_sph_cpu(u: &[f32], v: &[f32], k2: f64) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    let to64 = |x: &[f32]| -> Vec<f64> { x.iter().map(|&z| z as f64).collect() };
    let (u, v) = (to64(u), to64(v));
    let (nu, nv) = (norm64(&u), norm64(&v));
    if nu == 0.0 || nv == 0.0 {
        return 0.0;
    }
    let dotp: f64 = u.iter().zip(&v).map(|(a, b)| a * b).sum();
    let cos = (dotp / (nu * nv)).clamp(-1.0, 1.0);
    cos.acos() / k2.sqrt()
}

/// Euclidean distance. 1:1 with `manifold::dist_euc`.
fn dist_euc_cpu(u: &[f32], v: &[f32]) -> f64 {
    if u.is_empty() {
        return 0.0;
    }
    u.iter()
        .zip(v)
        .map(|(a, b)| ((a - b) as f64) * ((a - b) as f64))
        .sum::<f64>()
        .sqrt()
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
    if dim == 0 || query.len() != dim || vectors.is_empty() || vectors.len() % dim != 0 {
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
    if dim == 0 || query.len() != dim || vectors.is_empty() || vectors.len() % dim != 0 {
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
    if let Some(r) = topm_product_gpu(query, vectors, sig, m, scale) {
        return r;
    }
    topm_product_cpu(query, vectors, sig, m, scale)
}

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
