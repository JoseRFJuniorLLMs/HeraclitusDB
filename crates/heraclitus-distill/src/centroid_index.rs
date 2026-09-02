//! Atalho de pesquisa para o agrupamento do distiller: uma VP-tree sobre os
//! centróides, com sobreposição *dirty* para os que se mexeram desde a última
//! construção.
//!
//! # A promessa
//!
//! [`CentroidIndex::select`] devolve **exactamente** o que a varredura
//! exaustiva de `Distiller::cluster_com` devolveria: o mesmo índice de
//! agregado, com o mesmo desempate. Não é "aproximadamente o mesmo" nem "o
//! mesmo na prática" — o teste de equivalência compara membros e centróides bit
//! a bit contra o oráculo, e essa é a única razão pela qual a versão exaustiva
//! continua no código.
//!
//! # Como se mantém a promessa
//!
//! A árvore guarda uma **cópia** do centróide de cada agregado no momento em
//! que foi construída. Um agregado que receba um ponto novo passa a ter o
//! centróide desactualizado na árvore, e a partir daí a cópia mente. Em vez de
//! reconstruir a árvore a cada inserção — o que anularia o atalho — marca-se o
//! agregado como *dirty* ([`CentroidIndex::mark_changed`]) e ele sai da
//! pesquisa em árvore para passar a ser varrido linearmente com o centróide
//! **actual**. A união dos dois conjuntos é, por construção, o conjunto
//! completo de agregados com os valores actuais; nenhum fica de fora, nenhum é
//! consultado com um valor velho.
//!
//! Um agregado acabado de nascer também é *dirty*: não está de todo na árvore,
//! e sem a marca ficaria invisível até à reconstrução seguinte — o agrupamento
//! divergiria do exaustivo em silêncio, que é precisamente a falha que este
//! módulo não pode ter.
//!
//! # Poda e pontuação são coisas separadas
//!
//! A poda da árvore trabalha na distância hiperbólica `dh`; a decisão final usa
//! a mesma expressão da varredura exaustiva, `(hyp_weight * dh * dh).sqrt()`.
//! São deliberadamente separadas: `dh` é monótona na pontuação, portanto serve
//! para podar, mas duas distâncias diferentes podem arredondar para a mesma
//! pontuação. Se o desempate fosse feito em `dh`, esse caso escolheria um
//! índice diferente do oráculo. Só a pontuação decide quem ganha.

use heraclitus_manifold::dist_hyp;

/// `(pontuação, índice do agregado)` — a forma que a varredura exaustiva
/// devolve, e portanto a que este índice tem de devolver também.
type Candidato = (f64, usize);

/// Aplica o critério de vitória a um candidato, actualizando o melhor até
/// agora. Passa-se como objecto-função porque a travessia da árvore é recursiva
/// e o critério tem de ser exactamente o mesmo em todos os ramos.
type Propor<'a> = &'a mut dyn FnMut(f64, usize, &mut Option<Candidato>);

/// Contadores de uma corrida de agrupamento. Existem para o teste de
/// equivalência poder afirmar que o atalho foi de facto exercitado — um índice
/// que nunca é consultado passaria trivialmente em qualquer comparação com a
/// referência.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SearchStats {
    /// Distâncias calculadas pela varredura exaustiva (`usar_indice = false`).
    pub brute_force_distances: u64,
    /// Consultas servidas pelo caminho indexado.
    pub indexed_queries: u64,
    /// Distâncias calculadas a **responder** a consultas indexadas: nós da
    /// árvore visitados mais a sobreposição dirty.
    pub indexed_distances: u64,
    /// Distâncias gastas a **construir** árvores. Contabilizadas à parte para o
    /// custo da construção não se esconder dentro do custo da consulta.
    pub build_distances: u64,
    /// Reconstruções da árvore.
    pub rebuilds: u64,
}

/// Número mínimo de agregados a partir do qual vale a pena indexar. Abaixo
/// disto a varredura linear é mais barata do que construir a árvore.
const MIN_PARA_INDEXAR: usize = 16;

struct No {
    /// Posição do ponto-vantagem em `pontos`.
    vantagem: usize,
    /// Mediana das distâncias ao ponto-vantagem: separa dentro de fora.
    raio: f64,
    dentro: Option<Box<No>>,
    fora: Option<Box<No>>,
}

/// VP-tree sobre uma fotografia dos centróides.
struct Arvore {
    /// `(índice do agregado, cópia do centróide na altura da construção)`.
    pontos: Vec<(usize, Vec<f32>)>,
    raiz: Option<Box<No>>,
}

impl Arvore {
    fn construir(
        clusters: &[super::Cluster],
        curvature: f64,
        stats: &mut SearchStats,
    ) -> Option<Self> {
        if clusters.is_empty() {
            return None;
        }
        let pontos: Vec<(usize, Vec<f32>)> = clusters
            .iter()
            .enumerate()
            .map(|(indice, c)| (indice, c.centroid_hyp.centroid().to_vec()))
            .collect();
        let mut posicoes: Vec<usize> = (0..pontos.len()).collect();
        let raiz = construir_no(&pontos, &mut posicoes, curvature, stats);
        Some(Self { pontos, raiz })
    }
}

fn construir_no(
    pontos: &[(usize, Vec<f32>)],
    posicoes: &mut [usize],
    curvature: f64,
    stats: &mut SearchStats,
) -> Option<Box<No>> {
    if posicoes.is_empty() {
        return None;
    }
    // O ponto-vantagem é o primeiro do fatiamento. A escolha é determinística
    // de propósito: a árvore não pode depender de aleatoriedade, senão duas
    // corridas sobre os mesmos dados podariam de maneira diferente e o teste de
    // equivalência passaria a ser um sorteio.
    let vantagem = posicoes[0];
    let resto = &mut posicoes[1..];
    if resto.is_empty() {
        return Some(Box::new(No {
            vantagem,
            raio: 0.0,
            dentro: None,
            fora: None,
        }));
    }

    let referencia = &pontos[vantagem].1;
    let mut medidas: Vec<(f64, usize)> = resto
        .iter()
        .map(|&p| {
            stats.build_distances += 1;
            (dist_hyp(referencia, &pontos[p].1, curvature), p)
        })
        .collect();
    medidas.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let meio = medidas.len() / 2;
    let raio = medidas[meio].0;
    let (dentro_fatia, fora_fatia) = medidas.split_at(meio);
    let mut dentro: Vec<usize> = dentro_fatia.iter().map(|(_, p)| *p).collect();
    let mut fora: Vec<usize> = fora_fatia.iter().map(|(_, p)| *p).collect();

    Some(Box::new(No {
        vantagem,
        raio,
        dentro: construir_no(pontos, &mut dentro, curvature, stats),
        fora: construir_no(pontos, &mut fora, curvature, stats),
    }))
}

/// Índice de centróides com sobreposição dirty.
#[derive(Default)]
pub struct CentroidIndex {
    arvore: Option<Arvore>,
    /// `sujo[i] = true` ⇒ o agregado `i` não pode ser respondido pela árvore.
    sujo: Vec<bool>,
    sujos_contados: usize,
}

impl CentroidIndex {
    /// Marca o agregado `indice` como desactualizado na árvore. Tem de ser
    /// chamado sempre que um centróide muda **e** sempre que nasce um agregado
    /// novo — ver a nota do módulo sobre porque as duas coisas são a mesma.
    pub fn mark_changed(&mut self, indice: usize) {
        if indice >= self.sujo.len() {
            self.sujo.resize(indice + 1, false);
        }
        if !self.sujo[indice] {
            self.sujo[indice] = true;
            self.sujos_contados += 1;
        }
    }

    fn esta_sujo(&self, indice: usize) -> bool {
        self.sujo.get(indice).copied().unwrap_or(true)
    }

    /// Reconstrói quando metade dos agregados já está suja: abaixo disso a
    /// varredura da sobreposição ainda é mais barata do que reconstruir.
    fn deve_reconstruir(&self, total: usize) -> bool {
        if total < MIN_PARA_INDEXAR {
            return false;
        }
        // Um agregado nascido depois da construção NÃO obriga a reconstruir: já
        // está coberto pela sobreposição, porque `esta_sujo` trata como sujo
        // tudo o que caia fora da fotografia. Reconstruir a cada nascimento
        // gastaria uma árvore inteira por ponto na fase de arranque.
        match &self.arvore {
            None => true,
            Some(_) => self.sujos_contados * 2 >= total,
        }
    }

    /// Devolve `Some((pontuação, índice))` do agregado mais próximo dentro do
    /// limiar, ou `None` — exactamente como a varredura exaustiva.
    pub fn select(
        &mut self,
        clusters: &[super::Cluster],
        sonda: &[f32],
        curvature: f64,
        hyp_weight: f64,
        threshold: f64,
        stats: &mut SearchStats,
    ) -> Option<(f64, usize)> {
        stats.indexed_queries += 1;

        if self.deve_reconstruir(clusters.len()) {
            self.arvore = Arvore::construir(clusters, curvature, stats);
            if self.arvore.is_some() {
                stats.rebuilds += 1;
                self.sujo.clear();
                self.sujo.resize(clusters.len(), false);
                self.sujos_contados = 0;
            }
        }

        let pontuar = |dh: f64| (hyp_weight * dh * dh).sqrt();
        let mut melhor: Option<(f64, usize)> = None;

        // `min_by` devolve o PRIMEIRO mínimo entre iguais, e a varredura
        // exaustiva itera por índice crescente. Reproduz-se isso ordenando por
        // (pontuação, índice) — a travessia da árvore não visita por ordem de
        // índice, portanto o desempate tem de ser explícito.
        let propor = |pontuacao: f64, indice: usize, melhor: &mut Option<(f64, usize)>| {
            if pontuacao >= threshold {
                return;
            }
            match melhor {
                None => *melhor = Some((pontuacao, indice)),
                Some((melhor_p, melhor_i)) => {
                    let ordem = pontuacao
                        .total_cmp(melhor_p)
                        .then_with(|| indice.cmp(melhor_i));
                    if ordem == std::cmp::Ordering::Less {
                        *melhor = Some((pontuacao, indice));
                    }
                }
            }
        };

        // Sobreposição dirty: centróides actuais, varridos linearmente.
        let indexado = self.arvore.is_some();
        for (indice, cluster) in clusters.iter().enumerate() {
            if indexado && !self.esta_sujo(indice) {
                continue;
            }
            stats.indexed_distances += 1;
            let dh = dist_hyp(cluster.centroid_hyp.centroid(), sonda, curvature);
            propor(pontuar(dh), indice, &mut melhor);
        }

        // Árvore: centróides não sujos, cuja cópia continua válida.
        if let Some(arvore) = &self.arvore {
            // Raio de poda em espaço `dh`. A pontuação é monótona em `dh`, logo
            // um `dh` que já não bate o melhor actual nunca produzirá pontuação
            // melhor. Um raio generoso apenas visita a mais; nunca exclui um
            // candidato que pudesse ganhar.
            let escala = hyp_weight.sqrt();
            let limite_dh = if escala > 0.0 {
                threshold / escala
            } else {
                f64::INFINITY
            };
            let mut tau = match melhor {
                Some((p, _)) if escala > 0.0 => (p / escala).min(limite_dh),
                _ => limite_dh,
            };
            if let Some(raiz) = &arvore.raiz {
                percorrer(
                    raiz,
                    arvore,
                    self,
                    sonda,
                    curvature,
                    &mut tau,
                    stats,
                    &mut |dh, indice, melhor| propor(pontuar(dh), indice, melhor),
                    &mut melhor,
                    escala,
                );
            }
        }

        melhor
    }
}

#[allow(clippy::too_many_arguments)]
fn percorrer(
    no: &No,
    arvore: &Arvore,
    indice_estado: &CentroidIndex,
    sonda: &[f32],
    curvature: f64,
    tau: &mut f64,
    stats: &mut SearchStats,
    propor: Propor<'_>,
    melhor: &mut Option<Candidato>,
    escala: f64,
) {
    let (indice_cluster, centroide) = &arvore.pontos[no.vantagem];
    stats.indexed_distances += 1;
    let d = dist_hyp(centroide, sonda, curvature);

    // Um agregado sujo já foi tratado pela sobreposição com o centróide actual;
    // a cópia da árvore está velha e não pode concorrer. Mas a sua posição
    // continua a ser um pivô geométrico válido para a poda dos filhos, por isso
    // a travessia não pára aqui.
    if !indice_estado.esta_sujo(*indice_cluster) {
        propor(d, *indice_cluster, melhor);
        if let Some((p, _)) = melhor {
            if escala > 0.0 {
                *tau = tau.min(*p / escala);
            }
        }
    }

    if d < no.raio {
        if let Some(dentro) = &no.dentro {
            percorrer(
                dentro,
                arvore,
                indice_estado,
                sonda,
                curvature,
                tau,
                stats,
                propor,
                melhor,
                escala,
            );
        }
        if d + *tau >= no.raio {
            if let Some(fora) = &no.fora {
                percorrer(
                    fora,
                    arvore,
                    indice_estado,
                    sonda,
                    curvature,
                    tau,
                    stats,
                    propor,
                    melhor,
                    escala,
                );
            }
        }
    } else {
        if let Some(fora) = &no.fora {
            percorrer(
                fora,
                arvore,
                indice_estado,
                sonda,
                curvature,
                tau,
                stats,
                propor,
                melhor,
                escala,
            );
        }
        if d - *tau <= no.raio {
            if let Some(dentro) = &no.dentro {
                percorrer(
                    dentro,
                    arvore,
                    indice_estado,
                    sonda,
                    curvature,
                    tau,
                    stats,
                    propor,
                    melhor,
                    escala,
                );
            }
        }
    }
}
