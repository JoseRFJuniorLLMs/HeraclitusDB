//! Regras de aresta para o HeraclitusDB — dados abertos do governo federal
//!
//! Cada `EdgeRule` descreve como criar uma aresta no grafo a partir de dois
//! eventos já ingeridos: "do evento de kind `from_kind`, use o attr `from_attr`
//! para encontrar eventos de kind `to_kind` com `to_attr` igual, e crie a aresta
//! `relation` entre eles".
//!
//! Arestas são idempotentes: o edge_id é determinístico (de|rel|para).

/// Uma regra de aresta entre dois kinds de eventos.
#[derive(Debug, Clone)]
pub struct EdgeRule {
    /// Kind do evento de origem (ex: "Remuneracao")
    pub from_kind: &'static str,
    /// Attr do evento de origem que contém a FK (ex: "id_servidor")
    pub from_attr: &'static str,
    /// Kind do evento de destino (ex: "Servidor")
    pub to_kind: &'static str,
    /// Attr do evento de destino que contém a PK (ex: "id_servidor")
    pub to_attr: &'static str,
    /// Nome da relação no grafo
    pub relation: &'static str,
    /// Descrição legível para logs
    pub descricao: &'static str,
}

/// Todas as regras de aresta para os dados governamentais.
/// Ordem: primeiro as mais simples (1:1 via Id_SERVIDOR_PORTAL),
/// depois as de compras/licitações, depois as de transferências.
pub fn todas_as_regras() -> Vec<EdgeRule> {
    vec![
        // ─────────────────────────────────────────────────────────────────────
        // PESSOAL — âncora: Id_SERVIDOR_PORTAL
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "Remuneracao",
            from_attr: "id_servidor",
            to_kind: "Servidor",
            to_attr: "id_servidor",
            relation: "TEM_REMUNERACAO",
            descricao: "Remuneracao → Servidor (SIAPE)",
        },
        EdgeRule {
            from_kind: "Afastamento",
            from_attr: "id_servidor",
            to_kind: "Servidor",
            to_attr: "id_servidor",
            relation: "TEVE_AFASTAMENTO",
            descricao: "Afastamento → Servidor (SIAPE/BACEN)",
        },
        EdgeRule {
            from_kind: "ObservacaoServidor",
            from_attr: "id_servidor",
            to_kind: "Servidor",
            to_attr: "id_servidor",
            relation: "TEM_OBSERVACAO",
            descricao: "ObservacaoServidor → Servidor",
        },
        // Aposentados e Pensionistas têm a mesma estrutura de Id_SERVIDOR_PORTAL
        EdgeRule {
            from_kind: "Aposentado", // Remuneracao dentro do dataset Aposentado
            from_attr: "id_servidor",
            to_kind: "Aposentado", // Cadastro
            to_attr: "id_servidor",
            relation: "TEM_REMUNERACAO_APOSENTADO",
            descricao: "Remuneracao Aposentado → Cadastro Aposentado",
        },
        EdgeRule {
            from_kind: "Pensionista",
            from_attr: "id_servidor",
            to_kind: "Pensionista",
            to_attr: "id_servidor",
            relation: "TEM_REMUNERACAO_PENSIONISTA",
            descricao: "Remuneracao Pensionista → Cadastro Pensionista",
        },
        EdgeRule {
            from_kind: "ServidorBACEN",
            from_attr: "id_servidor",
            to_kind: "ServidorBACEN",
            to_attr: "id_servidor",
            relation: "TEM_REMUNERACAO_BACEN",
            descricao: "Remuneracao BACEN → Cadastro BACEN",
        },
        // ─────────────────────────────────────────────────────────────────────
        // COMPRAS — âncora: Numero_Contrato
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "ItemContrato",
            from_attr: "numero_contrato",
            to_kind: "Contrato",
            to_attr: "numero_contrato",
            relation: "ITEM_DE_CONTRATO",
            descricao: "ItemContrato → Contrato",
        },
        EdgeRule {
            from_kind: "TermoAditivo",
            from_attr: "numero_contrato",
            to_kind: "Contrato",
            to_attr: "numero_contrato",
            relation: "ADITOU_CONTRATO",
            descricao: "TermoAditivo → Contrato",
        },
        EdgeRule {
            from_kind: "Apostilamento",
            from_attr: "numero_contrato",
            to_kind: "Contrato",
            to_attr: "numero_contrato",
            relation: "APOSTILOU_CONTRATO",
            descricao: "Apostilamento → Contrato",
        },
        // ─────────────────────────────────────────────────────────────────────
        // LICITAÇÕES — âncora: Numero_Licitacao
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "Contrato",
            from_attr: "numero_licitacao", // campo-ponte adicionado na correção
            to_kind: "Licitacao",
            to_attr: "numero_licitacao",
            relation: "ORIGINOU_CONTRATO",
            descricao: "Contrato ← Licitacao (via numero_licitacao)",
        },
        EdgeRule {
            from_kind: "ItemLicitacao",
            from_attr: "numero_licitacao",
            to_kind: "Licitacao",
            to_attr: "numero_licitacao",
            relation: "ITEM_DE_LICITACAO",
            descricao: "ItemLicitacao → Licitacao",
        },
        EdgeRule {
            from_kind: "ParticipanteLicitacao",
            from_attr: "numero_licitacao",
            to_kind: "Licitacao",
            to_attr: "numero_licitacao",
            relation: "PARTICIPOU_DE_LICITACAO",
            descricao: "ParticipanteLicitacao → Licitacao",
        },
        EdgeRule {
            from_kind: "EmpenhoLicitacao",
            from_attr: "numero_licitacao",
            to_kind: "Licitacao",
            to_attr: "numero_licitacao",
            relation: "EMPENHO_DE_LICITACAO",
            descricao: "EmpenhoLicitacao → Licitacao",
        },
        // ─────────────────────────────────────────────────────────────────────
        // ITEM — âncora cruzado: Codigo_Item_Compra liga Licitação ↔ Contrato
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "ItemLicitacao",
            from_attr: "codigo_item_compra",
            to_kind: "ItemContrato",
            to_attr: "codigo_item_compra",
            relation: "MESMO_ITEM",
            descricao: "ItemLicitacao ↔ ItemContrato (mesmo codigo_item_compra)",
        },
        // ─────────────────────────────────────────────────────────────────────
        // COMPLIANCE E INVESTIGAÇÃO (CEIS, CNEP, CEPIM, CEAF, CPGF)
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "PunicaoCEIS",
            from_attr: "cnpj_sancionado",
            to_kind: "Contrato",
            to_attr: "codigo_contratado",
            relation: "EMPRESA_PUNIDA_CONTRATO",
            descricao: "PunicaoCEIS → Contrato (via CNPJ)",
        },
        EdgeRule {
            from_kind: "PunicaoCNEP",
            from_attr: "cnpj_sancionado",
            to_kind: "Contrato",
            to_attr: "codigo_contratado",
            relation: "EMPRESA_PUNIDA_CONTRATO",
            descricao: "PunicaoCNEP → Contrato (via CNPJ)",
        },
        EdgeRule {
            from_kind: "ImpedimentoCEPIM",
            from_attr: "cnpj_entidade",
            to_kind: "Transferencia",
            to_attr: "codigo_favorecido",
            relation: "ONG_IMPEDIDA_TRANSFERENCIA",
            descricao: "ImpedimentoCEPIM → Transferencia (via CNPJ)",
        },
        // ⚠️ NÃO ligar CEAF→Servidor nem CPGF→Servidor por igualdade exata do
        // CPF mascarado: dois CPFs com os mesmos 6 dígitos visíveis colidem e
        // geram arestas falsas. Essas ligações foram movidas para
        // `datasets::resolve` (entity resolution por fragmento + nome + órgão,
        // com score de confiança). Ver MESMA_PESSOA_EXPULSO / MESMA_PESSOA_CARTAO.
        EdgeRule {
            from_kind: "GastoCartaoCPGF",
            from_attr: "cnpj_favorecido",
            to_kind: "Contrato",
            to_attr: "codigo_contratado",
            relation: "MICRO_COMPRA_DE_CONTRATADO",
            descricao: "GastoCartaoCPGF → Contrato (via CNPJ Favorecido)",
        },
        // ─────────────────────────────────────────────────────────────────────
        // QSA (Receita) — âncora: cnpj_basico (raiz de 8 díg do CNPJ)
        // ─────────────────────────────────────────────────────────────────────
        EdgeRule {
            from_kind: "Socio",
            from_attr: "cnpj_basico",
            to_kind: "Contrato",
            to_attr: "cnpj_basico_contratado",
            relation: "SOCIO_DE_FORNECEDOR",
            descricao: "Socio → Contrato (via raiz do CNPJ) — quem é dono da empresa contratada",
        },
    ]
}
