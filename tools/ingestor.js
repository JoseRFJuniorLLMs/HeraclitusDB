const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const { parse } = require('csv-parse');
const fs = require('fs');
const path = require('path');
const iconv = require('iconv-lite');

// Load protobuf
const PROTO_PATH = path.resolve(__dirname, '../crates/heraclitus-proto/proto/heraclitus.proto');
const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
});
const proto = grpc.loadPackageDefinition(packageDefinition).heraclitus.v1;

// Configuration
const SERVER_URL = process.argv.includes('--server') ? process.argv[process.argv.indexOf('--server') + 1] : '127.0.0.1:7474';
const DATA_DIR = process.argv.includes('--dir') ? process.argv[process.argv.indexOf('--dir') + 1] : 'D:/dados-governo';
const BATCH_SIZE = 500;

console.log('╔══════════════════════════════════════════════════════════╗');
console.log('║  HeraclitusDB — Ingestor de Dados Governamentais (Node) ║');
console.log('╚══════════════════════════════════════════════════════════╝');
console.log(`  Servidor  : ${SERVER_URL}`);
console.log(`  Dados     : ${DATA_DIR}`);

// Fix URL for grpc (strip http:// if present)
const grpcUrl = SERVER_URL.replace(/^http:\/\//, '');
const client = new proto.Heraclitus(grpcUrl, grpc.credentials.createInsecure());

function sanitize(str) {
    if (!str) return '';
    return str.trim().replace(/\0/g, '').replace(/\r/g, '');
}

function sanitizeValor(str) {
    if (!str) return '';
    return str.replace(/"/g, '').replace(/\r/g, '').trim();
}

async function sendBatch(agentId, batch) {
    return new Promise((resolve) => {
        let ok = 0;
        let pending = batch.length;
        if (pending === 0) return resolve(0);

        for (const event of batch) {
            client.Append(event, (err, response) => {
                if (!err) ok++;
                else console.warn(`    gRPC append error: ${err.message}`);
                
                pending--;
                if (pending === 0) resolve(ok);
            });
        }
    });
}

async function processDespesas(csvPath, dirName) {
    console.log(`  📄 Lendo Despesas: ${csvPath}`);
    let total = 0;
    let batch = [];
    
    return new Promise((resolve, reject) => {
        const parser = parse({
            delimiter: ';',
            columns: true,
            skip_empty_lines: true
        });

        parser.on('readable', async function() {
            let record;
            while ((record = parser.read()) !== null) {
                // Find column keys
                const keys = Object.keys(record);
                const k = (search) => keys.find(x => x.toUpperCase().includes(search));
                
                const attrs = {
                    ano_mes: sanitize(record[k('ANO')]),
                    cod_orgao_superior: sanitize(record[k('CÓDIGO ÓRGÃO SUPERIOR') || k('COD')]),
                    orgao_superior: sanitize(record[k('NOME ÓRGÃO SUPERIOR') || k('NOME ÓRGÃO SUP')]),
                    cod_orgao: sanitize(record[k('CÓDIGO ÓRGÃO SUBORDINADO')]),
                    orgao: sanitize(record[k('NOME ÓRGÃO SUBORDINADO')]),
                    funcao: sanitize(record[k('NOME FUNÇÃO')]),
                    subfuncao: sanitize(record[k('NOME SUBFUNÇÃO') || k('NOME SUBFUN')]),
                    programa: sanitize(record[k('NOME PROGRAMA ORÇAMENTÁRIO') || k('PROGRAMA')]),
                    acao: sanitize(record[k('NOME AÇÃO')]),
                    categoria_economica: sanitize(record[k('NOME CATEGORIA ECONÔMICA') || k('CATEGORIA')]),
                    grupo_despesa: sanitize(record[k('NOME GRUPO DE DESPESA') || k('GRUPO')]),
                    elemento_despesa: sanitize(record[k('NOME ELEMENTO DE DESPESA') || k('ELEMENTO')]),
                    modalidade: sanitize(record[k('MODALIDADE DA DESPESA')]),
                    valor_empenhado: sanitizeValor(record[k('VALOR EMPENHADO')]),
                    valor_liquidado: sanitizeValor(record[k('VALOR LIQUIDADO')]),
                    valor_pago: sanitizeValor(record[k('VALOR PAGO')]),
                    uf: sanitize(record[k('UF')]),
                    municipio: sanitize(record[k('MUNICÍPIO') || k('MUNICIPIO')]),
                    dataset: dirName
                };

                const contentStr = `${attrs.ano_mes} | ${attrs.orgao} | Pago: ${attrs.valor_pago}`;
                
                batch.push({
                    agent_id: 'ingestor-despesas',
                    session_id: '',
                    kind: 'Despesa',
                    content: Buffer.from(contentStr, 'utf8'),
                    attrs: attrs,
                    parents: []
                });

                if (batch.length >= BATCH_SIZE) {
                    parser.pause();
                    const b = [...batch];
                    batch = [];
                    total += await sendBatch('ingestor-despesas', b);
                    if (total % 10000 === 0) console.log(`    ... ${total} despesas ingeridas`);
                    parser.resume();
                }
            }
        });

        parser.on('error', reject);
        parser.on('end', async () => {
            if (batch.length > 0) {
                total += await sendBatch('ingestor-despesas', batch);
            }
            console.log(`  Total despesas: ${total}`);
            resolve(total);
        });

        fs.createReadStream(csvPath)
            .pipe(iconv.decodeStream('win1252'))
            .pipe(parser);
    });
}

async function processServidores(dir, dirName) {
    let total = 0;
    const files = fs.readdirSync(dir);
    
    // Cadastro
    const cadFile = files.find(f => f.toUpperCase().endsWith('.CSV') && f.toUpperCase().includes('CADASTRO'));
    if (cadFile) {
        console.log(`  📄 Lendo Cadastro: ${cadFile}`);
        total += await processGeneric(path.join(dir, cadFile), dirName, 'Servidor', 'ingestor-servidores', record => {
            const keys = Object.keys(record);
            const k = (search) => keys.find(x => x.toUpperCase().includes(search));
            return {
                id_servidor: sanitize(record[k('ID_SERVIDOR') || k('ID_SER')]),
                cargo: sanitize(record[k('DESCRICAO_CARGO') || k('CARGO')]),
                orgao: sanitize(record[k('ORG_LOTACAO')]),
                uf_exercicio: sanitize(record[k('UF_EXERCICIO') || k('UF')]),
                dataset: dirName
            };
        });
    }

    // Remuneracao
    const remFile = files.find(f => f.toUpperCase().endsWith('.CSV') && f.toUpperCase().includes('REMUNERACAO'));
    if (remFile) {
        console.log(`  📄 Lendo Remuneração: ${remFile}`);
        total += await processGeneric(path.join(dir, remFile), dirName, 'Remuneracao', 'ingestor-remuneracao', record => {
            const keys = Object.keys(record);
            const k = (search) => keys.find(x => x.toUpperCase().includes(search));
            return {
                id_servidor: sanitize(record[k('ID_SERVIDOR') || k('ID_SER')]),
                remuneracao_basica: sanitizeValor(record[k('REMUNERACAO_BASICA_BRUTA') || k('REMUNERACAO')]),
                total_rendimentos: sanitizeValor(record[k('TOTAL_DE_RENDIMENTOS_LIQUIDOS') || k('TOTAL')]),
                dataset: dirName
            };
        });
    }

    return total;
}

async function processGeneric(csvPath, dirName, kind, agentId, attrExtractor) {
    let total = 0;
    let batch = [];
    
    return new Promise((resolve, reject) => {
        const parser = parse({ delimiter: ';', columns: true, skip_empty_lines: true });

        parser.on('readable', async function() {
            let record;
            while ((record = parser.read()) !== null) {
                let attrs = attrExtractor ? attrExtractor(record) : {};
                if (!attrExtractor) {
                    for (const [k, v] of Object.entries(record)) {
                        if (k) attrs[k.toLowerCase().replace(/ /g, '_')] = sanitize(v);
                    }
                    attrs.dataset = dirName;
                }

                batch.push({
                    agent_id: agentId,
                    session_id: '',
                    kind: kind,
                    content: Buffer.from(`${kind} record`, 'utf8'),
                    attrs: attrs,
                    parents: []
                });

                if (batch.length >= BATCH_SIZE) {
                    parser.pause();
                    const b = [...batch];
                    batch = [];
                    total += await sendBatch(agentId, b);
                    if (total % 10000 === 0) console.log(`    ... ${total} ${kind} ingeridos`);
                    parser.resume();
                }
            }
        });

        parser.on('error', reject);
        parser.on('end', async () => {
            if (batch.length > 0) total += await sendBatch(agentId, batch);
            resolve(total);
        });

        fs.createReadStream(csvPath).pipe(iconv.decodeStream('win1252')).pipe(parser);
    });
}

async function main() {
    let totalEventos = 0;
    let subdirs = fs.readdirSync(DATA_DIR, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => dirent.name)
        .sort();

    for (const subdir of subdirs) {
        console.log(`─────────────────────────────────────────`);
        console.log(`📂 Processando: ${subdir}`);
        const fullPath = path.join(DATA_DIR, subdir);
        const nomeUp = subdir.toUpperCase();

        try {
            if (nomeUp.includes('_DESPESAS') && !nomeUp.includes('(1)')) {
                const csvs = fs.readdirSync(fullPath).filter(f => f.toUpperCase().endsWith('.CSV') && !f.toUpperCase().includes('(1)'));
                if (csvs.length > 0) totalEventos += await processDespesas(path.join(fullPath, csvs[0]), subdir);
            } 
            else if (nomeUp.includes('_SERVIDORES_SIAPE')) {
                totalEventos += await processServidores(fullPath, subdir);
            }
            else if (nomeUp.includes('_COMPRAS')) {
                const csvs = fs.readdirSync(fullPath).filter(f => f.toUpperCase().endsWith('.CSV'));
                for(const csv of csvs) {
                    console.log(`  📄 Lendo: ${csv}`);
                    totalEventos += await processGeneric(path.join(fullPath, csv), subdir, 'Contrato', 'ingestor-compras', null);
                }
            }
            else if (nomeUp.includes('_TRANSFERENCIAS') && !nomeUp.includes('(1)')) {
                const csvs = fs.readdirSync(fullPath).filter(f => f.toUpperCase().endsWith('.CSV'));
                if (csvs.length > 0) totalEventos += await processGeneric(path.join(fullPath, csvs[0]), subdir, 'Transferencia', 'ingestor-transferencias', null);
            }
            else if (nomeUp.includes('_LICITACOES')) {
                const csvs = fs.readdirSync(fullPath).filter(f => f.toUpperCase().endsWith('.CSV'));
                for(const csv of csvs) {
                    console.log(`  📄 Lendo: ${csv}`);
                    totalEventos += await processGeneric(path.join(fullPath, csv), subdir, 'Licitacao', 'ingestor-licitacoes', null);
                }
            }
            else if (nomeUp.includes('APOSENTADOS') || nomeUp.includes('PENSIONISTAS') || nomeUp.includes('BACEN')) {
                const csvs = fs.readdirSync(fullPath).filter(f => f.toUpperCase().endsWith('.CSV'));
                for(const csv of csvs) {
                    console.log(`  📄 Lendo: ${csv}`);
                    totalEventos += await processGeneric(path.join(fullPath, csv), subdir, 'Servidor', 'ingestor-generico', null);
                }
            }
        } catch (e) {
            console.error(`  ✗ Erro em '${subdir}': ${e.message}`);
        }
    }

    console.log(`═════════════════════════════════════════════════════════`);
    console.log(`✅ CARGA CONCLUÍDA`);
    console.log(`   Total de eventos : ${totalEventos}`);
    
    // Call snapshot
    client.Snapshot({}, (err, resp) => {
        if (!err) console.log(`  Snapshot selado em LSN ${resp.lsn} ✓`);
        else console.warn(`  Aviso no snapshot: ${err.message}`);
    });
}

main().catch(console.error);
