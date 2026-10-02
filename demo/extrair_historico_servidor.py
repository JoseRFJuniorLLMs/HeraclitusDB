# -*- coding: utf-8 -*-
"""
Extrator histórico de remuneração e cadastro de servidor público federal.
Download automatizado via Portal da Transparência (Playwright/Chrome) com extração em streaming/memória.
"""
import os
import sys
import csv
import json
import time
import zipfile
import io
import argparse

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from playwright.sync_api import sync_playwright

PORTAL_URL = "https://portaldatransparencia.gov.br/download-de-dados/servidores"
PROFILE_DIR = r"D:\tmp\pw-portal-profile"
TEMP_DIR = r"D:\tmp\dl_temp"

def parse_args():
    parser = argparse.ArgumentParser(description="Extrair histórico de remuneração de servidor.")
    parser.add_argument("--query", default="ANDERSON VIEIRA DE LIMA", help="Nome do servidor")
    parser.add_argument("--sid", default="2865092", help="Id do servidor no portal")
    parser.add_argument("--de", default="201301", help="Mês inicial (YYYYMM)")
    parser.add_argument("--ate", default="202607", help="Mês final (YYYYMM)")
    parser.add_argument("--json-out", default=r"D:\DEV\BOOK\anderson_historico_completo.json")
    parser.add_argument("--md-out", default=r"D:\DEV\BOOK\anderson.md")
    return parser.parse_args()

def carregar_existentes(json_path):
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"servidor": {}, "remuneracoes": {}, "cadastros": {}}

def salvar_dados(dados, json_path, md_path):
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    gerar_markdown(dados, md_path)
    # Também salva cópia em D:\dados-governo\anderson.md
    cópia_dados_gov = r"D:\dados-governo\anderson.md"
    try:
        gerar_markdown(dados, cópia_dados_gov)
    except Exception:
        pass

def gerar_markdown(dados, md_path):
    remuns = dados.get("remuneracoes", {})
    cadastros = dados.get("cadastros", {})
    serv = dados.get("servidor", {})

    # Ordenar por ano e mês
    meses_ordenados = sorted(remuns.keys())

    linhas_md = [
        f"# Histórico Salarial Completo: {serv.get('NOME', 'ANDERSON VIEIRA DE LIMA')}\n",
        "## 1. Identificação e Dados Funcionais\n",
        "| Campo | Detalhe |",
        "| :--- | :--- |",
        f"| **Nome** | **{serv.get('NOME', 'ANDERSON VIEIRA DE LIMA')}** |",
        f"| **CPF** | `{serv.get('CPF', '***.498.902-**')}` |",
        f"| **Matrícula SIAPE** | `{serv.get('MATRICULA', '178****')}` |",
        f"| **Id Servidor Portal** | `{serv.get('Id_SERVIDOR_PORTAL', '2865092')}` |",
        f"| **Órgão** | {serv.get('ORG_LOTACAO', 'Instituto Nacional do Seguro Social')} |",
        f"| **Cargo Mais Recente** | {serv.get('DESCRICAO_CARGO', 'TECNICO DO SEGURO SOCIAL')} |",
        f"| **Função / Atividade** | {serv.get('ATIVIDADE', 'GERENTE DE AGENCIA')} |",
        f"| **Lotação Mais Recente** | {serv.get('UORG_LOTACAO', 'APS B EIRUNEPE')} |",
        f"| **Total de Meses Localizados** | **{len(meses_ordenados)} meses** |",
        "\n---\n",
        "## 2. Histórico de Salários Mês a Mês (Portal da Transparência)\n",
        "| Período | Bruto (R$) | Eventuais / Férias (R$) | Previdência / PSS (R$) | IRRF (R$) | Demais Ded. (R$) | Líquido (R$) | Indenizações (R$) | Total Estimado (R$) |",
        "| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]

    for m in meses_ordenados:
        r = remuns[m]
        ano = m[:4]
        mes = m[4:]
        
        def g(col_name):
            for k, v in r.items():
                if col_name.lower() in k.lower():
                    return v
            return "0,00"

        bruto = g("básica bruta") or g("basica bruta") or "0,00"
        ferias = g("férias") or g("ferias") or "0,00"
        eventuais = g("outras remunera") or "0,00"
        pss = g("pss") or "0,00"
        irrf = g("irrf") or "0,00"
        demais = g("demais dedu") or "0,00"
        liquido = g("após dedu") or g("apos dedu") or g("líquida") or "0,00"
        indeniz = g("total de verbas") or g("verbas indenizat") or "0,00"

        # Calcular soma de eventuais + ferias se houver
        event_str = f"R$ {eventuais}" if eventuais not in ("0,00", "0") else (f"R$ {ferias}" if ferias not in ("0,00", "0") else "R$ 0,00")

        # Total aproximado recebido
        try:
            liq_val = float(liquido.replace(".", "").replace(",", ".")) if liquido else 0.0
            ind_val = float(indeniz.replace(".", "").replace(",", ".")) if indeniz else 0.0
            tot_str = f"R$ {liq_val + ind_val:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        except Exception:
            tot_str = f"R$ {liquido}"

        linhas_md.append(
            f"| **{mes}/{ano}** | R$ {bruto} | {event_str} | R$ {pss} | R$ {irrf} | R$ {demais} | **R$ {liquido}** | R$ {indeniz} | **{tot_str}** |"
        )

    linhas_md.append("\n---\n")
    linhas_md.append("## 3. Fontes e Metadados\n")
    linhas_md.append("- **Repositório oficial:** [Portal da Transparência do Governo Federal](https://portaldatransparencia.gov.br/)")
    linhas_md.append("- **Conjunto de Dados:** Servidores Públicos do Poder Executivo Federal (SIAPE)")
    linhas_md.append(f"- **Última atualização:** {time.strftime('%d/%m/%Y %H:%M:%S')}")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas_md))

def extrair_do_zip(zip_path, query, sid, mes, dados):
    achou = False
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for fname in zf.namelist():
                if "Remuneracao" in fname:
                    with zf.open(fname) as f:
                        reader = csv.reader(io.TextIOWrapper(f, encoding="latin1", errors="replace"), delimiter=";")
                        try:
                            header = next(reader)
                        except StopIteration:
                            continue
                        for row in reader:
                            if any(sid == col or query in col.upper() for col in row):
                                row_dict = dict(zip(header, row))
                                dados["remuneracoes"][mes] = row_dict
                                if not dados.get("servidor"):
                                    dados["servidor"]["NOME"] = row_dict.get("NOME")
                                    dados["servidor"]["CPF"] = row_dict.get("CPF")
                                    dados["servidor"]["Id_SERVIDOR_PORTAL"] = row_dict.get("Id_SERVIDOR_PORTAL")
                                achou = True
                                break
                elif "Cadastro" in fname:
                    with zf.open(fname) as f:
                        reader = csv.reader(io.TextIOWrapper(f, encoding="latin1", errors="replace"), delimiter=";")
                        try:
                            header = next(reader)
                        except StopIteration:
                            continue
                        for row in reader:
                            if any(sid == col or query in col.upper() for col in row):
                                row_dict = dict(zip(header, row))
                                dados["cadastros"][mes] = row_dict
                                if "DESCRICAO_CARGO" in row_dict and row_dict["DESCRICAO_CARGO"].strip() and row_dict["DESCRICAO_CARGO"] != "Sem informaç":
                                    dados["servidor"]["DESCRICAO_CARGO"] = row_dict["DESCRICAO_CARGO"]
                                if "ATIVIDADE" in row_dict and row_dict["ATIVIDADE"].strip() and row_dict["ATIVIDADE"] != "Sem informaç":
                                    dados["servidor"]["ATIVIDADE"] = row_dict["ATIVIDADE"]
                                if "UORG_LOTACAO" in row_dict and row_dict["UORG_LOTACAO"].strip():
                                    dados["servidor"]["UORG_LOTACAO"] = row_dict["UORG_LOTACAO"]
                                if "ORG_LOTACAO" in row_dict and row_dict["ORG_LOTACAO"].strip():
                                    dados["servidor"]["ORG_LOTACAO"] = row_dict["ORG_LOTACAO"]
                                if "MATRICULA" in row_dict and row_dict["MATRICULA"].strip():
                                    dados["servidor"]["MATRICULA"] = row_dict["MATRICULA"]
                                achou = True
    except Exception as e:
        print(f"  Erro ao ler zip {zip_path}: {e}")
    return achou

def main():
    args = parse_args()
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)

    dados = carregar_existentes(args.json_out)

    # 1. Carregar meses que já temos localmente em D:\dados-governo
    pastas_locais = {
        "202601": r"D:\dados-governo\202601_Servidores_SIAPE",
        "202602": r"D:\dados-governo\202602_Servidores_SIAPE",
        "202603": r"D:\dados-governo\202603_Servidores_SIAPE",
        "202604": r"D:\dados-governo\202604_Servidores_SIAPE",
    }
    for m, p in pastas_locais.items():
        if m not in dados["remuneracoes"] and os.path.exists(p):
            rem_file = os.path.join(p, f"{m}_Remuneracao.csv")
            cad_file = os.path.join(p, f"{m}_Cadastro.csv")
            if os.path.exists(rem_file):
                with open(rem_file, "r", encoding="latin1") as f:
                    rdr = csv.reader(f, delimiter=";")
                    hdr = next(rdr)
                    for r in rdr:
                        if args.sid in r or args.query in " ".join(r).upper():
                            dados["remuneracoes"][m] = dict(zip(hdr, r))
                            break
            if os.path.exists(cad_file):
                with open(cad_file, "r", encoding="latin1") as f:
                    rdr = csv.reader(f, delimiter=";")
                    hdr = next(rdr)
                    for r in rdr:
                        if args.sid in r or args.query in " ".join(r).upper():
                            dados["cadastros"][m] = dict(zip(hdr, r))
                            break

    # Montar lista de todos os meses disponíveis
    de_y, de_m = int(args.de[:4]), int(args.de[4:6])
    ate_y, ate_m = int(args.ate[:4]), int(args.ate[4:6])
    todos_meses = []
    y, m = de_y, de_m
    while (y, m) <= (ate_y, ate_m):
        todos_meses.append(f"{y:04d}{m:02d}")
        m += 1
        if m > 12:
            m = 1
            y += 1

    faltantes = [m for m in todos_meses if m not in dados["remuneracoes"]]
    print(f"Total meses solicitados: {len(todos_meses)}")
    print(f"Meses já catalogados:   {len(dados['remuneracoes'])}")
    print(f"Meses a baixar:         {len(faltantes)}")

    if not faltantes:
        print("Todos os meses já estão processados!")
        salvar_dados(dados, args.json_out, args.md_out)
        return

    salvar_dados(dados, args.json_out, args.md_out)

    print("\nIniciando navegador Chrome via Playwright...")
    with sync_playwright() as pw:
        ctx = pw.chromium.launch_persistent_context(
            PROFILE_DIR, channel="chrome", headless=False, accept_downloads=True,
            args=["--disable-blink-features=AutomationControlled"]
        )
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.goto(PORTAL_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(2000)

        for i, mes in enumerate(faltantes, 1):
            url = f"https://portaldatransparencia.gov.br/download-de-dados/servidores/{mes}_Servidores_SIAPE"
            zip_dest = os.path.join(TEMP_DIR, f"{mes}_Servidores_SIAPE.zip")
            print(f"[{i}/{len(faltantes)}] Processando {mes}...")
            
            sucesso = False
            if os.path.exists(zip_dest) and zipfile.is_zipfile(zip_dest):
                sucesso = True
            else:
                for tentativa in range(2):
                    try:
                        with page.expect_download(timeout=60000) as di:
                            page.evaluate(
                                f"document.getElementById('link').href = '{url}'; document.getElementById('btn').click();"
                            )
                        d = di.value
                        d.save_as(zip_dest)
                        sucesso = True
                        break
                    except Exception as e:
                        print(f"  Tentativa {tentativa+1} falhou para {mes}: {e}")
                        page.wait_for_timeout(3000)

            if sucesso and os.path.exists(zip_dest):
                sz_mb = os.path.getsize(zip_dest) / 1024 / 1024
                print(f"  Download concluído ({sz_mb:.1f} MB). Extraindo servidor...")
                achou = extrair_do_zip(zip_dest, args.query, args.sid, mes, dados)
                # Salvar progresso a cada mês imediatamente
                salvar_dados(dados, args.json_out, args.md_out)
                if achou:
                    print(f"  [OK] {mes}: Registro encontrado e salvo!")
                else:
                    print(f"  [AVISO] {mes}: Servidor nao localizado neste mes.")
                
                # Remover ZIP temporário para não estourar o disco
                try:
                    os.remove(zip_dest)
                except Exception:
                    pass
            else:
                print(f"  [ERRO] Falha definitiva no download de {mes}.")

        ctx.close()

    print("\nProcesso concluído!")
    salvar_dados(dados, args.json_out, args.md_out)
    print(f"Resultados finais salvos em:\n  JSON: {args.json_out}\n  MD:   {args.md_out}")

if __name__ == "__main__":
    main()
