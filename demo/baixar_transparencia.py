# Desenvolvedor: Jose R F Junior
# web2ajax@gmail.com
# joseribamar.junior@inss.gov.br

r"""Downloader em LOTE do Portal da Transparencia (fura o AWS WAF / CAPTCHA).

O portal usa AWS WAF com CAPTCHA interativo ("Let's confirm you are human").
Nao da' para resolver por script — precisa de UM toque humano. A estrategia:

  * Chrome REAL via Playwright (channel=chrome), modo STEALTH (esconde a flag de
    automacao; senao a AWS endurece/repete o CAPTCHA).
  * Perfil PERSISTENTE (--profile): resolve-se o CAPTCHA UMA vez, o cookie
    aws-waf-token fica guardado no perfil e os downloads seguintes nao pedem mais.
  * Download NATIVO do Chrome (anchor <a download>), com fingerprint + cookies
    certos -> o WAF deixa passar.

USO (Python 3.12, onde o playwright esta' instalado):
  py -3.12 demo/baixar_transparencia.py --de 202401 --ate 202412 \
      --datasets contratos despesas

Na 1a vez: abre o Chrome, RESOLVA o CAPTCHA (botao "Begin" + puzzle). Assim que
o site abrir, o script comeca a baixar sozinho. Ficheiros ja' existentes sao
saltados (retoma de onde parou).
"""
import argparse
import os
import time
import zipfile

PORTAL = "https://portaldatransparencia.gov.br/download-de-dados"

DATASETS = {
    "contratos":     ("contratos", "Contratos"),
    "licitacoes":    ("licitacoes", "Licitacoes"),
    "despesas":      ("despesas/execucao-pagamento", "Despesas_Execucao_Pagamento"),
    "cpgf":          ("cpgf", "CPGF"),
    "viagens":       ("viagens", "Viagens"),
    "convenios":     ("convenios", "Convenios"),
    "servidores":    ("servidores/SIAPE", "Servidores_SIAPE"),
    "bolsa-familia": ("bolsa-familia-pagamentos", "BolsaFamilia_Pagamentos"),
}

STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['pt-BR','pt','en']});
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
window.chrome = window.chrome || {runtime: {}};
"""


def meses(de, ate):
    y, m = int(de[:4]), int(de[4:6])
    yf, mf = int(ate[:4]), int(ate[4:6])
    out = []
    while (y, m) <= (yf, mf):
        out.append(f"{y:04d}{m:02d}")
        m += 1
        if m > 12:
            m, y = 1, y + 1
    return out


def _parece_challenge(page):
    try:
        txt = page.evaluate(
            "() => (document.body ? document.body.innerText : '')").lower()
    except Exception:
        return True
    return ("confirm you are human" in txt or "human verification" in txt
            or "security check" in txt or txt.strip() == "")


def _esperar_solve(page, espera):
    """Bloqueia ate o utilizador resolver o CAPTCHA (ou auto-passar)."""
    print("\n  >>> RESOLVA o CAPTCHA na janela do Chrome (botao 'Begin' + puzzle).")
    print("  >>> Assim que o site abrir, o download comeca sozinho.\n")
    t0 = time.time()
    while time.time() - t0 < espera:
        if not _parece_challenge(page):
            return time.time() - t0
        page.wait_for_timeout(2000)
    raise RuntimeError("CAPTCHA nao resolvido a tempo.")


def baixar_lote(alvos, raw_dir, profile_dir, espera, dl_timeout_s):
    from playwright.sync_api import sync_playwright

    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(profile_dir, exist_ok=True)
    pw = sync_playwright().start()
    ctx = pw.chromium.launch_persistent_context(
        profile_dir, channel="chrome", headless=False, accept_downloads=True,
        args=["--disable-blink-features=AutomationControlled", "--start-maximized"],
        ignore_default_args=["--enable-automation"],
        no_viewport=True,
    )
    ctx.add_init_script(STEALTH_JS)
    page = ctx.pages[0] if ctx.pages else ctx.new_page()

    seg0 = DATASETS[alvos[0][0]][0].split("/")[0]
    print("A abrir o Chrome (perfil persistente)...")
    page.goto(f"{PORTAL}/{seg0}", wait_until="domcontentloaded", timeout=60000)
    page.wait_for_timeout(2500)
    if _parece_challenge(page):
        dt = _esperar_solve(page, espera)
        print(f"  CAPTCHA resolvido apos {dt:.0f}s. A baixar...\n")
    else:
        print("  Sessao ja' valida (perfil guardado). A baixar...\n")

    ok = skip = fail = 0
    tot = 0
    for ds, mes in alvos:
        seg, suf = DATASETS[ds]
        dest = os.path.join(raw_dir, f"{mes}_{suf}.zip")
        if os.path.exists(dest) and zipfile.is_zipfile(dest):
            print(f"  [skip] {os.path.basename(dest)}")
            skip += 1
            continue
        url = f"{PORTAL}/{seg}/{mes}"
        try:
            with page.expect_download(timeout=dl_timeout_s * 1000) as di:
                page.evaluate(
                    "(u) => { const a=document.createElement('a'); a.href=u;"
                    " a.download=''; document.body.appendChild(a); a.click(); }",
                    url)
            d = di.value
            d.save_as(dest)
            if not zipfile.is_zipfile(dest):
                # provavelmente caiu o CAPTCHA de novo -> pede solve e repete 1x
                if os.path.exists(dest):
                    os.remove(dest)
                raise RuntimeError("resposta nao e' ZIP (CAPTCHA expirou?)")
            n = os.path.getsize(dest)
            tot += n
            ok += 1
            print(f"  [ok]   {os.path.basename(dest)}  ({n/1e6:.1f} MB)")
        except Exception as e:
            fail += 1
            print(f"  [FALHA] {ds} {mes} — {str(e)[:90]}")
            # se a sessao expirou, da' chance de re-resolver
            if _parece_challenge(page):
                try:
                    _esperar_solve(page, espera)
                except Exception:
                    break

    ctx.close()
    pw.stop()
    return ok, skip, fail, tot


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="Download em lote do Portal (browser+CAPTCHA)")
    ap.add_argument("--de", default="202401")
    ap.add_argument("--ate", default="202401")
    ap.add_argument("--datasets", nargs="+", default=["contratos", "despesas"],
                    choices=list(DATASETS))
    ap.add_argument("--raw-dir", default=os.path.join(here, "data", "raw"))
    ap.add_argument("--profile", default=r"D:\tmp\pw-portal-profile",
                    help="perfil Chrome persistente (guarda o token do WAF)")
    ap.add_argument("--espera", type=int, default=300, help="seg. p/ resolver o CAPTCHA")
    ap.add_argument("--dl-timeout", type=int, default=900)
    args = ap.parse_args()

    periodos = meses(args.de, args.ate)
    alvos = [(ds, mes) for ds in args.datasets for mes in periodos]
    print(f"== Download: {len(args.datasets)} dataset(s) x {len(periodos)} mes(es) "
          f"= {len(alvos)} ficheiro(s) -> {args.raw_dir} ==")
    ok, skip, fail, tot = baixar_lote(alvos, args.raw_dir, args.profile,
                                      args.espera, args.dl_timeout)
    print(f"\n== Concluido: {ok} baixados ({tot/1e6:.1f} MB), "
          f"{skip} ja existiam, {fail} falharam ==")


if __name__ == "__main__":
    main()
