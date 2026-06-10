import argparse
import asyncio
import os
import sys
from typing import Dict

# Adjust path if executed from root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api_fuzzer.core.parser import OpenAPIParser
from api_fuzzer.core.runner import AttackSimulatorRunner
from api_fuzzer.core.reporter import VulnerabilityReporter

def parse_headers(header_list: list) -> Dict[str, str]:
    """Parses key-value headers from input CLI list."""
    headers = {}
    if not header_list:
        return headers
    for item in header_list:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers

async def async_main():
    parser = argparse.ArgumentParser(
        description="Fuzzer e Simulador de Ataques em APIs (Rate Limiting, IDOR, Logic/Input Breaking)"
    )
    parser.add_argument(
        "--spec",
        required=True,
        help="Caminho para o arquivo local JSON ou YAML da documentação OpenAPI/Swagger"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="URL base da API alvo (ex: http://localhost:8000)"
    )
    parser.add_argument(
        "--html",
        default="report.html",
        help="Caminho de saída para o relatório HTML (padrão: report.html)"
    )
    parser.add_argument(
        "--json",
        default="report.json",
        help="Caminho de saída para o relatório JSON (padrão: report.json)"
    )
    parser.add_argument(
        "--header",
        action="append",
        help="Cabeçalhos HTTP adicionais para enviar (ex: 'Authorization: Bearer <TOKEN>'). Pode ser repetido."
    )

    args = parser.parse_args()

    print("=" * 60)
    print("      SIMULADOR DE ATAQUES & FUZZER DE API (AppSec)     ")
    print("=" * 60)
    print(f"[+] Carregando especificação: {args.spec}")
    
    try:
        spec_parser = OpenAPIParser.from_file(args.spec)
        endpoints = spec_parser.get_endpoints()
        print(f"[+] Total de endpoints mapeados: {len(endpoints)}")
        for endpoint in endpoints:
            print(f"  - {endpoint.method} {endpoint.path}")
    except Exception as e:
        print(f"[-] Erro ao ler documentação OpenAPI: {str(e)}")
        sys.exit(1)

    headers = parse_headers(args.header)

    print(f"[+] Target definido: {args.target}")
    print(f"[+] Iniciando simulações de ataque...")
    
    runner = AttackSimulatorRunner(
        target_url=args.target,
        endpoints=endpoints,
        extra_headers=headers
    )
    
    findings = await runner.run_all()
    
    print("=" * 60)
    print(f"[+] Varredura concluída. Vulnerabilidades encontradas: {len(findings)}")
    print("=" * 60)
    
    reporter = VulnerabilityReporter(target=args.target, findings=findings)
    reporter.save_json(args.json)
    reporter.save_html(args.html)

def main():
    # Helper to resolve windows event loop policy issue for async playwright
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
