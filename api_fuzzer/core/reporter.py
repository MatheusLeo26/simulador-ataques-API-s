import json
import os
from typing import Any, Dict, List
from jinja2 import Template

class VulnerabilityReporter:
    def __init__(self, target: str, findings: List[Dict[str, Any]]):
        self.target = target
        self.findings = findings

    def save_json(self, filepath: str) -> None:
        """Saves scan results to a structured JSON file."""
        report = {
            "target": self.target,
            "total_vulnerabilities": len(self.findings),
            "findings": self.findings
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"[+] Relatório JSON salvo com sucesso em: {filepath}")

    def save_html(self, filepath: str) -> None:
        """Saves a rich and interactive HTML report with a modern dark theme and animations."""
        
        # HTML Template using Jinja2
        html_template = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança - Fuzzer de API</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: #151c2c;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-primary: #8b5cf6;
            --accent-secondary: #3b82f6;
            --severity-high: #ef4444;
            --severity-medium: #f59e0b;
            --severity-low: #10b981;
            --border-color: #243049;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }

        header {
            margin-bottom: 2.5rem;
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.1) 0%, rgba(59, 130, 246, 0.1) 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            backdrop-filter: blur(10px);
        }

        .header-title {
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(90deg, #a78bfa, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .target-url {
            font-size: 1rem;
            color: var(--text-secondary);
            font-family: monospace;
            background: rgba(0, 0, 0, 0.2);
            padding: 0.4rem 0.8rem;
            border-radius: 6px;
            display: inline-block;
            margin-top: 0.5rem;
            border: 1px solid var(--border-color);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .stat-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
        }

        .stat-val {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 0.5rem;
        }

        .section-title {
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .findings-list {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .finding-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: border-color 0.2s;
        }

        .finding-card::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 5px;
        }

        .finding-card.severity-alto::before { background-color: var(--severity-high); }
        .finding-card.severity-médio::before { background-color: var(--severity-medium); }
        .finding-card.severity-baixo::before { background-color: var(--severity-low); }

        .finding-card:hover {
            border-color: rgba(139, 92, 246, 0.4);
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .finding-title {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .badge {
            padding: 0.25rem 0.6rem;
            border-radius: 5px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge.severity-alto { background-color: rgba(239, 68, 68, 0.15); color: var(--severity-high); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge.severity-médio { background-color: rgba(245, 158, 11, 0.15); color: var(--severity-medium); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge.severity-baixo { background-color: rgba(16, 185, 129, 0.15); color: var(--severity-low); border: 1px solid rgba(16, 185, 129, 0.3); }

        .finding-endpoint {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.2);
            padding: 0.3rem 0.6rem;
            border-radius: 4px;
            color: #38bdf8;
            font-size: 0.9rem;
            display: inline-block;
            margin-bottom: 0.8rem;
            border: 1px solid rgba(56, 189, 248, 0.2);
        }

        .finding-desc {
            color: var(--text-primary);
            margin-bottom: 1rem;
        }

        .finding-details {
            background-color: rgba(0, 0, 0, 0.25);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            padding: 1rem;
            margin-top: 1rem;
        }

        .detail-row {
            margin-bottom: 0.5rem;
            font-size: 0.9rem;
        }

        .detail-row:last-child {
            margin-bottom: 0;
        }

        .detail-label {
            font-weight: 600;
            color: var(--text-secondary);
        }

        .code-block {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.4);
            padding: 0.5rem;
            border-radius: 4px;
            color: #fb7185;
            display: block;
            margin-top: 0.25rem;
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.03);
        }

        .recommendation {
            margin-top: 0.8rem;
            border-top: 1px dashed var(--border-color);
            padding-top: 0.8rem;
            font-size: 0.9rem;
            color: #a78bfa;
        }
    </style>
</head>
<body>

    <header>
        <div class="header-title">Relatório de Vulnerabilidades de API</div>
        <p>Varredura de segurança automatizada simulando ataques de lógica, Rate Limiting e IDOR.</p>
        <div class="target-url">Alvo: {{ target }}</div>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-val" style="color: #ef4444;">{{ high_count }}</div>
            <div class="stat-label">Alto Impacto</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #f59e0b;">{{ medium_count }}</div>
            <div class="stat-label">Médio Impacto</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #10b981;">{{ low_count }}</div>
            <div class="stat-label">Baixo Impacto</div>
        </div>
        <div class="stat-card">
            <div class="stat-val">{{ findings|length }}</div>
            <div class="stat-label">Total Vulnerabilidades</div>
        </div>
    </div>

    <div class="section-title">
        Vulnerabilidades Encontradas
    </div>

    <div class="findings-list">
        {% if findings|length == 0 %}
            <div class="finding-card" style="text-align: center; padding: 3rem;">
                <p style="color: var(--text-secondary); font-size: 1.1rem;">Nenhuma vulnerabilidade foi detectada durante o fuzzing.</p>
            </div>
        {% else %}
            {% for finding in findings %}
                <div class="finding-card severity-{{ finding.severity|lower }}">
                    <div class="finding-header">
                        <div class="finding-title">{{ finding.module }}</div>
                        <span class="badge severity-{{ finding.severity|lower }}">{{ finding.severity }}</span>
                    </div>
                    <div class="finding-endpoint">{{ finding.endpoint }}</div>
                    <div class="finding-desc">{{ finding.description }}</div>
                    
                    <div class="finding-details">
                        {% if finding.details.parameter %}
                            <div class="detail-row">
                                <span class="detail-label">Parâmetro Focado:</span> <code>{{ finding.details.parameter }}</code>
                            </div>
                        {% endif %}
                        {% if finding.details.payload_used %}
                            <div class="detail-row">
                                <span class="detail-label">Payload Utilizado:</span> 
                                <span class="code-block">{{ finding.details.payload_used }}</span>
                            </div>
                        {% endif %}
                        {% if finding.details.response_status %}
                            <div class="detail-row">
                                <span class="detail-label">Status HTTP da Resposta:</span> <code>{{ finding.details.response_status }}</code>
                            </div>
                        {% endif %}
                        {% if finding.details.response_snippet %}
                            <div class="detail-row">
                                <span class="detail-label">Recorte da Resposta:</span>
                                <span class="code-block">{{ finding.details.response_snippet }}</span>
                            </div>
                        {% endif %}
                        {% if finding.details.recommendation %}
                            <div class="recommendation">
                                <strong>Recomendação de Correção:</strong> {{ finding.details.recommendation }}
                            </div>
                        {% endif %}
                    </div>
                </div>
            {% endfor %}
        {% endif %}
    </div>

</body>
</html>
        """
        
        high_count = sum(1 for f in self.findings if f["severity"].lower() == "alto")
        medium_count = sum(1 for f in self.findings if f["severity"].lower() == "médio")
        low_count = sum(1 for f in self.findings if f["severity"].lower() == "baixo")

        t = Template(html_template)
        rendered = t.render(
            target=self.target,
            findings=self.findings,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(rendered)
        print(f"[+] Relatório HTML premium salvo com sucesso em: {filepath}")
