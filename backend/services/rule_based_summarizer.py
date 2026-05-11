from models.schemas import AnalyzeResponse, Finding, InputType, RiskLevel


# ── helpers ───────────────────────────────────────────────────────────────────

def _score_to_risk(score: float) -> RiskLevel:
    if score >= 9.0:
        return RiskLevel.critical
    if score >= 7.0:
        return RiskLevel.high
    if score >= 4.0:
        return RiskLevel.medium
    if score > 0.0:
        return RiskLevel.low
    return RiskLevel.clean


# ── por tipo de input ─────────────────────────────────────────────────────────

def _analyze_ip(query: str, raw_data: dict) -> dict:
    findings: list[Finding] = []
    recommendations: list[str] = []
    score = 0.0

    # --- VirusTotal ---
    vt = raw_data.get("virustotal", {})
    malicious_vt = vt.get("malicious", 0) or 0
    suspicious_vt = vt.get("suspicious", 0) or 0
    harmless_vt = vt.get("harmless", 0) or 0
    total_vt = malicious_vt + suspicious_vt + harmless_vt
    country = vt.get("country", "N/A")
    as_owner = vt.get("as_owner", "N/A")
    reputation = vt.get("reputation")

    if total_vt > 0:
        vt_ratio = (malicious_vt + suspicious_vt) / total_vt
        score = max(score, round(vt_ratio * 10, 1))

    if malicious_vt > 0 or suspicious_vt > 0:
        findings.append(Finding(
            title="Detecções no VirusTotal",
            description=(
                f"{malicious_vt} engines classificaram como malicioso e "
                f"{suspicious_vt} como suspeito de {total_vt} engines consultadas. "
                f"País: {country} | AS: {as_owner}."
                + (f" Reputação: {reputation}." if reputation is not None else "")
            ),
            source="VirusTotal",
        ))
        recommendations.append("Bloquear o IP no firewall perimetral imediatamente.")
    elif total_vt > 0:
        findings.append(Finding(
            title="IP limpo no VirusTotal",
            description=(
                f"Nenhuma engine de {total_vt} consultadas sinalizou ameaça. "
                f"País: {country} | AS: {as_owner}."
            ),
            source="VirusTotal",
        ))

    # --- AbuseIPDB ---
    abuse = raw_data.get("abuseipdb", {})
    abuse_score = abuse.get("abuse_confidence_score", 0) or 0
    total_reports = abuse.get("total_reports", 0) or 0
    abuse_country = abuse.get("country_code", "N/A")
    isp = abuse.get("isp", "N/A")
    is_tor = abuse.get("is_tor", False)
    usage_type = abuse.get("usage_type", "N/A")
    last_reported = abuse.get("last_reported_at", "N/A")
    if last_reported and last_reported != "N/A":
        last_reported = last_reported[:10]

    score = max(score, round(abuse_score / 10, 1))

    if abuse_score > 0:
        tor_info = " | Nó Tor identificado." if is_tor else ""
        findings.append(Finding(
            title="Histórico de abuso no AbuseIPDB",
            description=(
                f"Score de confiança de abuso: {abuse_score}%. "
                f"Total de relatórios: {total_reports}. "
                f"País: {abuse_country} | ISP: {isp} | Uso: {usage_type}."
                f" Último reporte: {last_reported}.{tor_info}"
            ),
            source="AbuseIPDB",
        ))
        if is_tor:
            recommendations.append("IP identificado como nó Tor — alto risco de anonimização maliciosa.")
        if abuse_score >= 80:
            recommendations.append("Incluir em blocklist automática.")
        if abuse_score >= 50:
            recommendations.append("Investigar logs de acesso para conexões originadas deste IP.")
    else:
        findings.append(Finding(
            title="Sem relatórios de abuso no AbuseIPDB",
            description=f"IP sem histórico de abuso registrado. País: {abuse_country} | ISP: {isp}.",
            source="AbuseIPDB",
        ))

    if not recommendations:
        recommendations.append("Monitorar o IP em futuras análises como medida preventiva.")

    risk = _score_to_risk(score)

    summary_parts = [f"Análise do IP {query}:"]
    if malicious_vt or suspicious_vt:
        summary_parts.append(
            f"O VirusTotal identificou {malicious_vt} detecções maliciosas e "
            f"{suspicious_vt} suspeitas de {total_vt} engines."
        )
    if abuse_score > 0:
        summary_parts.append(
            f"O AbuseIPDB registra score de abuso de {abuse_score}% com {total_reports} relatório(s)."
        )
    if is_tor:
        summary_parts.append("O IP é um nó da rede Tor.")
    if risk in (RiskLevel.clean, RiskLevel.low) and not abuse_score and not malicious_vt:
        summary_parts.append("O IP não apresenta indicadores expressivos de comprometimento.")

    return dict(
        risk_level=risk,
        risk_score=score,
        summary=" ".join(summary_parts),
        findings=findings,
        recommendations=recommendations,
    )


def _analyze_hash(query: str, raw_data: dict) -> dict:
    findings: list[Finding] = []
    recommendations: list[str] = []
    score = 0.0

    vt = raw_data.get("virustotal", {})
    malicious_vt = vt.get("malicious", 0) or 0
    suspicious_vt = vt.get("suspicious", 0) or 0
    harmless_vt = vt.get("harmless", 0) or 0
    total_vt = malicious_vt + suspicious_vt + harmless_vt

    file_type = vt.get("type", "desconhecido")
    file_name = vt.get("name") or query[:16] + "..."
    file_size = vt.get("size")
    tags = vt.get("tags", [])

    if total_vt > 0:
        vt_ratio = (malicious_vt + suspicious_vt) / total_vt
        score = round(vt_ratio * 10, 1)

        desc = (
            f"{malicious_vt} engines detectaram como malicioso, "
            f"{suspicious_vt} como suspeito, de {total_vt} engines totais. "
            f"Tipo: {file_type}."
            + (f" Tamanho: {file_size} bytes." if file_size else "")
            + (f" Tags: {', '.join(tags)}." if tags else "")
        )
        findings.append(Finding(
            title="Resultado da análise antivírus",
            description=desc,
            source="VirusTotal",
        ))

        if malicious_vt >= 5:
            recommendations.append("Isolar imediatamente o sistema onde o arquivo foi encontrado.")
            recommendations.append("Iniciar processo de resposta a incidentes (IR).")
        elif malicious_vt > 0:
            recommendations.append("Quarentenar o arquivo e investigar sua origem.")
        else:
            recommendations.append("Monitorar o arquivo em análises futuras.")
    else:
        findings.append(Finding(
            title="Hash não encontrado no VirusTotal",
            description="O hash não possui histórico de análise no VirusTotal.",
            source="VirusTotal",
        ))
        recommendations.append("Submeter o arquivo ao VirusTotal para análise manual.")

    risk = _score_to_risk(score)

    summary_parts = [f"Análise do hash {file_name}:"]
    if malicious_vt or suspicious_vt:
        summary_parts.append(f"{malicious_vt} de {total_vt} engines identificaram como malicioso.")
    else:
        summary_parts.append("Nenhuma detecção registrada no VirusTotal.")

    return dict(
        risk_level=risk,
        risk_score=score,
        summary=" ".join(summary_parts),
        findings=findings,
        recommendations=recommendations,
    )


def _analyze_domain(query: str, raw_data: dict) -> dict:
    findings: list[Finding] = []
    recommendations: list[str] = []
    score = 0.0

    vt = raw_data.get("virustotal", {})
    malicious_vt = vt.get("malicious", 0) or 0
    suspicious_vt = vt.get("suspicious", 0) or 0
    harmless_vt = vt.get("harmless", 0) or 0
    total_vt = malicious_vt + suspicious_vt + harmless_vt

    reputation = vt.get("reputation")
    registrar = vt.get("registrar", "N/A")
    categories = vt.get("categories", {})

    if total_vt > 0:
        vt_ratio = (malicious_vt + suspicious_vt) / total_vt
        score = round(vt_ratio * 10, 1)

        desc = (
            f"{malicious_vt} engines detectaram como malicioso e "
            f"{suspicious_vt} como suspeito de {total_vt} engines totais. "
            f"Registrar: {registrar}."
            + (f" Reputação: {reputation}." if reputation is not None else "")
            + (f" Categorias: {', '.join(set(categories.values()))}." if categories else "")
        )
        findings.append(Finding(
            title="Análise do domínio no VirusTotal",
            description=desc,
            source="VirusTotal",
        ))

        if malicious_vt >= 3:
            recommendations.append("Bloquear o domínio no proxy/DNS corporativo.")
            recommendations.append("Verificar se há usuários que acessaram o domínio nos logs.")
        elif malicious_vt > 0:
            recommendations.append("Investigar o contexto do domínio antes de liberar acesso.")
        else:
            recommendations.append("Monitorar como precaução.")
    else:
        findings.append(Finding(
            title="Domínio não encontrado no VirusTotal",
            description="Sem histórico de análise para este domínio.",
            source="VirusTotal",
        ))
        recommendations.append("Pesquisar o domínio em fontes OSINT adicionais (WHOIS, Shodan).")

    risk = _score_to_risk(score)

    summary_parts = [f"Análise do domínio {query}:"]
    if malicious_vt or suspicious_vt:
        summary_parts.append(f"{malicious_vt} detecções maliciosas em {total_vt} engines consultadas.")
    else:
        summary_parts.append("Domínio sem detecções expressivas no VirusTotal.")

    return dict(
        risk_level=risk,
        risk_score=score,
        summary=" ".join(summary_parts),
        findings=findings,
        recommendations=recommendations,
    )

def _analyze_cve(query: str, raw_data: dict) -> dict:
    findings: list[Finding] = []
    recommendations: list[str] = []

    nvd = raw_data.get("nvd", {})

    if "error" in nvd or not nvd:
        return dict(
            risk_level=RiskLevel.unknown,
            risk_score=None,
            summary=f"CVE {query} não encontrada na base NVD/NIST.",
            findings=[Finding(
                title="CVE não encontrada",
                description="Nenhum registro encontrado no NVD para esta CVE.",
                source="NVD",
            )],
            recommendations=["Verificar o identificador CVE e consultar o site oficial do NVD."],
        )

    cvss_score = nvd.get("cvss_score")
    cvss_severity = nvd.get("cvss_severity")
    cvss_vector = nvd.get("cvss_vector")
    description = nvd.get("description", "Sem descrição disponível.")
    published = (nvd.get("published") or "N/A")[:10]
    modified = (nvd.get("last_modified") or "N/A")[:10]
    references = nvd.get("references", [])

    score = float(cvss_score) if cvss_score is not None else 0.0

    cvss_info = f"CVSS Score: {cvss_score}" if cvss_score else "Score CVSS não disponível"
    if cvss_severity:
        cvss_info += f" ({cvss_severity})"
    if cvss_vector:
        cvss_info += f" | Vector: {cvss_vector}"

    findings.append(Finding(
        title=f"{query} — {cvss_severity or 'Severidade desconhecida'}",
        description=f"{cvss_info}. Publicada em: {published}. Última atualização: {modified}.",
        source="NVD",
    ))

    findings.append(Finding(
        title="Descrição técnica",
        description=description[:500] + ("..." if len(description) > 500 else ""),
        source="NVD",
    ))

    patch_refs = [r for r in references if "patch" in r.lower() or "advisory" in r.lower()]
    if patch_refs:
        findings.append(Finding(
            title="Referências disponíveis",
            description=" | ".join(patch_refs[:3]),
            source="NVD",
        ))
        recommendations.append(f"Consultar: {patch_refs[0]}")
    elif references:
        findings.append(Finding(
            title="Referências disponíveis",
            description=" | ".join(references[:3]),
            source="NVD",
        ))

    if score >= 9.0:
        recommendations.append("Prioridade CRÍTICA: aplicar patch imediatamente ou isolar o sistema afetado.")
        recommendations.append("Notificar o time de gestão de vulnerabilidades e abrir incidente.")
    elif score >= 7.0:
        recommendations.append("Planejar aplicação do patch na próxima janela de manutenção.")
        recommendations.append("Avaliar mitigações temporárias (WAF rules, desabilitar feature afetada).")
    elif score >= 4.0:
        recommendations.append("Incluir no ciclo regular de patching.")
    else:
        recommendations.append("Monitorar atualizações futuras desta vulnerabilidade.")

    risk = _score_to_risk(score)

    summary_parts = [f"Vulnerabilidade {query}:"]
    summary_parts.append(description[:200] + ("..." if len(description) > 200 else ""))
    if cvss_score:
        summary_parts.append(f"CVSS base score: {cvss_score} ({cvss_severity or 'N/A'}).")

    return dict(
        risk_level=risk,
        risk_score=score if cvss_score is not None else None,
        summary=" ".join(summary_parts),
        findings=findings,
        recommendations=recommendations,
    )

# ── entry point ───────────────────────────────────────────────────────────────

async def summarize(query: str, input_type: InputType, raw_data: dict) -> AnalyzeResponse:
    handlers = {
        InputType.ip: _analyze_ip,
        InputType.hash: _analyze_hash,
        InputType.domain: _analyze_domain,
        InputType.cve: _analyze_cve,
    }

    result = handlers[input_type](query, raw_data)

    return AnalyzeResponse(
        query=query,
        input_type=input_type,
        raw_data=raw_data,
        **result,
    )