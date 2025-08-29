# Discord NVD Threat Intelligence Bot

## Objetivo

Este bot é um **especialista em Threat Intelligence**, projetado para monitorar novas vulnerabilidades (CVEs) em ativos específicos da empresa e reportar automaticamente em um servidor privado do Discord.  

Ele utiliza APIs oficiais (NVD, MITRE, CVE.org) para garantir **alta precisão**, e possui funcionalidades de:

- Reports normais e críticos  
- Auto-clean de mensagens antigas  
- Comandos interativos via Discord  

---

## Ativos Monitorados

O bot monitora os seguintes ativos:

| Ativo | Tipo |
|-------|------|
| Red Hat Enterprise Linux 9 | Sistema Operacional do Servidor |
| Oracle Database 19c | Banco de Dados |
| Mozilla Firefox | Navegador Workspaces |
| Juniper MX Series | Roteador da Rede |
| Ubuntu 22.04 (Jammy Jellyfish) | Sistema Operacional Workspaces |

---

## Estrutura do Repositório

discord-nvd-alert/
├─ bot/
│ ├─ main.py # Ponto de entrada do bot
│ ├─ cve_monitor.py # Busca e filtra CVEs
│ ├─ commands.py # Comandos interativos
│ ├─ cleanup.py # Auto-clean de mensagens
│ └─ utils.py # Funções auxiliares e persistência
├─ data/
│ └─ seen_db.json # Histórico de CVEs reportadas
├─ .github/workflows/
│ └─ bot_runner.yml # Workflow do GitHub Actions
├─ requirements.txt # Dependências Python
├─ .gitignore
└─ README.md

           ┌───────────────────┐
           │ Bot Inicializado  │
           └─────────┬─────────┘
                     │
           ┌─────────▼─────────┐
           │ monitor_cves loop │
           │ (a cada 1h)       │
           └─────────┬─────────┘
                     │
        ┌────────────▼────────────┐
        │ Busca novas CVEs nos    │
        │ ativos específicos      │
        └────────────┬────────────┘
                     │
       ┌─────────────▼─────────────┐
       │ CVE é nova?               │
       │ Se sim:                     │
       │ - Crítica → @everyone      │
       │ - Normal → mensagem normal │
       └─────────────┬─────────────┘
                     │
           ┌─────────▼─────────┐
           │ Atualiza seen_db  │
           └─────────┬─────────┘
                     │
           ┌─────────▼─────────┐
           │ Auto-clean loop   │
           │ (a cada 6h20min) │
           └─────────┬─────────┘
                     │
           ┌─────────▼─────────┐
           │ Deleta mensagens  │
           │ não críticas       │
           │ preserva últimas  │
           │ 20 min + críticos │
           └───────────────────┘


