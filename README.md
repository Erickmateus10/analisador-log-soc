# 🔍 Analisador de Logs para SOC

Ferramenta Python para análise de logs de segurança, desenvolvida para analistas de SOC.

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![GitHub](https://img.shields.io/badge/Status-Production-green.svg)
![Cybersecurity](https://img.shields.io/badge/Focus-SOC-orange.svg)

## 🚀 Funcionalidades

- ✅ **Análise de logs SSH** - Detecção de tentativas de brute force
- ✅ **Análise de logs Web** - Identificação de requisições suspeitas  
- ✅ **Detecção de IPs maliciosos** - Baseado em frequência de tentativas
- ✅ **Relatório consolidado** - Visão geral das atividades de segurança
- ✅ **Modo interativo** - Para testes e demonstrações

## 🛠️ Tecnologias

- **Python 3.6+** - Linguagem principal
- **Regex** - Para parsing de logs
- **Argparse** - Interface de linha de comando
- **Coleções** - Para análise de frequência

## 📦 Instalação

```bash
# Clone o repositório
git clone https://github.com/Erickmateus10/analisador-logs-soc.git

# Entre nessa pasta
cd analisador-logs-soc

🎯 Como Usar
Modo Interativo (iniciantes)
python analisador_soc.py 

Análise de logs SSH
python analisador_soc.py --ssh /var/log/auth.log 

Análise de logs Web
python analisador_soc.py --web /var/log/apache2/access.log 

Análise Completa
python analisador_soc.py --ssh auth.log --web access.log 

📊 Exemplo de Saída:
🔴 [ALERTA] IPs com múltiplas tentativas falhas:
   IP: 192.168.1.100 - 6 tentativas

📊 RESUMO DA ANÁLISE SSH:
   • Tentativas falhas: 7
   • Logins bem-sucedidos: 1  
   • Padrões suspeitos: 2
   