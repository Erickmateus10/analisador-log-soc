#!/usr/bin/env python3
"""
ANALISADOR DE LOGS PARA SOC - v1.0
Autor: Erick Mateus
GitHub: Erickmateus10
Descrição: Ferramenta para análise de logs de segurança
"""

import re
import argparse
from collections import Counter
from datetime import datetime

def banner():
    print("""
    ╔══════════════════════════════════════════╗
    ║           ANALISADOR DE LOGS SOC         ║
    ║            Cybersecurity Tool            ║
    ╚══════════════════════════════════════════╝
    """)

def analisar_logs_ssh(arquivo_log):
    """
    Analisa logs SSH para detectar atividades suspeitas
    """
    print(f"\n[+] Analisando logs SSH: {arquivo_log}")
    
    tentativas_falhas = []
    logins_sucesso = []
    padroes_suspeitos = []
    
    try:
        with open(arquivo_log, 'r', encoding='utf-8', errors='ignore') as file:
            linhas = file.readlines()
            
        for numero_linha, linha in enumerate(linhas, 1):
            linha = linha.strip()
            
            # Detectar tentativas falhas de password
            if 'Failed password' in linha:
                ip = re.findall(r'from (\d+\.\d+\.\d+\.\d+)', linha)
                usuario = re.findall(r'for (\w+) from', linha)
                if ip:
                    tentativas_falhas.append(ip[0])
                    print(f"   ⚠️  Tentativa falha - IP: {ip[0]}, Linha: {numero_linha}")
            
            # Detectar logins bem-sucedidos
            elif 'Accepted password' in linha:
                ip = re.findall(r'from (\d+\.\d+\.\d+\.\d+)', linha)
                if ip:
                    logins_sucesso.append(ip[0])
                    print(f"   ✅ Login aceito - IP: {ip[0]}, Linha: {numero_linha}")
            
            # Detectar padrões suspeitos
            if 'invalid user' in linha.lower():
                padroes_suspeitos.append(f"Usuário inválido - Linha {numero_linha}")
            
            if 'break-in attempt' in linha.lower():
                padroes_suspeitos.append(f"Tentativa de invasão - Linha {numero_linha}")
        
        # Análise de frequência
        if tentativas_falhas:
            contador = Counter(tentativas_falhas)
            ips_suspeitos = [(ip, count) for ip, count in contador.items() if count > 3]
            
            if ips_suspeitos:
                print(f"\n🔴 [ALERTA] IPs com múltiplas tentativas falhas:")
                for ip, tentativas in ips_suspeitos:
                    print(f"   IP: {ip} - {tentativas} tentativas")
        
        # Resumo
        print(f"\n📊 RESUMO DA ANÁLISE SSH:")
        print(f"   • Tentativas falhas: {len(tentativas_falhas)}")
        print(f"   • Logins bem-sucedidos: {len(logins_sucesso)}")
        print(f"   • Padrões suspeitos: {len(padroes_suspeitos)}")
        
        return {
            'tentativas_falhas': len(tentativas_falhas),
            'logins_sucesso': len(logins_sucesso),
            'padroes_suspeitos': padroes_suspeitos,
            'ips_suspeitos': ips_suspeitos if 'ips_suspeitos' in locals() else []
        }
        
    except FileNotFoundError:
        print(f"❌ Erro: Arquivo {arquivo_log} não encontrado!")
        return None
    except Exception as e:
        print(f"❌ Erro na análise: {e}")
        return None

def analisar_logs_web(arquivo_log):
    """
    Analisa logs de acesso web (Apache/Nginx)
    """
    print(f"\n[+] Analisando logs Web: {arquivo_log}")
    
    requisicoes_suspeitas = []
    status_codes = []
    
    try:
        with open(arquivo_log, 'r', encoding='utf-8', errors='ignore') as file:
            for numero_linha, linha in enumerate(file, 1):
                # Padrão simples para logs Apache
                padrao = r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "(\w+) (.*?) HTTP.*" (\d+)'
                match = re.search(padrao, linha)
                
                if match:
                    ip, metodo, url, status = match.groups()
                    status_codes.append(status)
                    
                    # Detectar atividades suspeitas
                    if status in ['404', '403', '500']:
                        requisicoes_suspeitas.append(f"IP {ip} - {metodo} {url} - Status {status}")
                    
                    if 'etc/passwd' in url or 'admin' in url or 'wp-admin' in url:
                        print(f"   🔍 Requisição suspeita - IP: {ip}, URL: {url}")
        
        print(f"\n📊 RESUMO DA ANÁLISE WEB:")
        print(f"   • Total de requisições analisadas: {len(status_codes)}")
        print(f"   • Requisições suspeitas: {len(requisicoes_suspeitas)}")
        
        return {
            'total_requisicoes': len(status_codes),
            'requisicoes_suspeitas': requisicoes_suspeitas
        }
        
    except Exception as e:
        print(f"❌ Erro na análise web: {e}")
        return None

def gerar_relatorio(analises):
    """
    Gera um relatório consolidado das análises
    """
    print("\n" + "="*50)
    print("           RELATÓRIO DE SEGURANÇA")
    print("="*50)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Data/Hora da análise: {timestamp}")
    
    for tipo, dados in analises.items():
        if dados:
            print(f"\n🔍 {tipo.upper()}:")
            for chave, valor in dados.items():
                if chave == 'ips_suspeitos' and valor:
                    print(f"   IPs Suspeitos: {len(valor)} encontrados")
                    for ip, tentativas in valor:
                        print(f"     • {ip} ({tentativas} tentativas)")
                elif isinstance(valor, list):
                    print(f"   {chave}: {len(valor)}")
                else:
                    print(f"   {chave}: {valor}")

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Analisador de Logs para SOC')
    parser.add_argument('--ssh', help='Caminho do arquivo de log SSH')
    parser.add_argument('--web', help='Caminho do arquivo de log Web')
    
    args = parser.parse_args()
    
    analises = {}
    
    if args.ssh:
        analises['ssh'] = analisar_logs_ssh(args.ssh)
    
    if args.web:
        analises['web'] = analisar_logs_web(args.web)
    
    if not args.ssh and not args.web:
        print("ℹ️  Modo de uso:")
        print("   python analisador_soc.py --ssh /caminho/ssh.log")
        print("   python analisador_soc.py --web /caminho/access.log")
        print("   python analisador_soc.py --ssh ssh.log --web access.log")
        
        # Modo interativo para teste
        resposta = input("\n🎮 Modo interativo? Quer testar com exemplos? (s/n): ")
        if resposta.lower() == 's':
            testar_com_exemplos()
            return
    
    gerar_relatorio(analises)

def testar_com_exemplos():
    """
    Cria logs de exemplo para demonstrar a ferramenta
    """
    print("\n[+] Criando logs de exemplo...")
    
    # Criar log SSH de exemplo
    with open('logs_exemplos/ssh_exemplo.log', 'w') as f:
        f.write("""Jan 1 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:00:01 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:00:02 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 1 10:00:03 server sshd[1237]: Accepted password for user1 from 192.168.1.50 port 22 ssh2
Jan 1 10:00:04 server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:00:05 server sshd[1239]: Invalid user hacker from 192.168.1.100
Jan 1 10:01:00 server sshd[1240]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 1 10:01:01 server sshd[1241]: Failed password for root from 192.168.1.100 port 22 ssh2
""")
    
    # Criar log Web de exemplo
    with open('logs_exemplos/web_exemplo.log', 'w') as f:
        f.write("""192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /admin HTTP/1.1" 404 123
192.168.1.50 - - [01/Jan/2024:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 4567
192.168.1.100 - - [01/Jan/2024:10:00:02 +0000] "GET /etc/passwd HTTP/1.1" 403 234
192.168.1.100 - - [01/Jan/2024:10:00:03 +0000] "POST /wp-admin HTTP/1.1" 500 345
192.168.1.200 - - [01/Jan/2024:10:00:04 +0000] "GET /contact.html HTTP/1.1" 200 1234
""")
    
    print("[+] Analisando logs de exemplo...")
    analises = {
        'ssh': analisar_logs_ssh('logs_exemplos/ssh_exemplo.log'),
        'web': analisar_logs_web('logs_exemplos/web_exemplo.log')
    }
    
    gerar_relatorio(analises)
    print("\n🎯 Demonstração concluída! Agora você pode usar com seus próprios logs.")

if __name__ == "__main__":
    main()