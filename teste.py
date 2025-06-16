import pandas as pd
from scapy.all import rdpcap, TCP, IP
from pathlib import Path

# Diretório base (pasta onde o script está rodando)
diretorio_base = Path('.')

# Lista para acumular todos os DataFrames
todos_resultados = []

# Percorre todas as subpastas
for subpasta in diretorio_base.iterdir():
    if subpasta.is_dir():
        caminho_pcap = subpasta / 'l3.pcap' / 'l3.pcap'
        if caminho_pcap.exists():
            print(f'📁 Processando: {caminho_pcap}')
            try:
                packets = rdpcap(str(caminho_pcap))
                data = []
                for pkt in packets:
                    if pkt.haslayer(IP) and pkt.haslayer(TCP):
                        try:
                            timestamp = pkt.time
                            ip_src = pkt[IP].src
                            ip_dst = pkt[IP].dst
                            port_src = pkt[TCP].sport
                            port_dst = pkt[TCP].dport
                            size_bytes = len(pkt)

                            data.append({
                                'timestamp': timestamp,
                                'experimento': subpasta.name,
                                'ip_src': ip_src,
                                'ip_dst': ip_dst,
                                'porta_src': port_src,
                                'porta_dst': port_dst,
                                'bytes': size_bytes
                            })
                        except Exception:
                            continue

                if data:
                    df = pd.DataFrame(data)
                    df['ts_rounded'] = df['timestamp'].astype(int)
                    df_grouped = df.groupby('ts_rounded')['bytes'].sum().reset_index()
                    df_grouped['throughput_mbps'] = (df_grouped['bytes'] * 8) / 1_000_000
                    df_grouped['experimento'] = subpasta.name
                    todos_resultados.append(df_grouped)
            except Exception as e:
                print(f"⚠️ Erro ao processar {caminho_pcap}: {e}")

# Junta todos os resultados em um único DataFrame
df_final = pd.concat(todos_resultados, ignore_index=True)

# Salva em CSV
df_final.to_csv('resultado_geral.csv', index=False)
print("✅ Arquivo 'resultado_geral.csv' salvo com sucesso!")
