# Avaliação experimental: Migração Pós-Quântica (PQC) 
# Algoritmo original: RSA-OAEP (Item 7 da tabela 1 da atividade em grupo - 28/09/2026)
# Algoritmo substituto: ML-KEM / Kyber (key Encapsulation Mechanism)
# Alunos: Adriel Nascimento | Fábio Luís
# Disciplina: [2026.2] Computação Quântica para Defesa Cibernética

"""
 Objetivo: Atender aos capítulos 5 e 5.1 do documento de avaliação.
 Justificativa: Como o RSA-OAEP é utilizado para criptografia e estabelecimento de chaves,
 a substituição adequada que preserva a função original é um algoritmo PQC de encapsulamento
 de chaves, especificamente o ML-KEM. 
"""

import os
import time
import matplotlib.pyplot as plt
import numpy as np

try:
    import oqs
except ImportError:
    print("Erro: A biblioteca 'liboqs-python' não foi encontrada.")
    print("Instale utilizando: pip install liboqs-python (no ambiente virtual)")
    exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:        
    print("Erro: A biblioteca 'cryptography' não foi encontrada.")
    print("Instale utilizando: pip install cryptography")
    exit(1)

def benchmark_rsa_2048_oaep():
    """
    Realiza o benchmark da solução atual (RSA-2048-OAEP) para extrair
    metricas reais de tempo e tamanho (Baseline para o capítulo 6).
    """
    # KeyGen
    start = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keygen_t = time.perf_counter() - start

    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()       
    )

    secret = os.urandom(32) # Segredo com padrão de 256 bits

    # Encaps (Cifragem)
    start = time.perf_counter()
    ciphertext = public_key.encrypt(
        secret,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encaps_t = time.perf_counter()

    # Decaps (Decifragem)
    start = time.perf_counter()
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    decaps_t = time.perf_counter() - start

    return{
        "pub_size": len(pub_bytes),
        "priv_size": len(priv_bytes),
        "cipher_size": len(ciphertext),
        "secret_size": len(secret),
        "keygen_t": keygen_t,
        "encaps_t": encaps_t,
        "decaps_t": decaps_t       
    }

def executar_mlkem():
    """
    Implementação da alternativa PQC (Capítulo 5.1)
    Realiza a execução experimental contendo: Keygen -> Encaps -> Decaps
    """

# Seleciona o algoritmo ML-KEM (Kyber-512 equivalente à segurança do AES-128)
kem_name = "Kyber512"

print("="*82)
print(f"Implementação da alternativa PQC ({kem_name}) - (Cápitulo 5.1)")
print("="*82)

# Inicia o mecanismo KEM do open quantum safe""
with oqs.KeyEncapsulation(kem_name) as kem:

    """
    Etapa 1 - KeyGen - gera chaves
    """
    start_time = time.perf_counter()
    public_key = kem.generate_keypair()
    keygen_time = time.perf_counter() - start_time    

    # O segredo privado fica armazenado internamente no objeto 'kem'
    private_key = kem.export_secret_key()
    
    print("\n[1] KeyGen - Geração de chaves concluída:")
    print(f"    - Tempo de geração: {keygen_time:.6f} segundos")
    print(f"    - Tamanho da chave pública: {len(public_key)} bytes")
    print(f"    - Tamanho da chave privada: {len(private_key)} bytes")   

    """
    Etapa 2 - Encaps - operação criptográfica principal

    O remetente usa a chave pública para gerar um ciphertext
    e um segredo compartilhado.
    """
    start_time = time.perf_counter()
    ciphertext, shared_secret_sender = kem.encap_secret(public_key)
    encaps_time = time.perf_counter() - start_time
    
    print("\n[2] Encaps - Encapsulamento da chave (remetente):")
    print(f"    - Tempo de encapsulamento: {encaps_time:.6f} segundos")
    print(f"    - Tamanho do ciphertext: {len(ciphertext)} bytes")
    print(f"    - Tamanho do segredo compartilhado: {len(shared_secret_sender)} bytes")

    """
    Etapa 3 - Decaps - operação inversa / desencapsulamento

    O destinatário usa sua chave privada para extrair o segredo do ciphertext.
    """
    start_time = time.perf_counter()
    shared_secret_receiver = kem.decap_secret(ciphertext)
    decaps_time = time.perf_counter() - start_time
    
    print("\n[3] Decaps - Desencapsulamento da chave (destinatário):")
    print(f"    - Tempo de desencapsulamento: {decaps_time:.6f} segundos")

    """
    Etapa final - verificação
    """
    print("\n" + "-"*82)
    print("Verificação de integridade:")
    if shared_secret_sender == shared_secret_receiver:
        print("[✔] SUCESSO! ML-KEM KeyGen -> Encaps -> Decaps validados.")
    #    print(f"\n    Segredo (Hex): {shared_secret_sender.hex()[:32]}...")
    else:
        print("[✖] FALHA na verificação do ML-KEM.")
    print("-"*82)
    
    pqc_metrics = {
        "pub_size": len(public_key),
        "priv_size": len(private_key),
        "cipher_size": len(ciphertext),
        "secret_size": len(shared_secret_sender),
        "keygen_t": keygen_time,
        "encaps_t": encaps_time,
        "decaps_t": decaps_time
    }    

"""
Comparação quantitativa (Tabela 2, capítulo 6 até 6.2)
"""
rsa_metrics = benchmark_rsa_2048_oaep()

def calc_delta(vpqc, vatual):
    return ((vpqc - vatual) / vatual) * 100

print("\n" + "="*82)
print("Comparação quantitativa (Tabela 2, capítulo 6.2)")
print("="*82)
print(f"{'Métrica':<30} | {'RSA-OAEP 2048':<15} | {'ML-KEM (Kyber)':<15} | {'Diferença (%)':<10}")
print("-" * 82)

metrics_map = [
    ("Chave pública (Bytes)", "pub_size", False),
    ("Chave privada (Bytes)", "priv_size", False),
    ("Ciphertext (Bytes)", "cipher_size", False),
    ("KeyGen (Segundos)", "keygen_t", True),
    ("Encapsulação (Segundos)", "encaps_t", True),
    ("Decapsulação (Segundos)", "decaps_t", True) 
]

for label, key, is_float in metrics_map:
    v_rsa = rsa_metrics[key]
    v_pqc = pqc_metrics[key]
    delta = calc_delta(v_pqc, v_rsa)

    if is_float:
        print(f"{label:<30} | {v_rsa:<15.6f} | {v_pqc:<15.6f} | {delta:>+8.2f}%")
    else:
        print(f"{label:<30} | {v_rsa:<15} | {v_pqc:<15} | {delta:>+8.2f}%")

"""
Preparação: Avaliação da migração pós-quântica (Capítulo 7)
"""
print("\n" + "="*82)
print("Insights de preparação da migração PQC (Capítulo 7)")
print("="*82)

print("[1] Armazenamento:")
d_pub = calc_delta(pqc_metrics['pub_size'], rsa_metrics['pub_size'])
print(f"    - Chaves públicas sofrerão um impacto de {d_pub:+.2f}%.")
print("    - (Preparar exemplo numérico para 1 milhão de certificados).")

print("\n[2] Comunicação:")
d_ciph = calc_delta(pqc_metrics['cipher_size'], rsa_metrics['cipher_size'])
print(f"    - Os ciphertexts/encapsulamentos sofrerão um impacto de {d_ciph:+.2f}%.")
print("    - (Preparar cenário quantitativo para o volume de dados transmitidos).")
    
print("\n[3] Processamento:")
d_kg = calc_delta(pqc_metrics['keygen_t'], rsa_metrics['keygen_t'])
print(f"    - Velocidade de geração de chaves: {d_kg:+.2f}%.")
print("    - ML-KEM costuma ser drasticamente mais rápido que o RSA clássico.")
print("="*82)

"""
Gráfico de desempenho isolado do ML-KEM (Capítulo 5.1)
"""
fig_kem, axs_kem = plt.subplots(1, 2, figsize=(12, 5))
fig_kem.suptitle('Análise de desempenho isolado: ML-KEM (Kyber512) - Capítulo 5.1')

# Gráfico 1: Tamanhos (Bytes)
labels_sizes = ['Chave pública', 'Chave privada', 'Ciphertext']
sizes = [pqc_metrics['pub_size'], pqc_metrics['priv_size'], pqc_metrics['cipher_size']]
bars_sizes = axs_kem[0].bar(labels_sizes, sizes, color=['#1f77b4', '#ff7f0e', '#2ca02c'])
axs_kem[0].set_ylabel('Tamanho (Bytes)')
axs_kem[0].set_title('Distribuição de armazenamento')
axs_kem[0].bar_label(bars_sizes, padding=3) # Adiciona os valores acima das barras

# Gráfico 2: Tempos (Segundos)
labels_times = ['KeyGen', 'Encaps', 'Decaps']
times = [pqc_metrics['keygen_t'], pqc_metrics['encaps_t'], pqc_metrics['decaps_t']]
bars_times = axs_kem[1].bar(labels_times, times, color=['#d62728', '#9467bd', '#8c564b'])
axs_kem[1].set_ylabel('Tempo (Segundos)')
axs_kem[1].set_title('Tempo de execução por operação')
axs_kem[1].bar_label(bars_times, fmt='%.6f', padding=3)

plt.tight_layout()
plt.savefig("mlkem_desempenho_isolado.png")
print(f"\n[✔] Gráfico de desempenho isolado do PQC salvo como: \n'mlkem_desempenho_isolado.png'.\n")

"""
Geração de gráficos comparativos (Capítulo 6 e 6.2)
"""
fig, axs = plt.subplots(1,2, figsize=(14, 6))
fig.suptitle('Comparação quantitativa: RSA-OAEP 2048 vs ML-KEM (Capítulo 6.2)')

width = 0.35

# Gráfico 1: Armazenamento e comunicação (Bytes)
labels_bytes = ['Chave pública', 'Chave privada', 'Ciphertext']
rsa_bytes = [rsa_metrics['pub_size'], rsa_metrics['priv_size'], rsa_metrics['cipher_size']]
pqc_bytes = [pqc_metrics['pub_size'], pqc_metrics['priv_size'], pqc_metrics['cipher_size']]

x_bytes = np.arange(len(labels_bytes))

axs[0].bar(x_bytes - width/2, rsa_bytes, width, label='RSA-OAEP 2048', color='dimgray')
axs[0].bar(x_bytes + width/2, pqc_bytes, width, label='ML-KEM (Kyber512)', color='darkcyan')
axs[0].set_ylabel('Tamanho (Bytes)')
axs[0].set_title('Impacto no armazenamento / comunicação')
axs[0].set_xticks(x_bytes)
axs[0].set_xticklabels(labels_bytes)
axs[0].legend()

# Gráfico 2: Processamento (Segundos)
labels_time = ['KeyGen', 'Encapsulação', 'Decapsulação']
rsa_time = [rsa_metrics['keygen_t'], rsa_metrics['encaps_t'], rsa_metrics['decaps_t']]
pqc_time = [pqc_metrics['keygen_t'], pqc_metrics['encaps_t'], pqc_metrics['decaps_t']]

x_time = np.arange(len(labels_time))

axs[1].bar(x_time - width/2, rsa_time, width, label='RSA-OAEP 2048', color='dimgray')
axs[1].bar(x_time + width/2, pqc_time, width, label='ML-KEM (Kyber512)', color='darkcyan')
axs[1].set_ylabel('Tempo (Segundos) - Escala logarítmica')
axs[1].set_title('Impacto no processamento')
axs[1].set_xticks(x_time)
axs[1].set_xticklabels(labels_time)
axs[1].set_yscale('log') # Escala logarítmica devido à extrema diferença de tempo no KeyGen
axs[1].legend()

plt.tight_layout()
plt.savefig("pqc_mlkem_comparativo.png")
print(f"[✔] Gráfico comparativo salvo como: \n'pqc_mlkem_comparativo.png'.\n")

if __name__ == "__main__":
    executar_mlkem