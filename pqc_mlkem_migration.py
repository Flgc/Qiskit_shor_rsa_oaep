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

INTERATIONS = 100 # Número de repetições para garantir média precisa

def benchmark_rsa_2048_oaep(iterations=INTERATIONS):
    """
    Realiza o benchmark da solução atual (RSA-2048-OAEP) com multiplas
    execuçõrs para extrair médias reais de tempo.    
    """
    
    keygen_times, encaps_times, decaps_times = [], [], []
    
    # Execução base para extrair tamanhos    
    private_key_base = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_bytes = private_key_base.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key_base.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()       
    )

    secret = os.urandom(32) # Segredo com padrão de 256 bits

    # Loop de repetições para tempos médios
    for _ in range(iterations):
        # Encaps (Cifragem)
        start = time.perf_counter()
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        keygen_times.append(time.perf_counter() - start)

        pub_key = priv_key.public_key()

        start = time.perf_counter()
        ciphertext = pub_key.encrypt(
            secret, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encaps_times.append(time.perf_counter() - start) # Correção aplicada

    # Decaps (Decifragem)
    start = time.perf_counter()
    decrypted = priv_key.decrypt(    
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    decaps_times.append(time.perf_counter() - start)

    return{
        "pub_size": len(pub_bytes),
        "priv_size": len(priv_bytes),
        "cipher_size": len(ciphertext),
        "secret_size": len(secret),        
        "keygen_t": sum(keygen_times) / iterations,              
        "encaps_t": sum(encaps_times) / iterations,
        "decaps_t": sum(decaps_times) / iterations        
    }

def executar_mlkem():
    """
    Implementação da alternativa PQC (Capítulo 5.1)
    Realiza a execução experimental contendo: Keygen -> Encaps -> Decaps
    """

# Seleciona o algoritmo ML-KEM (Kyber-512 equivalente à segurança do AES-128)
kem_name = "ML-KEM-512"

print("="*87)
print(f"Implementação da alternativa PQC ({kem_name}) - (Cápitulo 5.1)")
print(f"Executando {INTERATIONS} interações para cálculo de médias...")
print("="*87)

# Inicia o mecanismo KEM do open quantum safe""
with oqs.KeyEncapsulation(kem_name) as kem:
   
    keygen_times, encaps_times, decaps_times = [], [], []

    for i in range(INTERATIONS):
        """
        Etapa 1 - KeyGen - gera chaves
        """
        start = time.perf_counter()        
        public_key = kem.generate_keypair()
        keygen_times.append(time.perf_counter() - start)

        """
        Etapa 2 - Encaps - operação criptográfica principal
        O remetente usa a chave pública para gerar um ciphertext
        e um segredo compartilhado.
        """
        start = time.perf_counter()
        ciphertext, shared_secret_sender = kem.encap_secret(public_key)
        encaps_times.append(time.perf_counter() - start)

        """
        Etapa 3 - Decaps - operação inversa / desencapsulamento
        O destinatário usa sua chave privada para extrair o segredo do ciphertext.
        """
        start = time.perf_counter()
        shared_secret_receiver = kem.decap_secret(ciphertext)
        decaps_times.append(time.perf_counter() - start)

        # Verificação apenas na última iteração para exibir  no terminal
        if i == INTERATIONS -1:
            # O segredo privado fica armazenado internamente no objeto 'kem'
            private_key = kem.export_secret_key()
            valido = (shared_secret_sender == shared_secret_receiver)

    avg_keygen = sum(keygen_times) / INTERATIONS
    avg_encaps = sum(encaps_times) / INTERATIONS
    avg_decaps = sum(decaps_times) / INTERATIONS
    
    print("\n[1] KeyGen - Geração de chaves concluída:")
    print(f"    - Tempo médio de geração: {avg_keygen:.6f} segundos")    
    print(f"    - Tamanho da chave pública: {len(public_key)} bytes")
    print(f"    - Tamanho da chave privada: {len(private_key)} bytes")   
    
    print("\n[2] Encaps - Encapsulamento da chave (remetente):")
    print(f"    - Tempo de médio de encapsulamento: {avg_encaps:.6f} segundos")
    print(f"    - Tamanho do ciphertext: {len(ciphertext)} bytes")
    print(f"    - Tamanho do segredo compartilhado: {len(shared_secret_sender)} bytes")
  
    print("\n[3] Decaps - Desencapsulamento da chave (destinatário):")
    print(f"    - Tempo médio de desencapsulamento: {avg_decaps:.6f} segundos")

    """
    Etapa final - verificação
    """
    print("\n" + "-"*87)
    print("Verificação de integridade:")
    if valido:
        print(f"[✔] SUCESSO! {kem_name} KeyGen -> Encaps -> Decaps validados.")    
    else:
        print(f"[✖] FALHA na verificação do {kem_name}.")
    print("-"*87)
    
    pqc_metrics = {
        "pub_size": len(public_key),
        "priv_size": len(private_key),
        "cipher_size": len(ciphertext),
        "secret_size": len(shared_secret_sender),
        "keygen_t": avg_keygen,
        "encaps_t": avg_encaps,
        "decaps_t": avg_decaps
    }    

"""
Comparação quantitativa (Tabela 2, capítulo 6 até 6.2)
"""
rsa_metrics = benchmark_rsa_2048_oaep()

def calc_delta(vpqc, vatual):
    return ((vpqc - vatual) / vatual) * 100

print("\n" + "="*87)
print("Comparação quantitativa (Tabela 2, capítulo 6.2)")
print("="*87)
print(f"{'Métrica':<30} | {'RSA-OAEP 2048':<15} | {kem_name:<15} | {'Diferença (%)':<10}")
print("-" * 87)

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
Avaliação da migração pós-quântica (Capítulo 7)
"""
print("\n" + "-"*87)
print("Avaliação da migração PQC (Capítulo 7)")
print("-"*87)

# Simulação de cenário: 1.000.000 de operações
operacoes = 1_000_000

# Armazenamento (1 milhão de chaves públicas - Capítulo 7.1)
armazenamento_rsa_mb = (rsa_metrics['pub_size'] * operacoes) / (1024**2)
armazenamento_pqc_mb = (pqc_metrics['pub_size'] * operacoes) / (1024**2)
diff_armazenamento = armazenamento_pqc_mb - armazenamento_rsa_mb

print("[7.1] - Armazenamento (Cenário: 1 milhão de chaves públicas armazenadas):")
print(f"      - RSA-OAEP: {armazenamento_rsa_mb:.2f} MB")
print(f"      - ML-KEM  : {armazenamento_pqc_mb:.2f} MB")
print(f"      - Impacto : Necessidade de +{diff_armazenamento:.2f} MB de espaço.")

# Comunicação (1 milhão de encapsulamentos/transações por dia - Capítulo 7.2)
banda_rsa_mb = (rsa_metrics['cipher_size'] * operacoes) / (1024**2)
banda_pqc_mb = (pqc_metrics['cipher_size'] * operacoes) / (1024**2)
diff_banda = banda_pqc_mb - banda_rsa_mb

print("\n[7.2] - Comunicação (Cenário: 1 milhão de ciphertexts transmitidos/dia):")
print(f"      - RSA-OAEP: {banda_rsa_mb:.2f} MB trafegados")
print(f"      - ML-KEM  : {banda_pqc_mb:.2f} MB trafegados")
print(f"      - Impacto : Aumento de +{diff_banda:.2f} MB no consumo de banda diária.")
    
# Processamento  (Capítulo 7.3)
print("\n[7.3] - Processamento:")
print(f"      - A operação de maior impacto positivo é o KeyGen ({calc_delta(pqc_metrics['keygen_t'], rsa_metrics['keygen_t']):+.2f}%).")
print(f"      - A operação de maior impacto negativo tende a ser a latência de rede")
print(f"         devido ao aumento do ciphertext, mais do que o consumo de CPU em si.")

"""
Análise Final (Capítulo 8)
"""
print("\n" + "="*87)
print("Análise final (Capítulo 8)")
print("="*87)
print("Q1. Maior instância comprometida via Shor:")
print("    R: N=35 (6 bits).")

print("\nQ2. Principal fator limitante:")
print("    R: A quantidade de qubits lógicos necessários e a extrema profundidade (Circuit")
print("    Depth) do oráculo de exponenciação modular, que causam decoerência no simulador.")

print("\nQ3. Por que é vulnerável mesmo sem quebrar a chave real?")
print("    R: O algoritmo de Shor demonstra matematicamente que o problema da fatoração")
print("    possui complexidade de tempo polinomial num computador quântico, eliminando a")
print("    segurança exponencial que protege o RSA clássico.")

print("\nQ4. Qual algoritmo PQC substituto e por quê?")
print("    R: ML-KEM-512. Como o RSA-OAEP atua no estabelecimento de chaves seguras,")
print("    o substituto deve ser um Key Encapsulation Mechanism (KEM).")

print("\nQ5. Custo quantitativo da migração?")
print("    R: Conforme capítulo 7, o custo primário é de armazenamento e comunicação (aumento")
print("    no tamanho de chaves e ciphertexts), compensado pela rapidez no processamento.")

print("\nQ6. Alterações de infraestrutura em um sistema real?")
print("    R: Atualização de bibliotecas de criptografia, aumento do tamanho de buffers de")
print("    rede (TLS/TCP) e emissão de novos formatos de certificados X.509.")

print("\nQ7. A simples substituição é suficiente?")
print("    R: Não. São necessárias alterações arquiteturais como o uso de 'Criptografia")
print("    Híbrida' (combinando PQC e clássica durante o período de transição) para mitigar")
print("    ataques do tipo 'Harvest Now, Decrypt Later'.")
print("="*87)

"""
Gráfico de desempenho isolado do ML-KEM-512 (Capítulo 5.1)
"""
fig_kem, axs_kem = plt.subplots(1, 2, figsize=(12, 5))
fig_kem.suptitle(f'Análise de desempenho isolado: {kem_name} - Capítulo 5.1')

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
fig.suptitle(f'Comparação quantitativa: RSA-OAEP 2048 vs {kem_name} (Capítulo 6.2)')

width = 0.35

# Gráfico 1: Armazenamento e comunicação (Bytes)
labels_bytes = ['Chave pública', 'Chave privada', 'Ciphertext']
rsa_bytes = [rsa_metrics['pub_size'], rsa_metrics['priv_size'], rsa_metrics['cipher_size']]
pqc_bytes = [pqc_metrics['pub_size'], pqc_metrics['priv_size'], pqc_metrics['cipher_size']]

x_bytes = np.arange(len(labels_bytes))

axs[0].bar(x_bytes - width/2, rsa_bytes, width, label='RSA-OAEP 2048', color='dimgray')
axs[0].bar(x_bytes + width/2, pqc_bytes, width, label=kem_name, color='darkcyan')
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
axs[1].bar(x_time + width/2, pqc_time, width, label=kem_name, color='darkcyan')
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