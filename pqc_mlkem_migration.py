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

import time
try:
    import oqs
except ImportError:
    print("Erro: A biblioteca 'liboqs-python' não foi encontrada.")
    print("Instale utilizando: pip install liboqs-python (no ambiente virtual)")
    exit(1)

def executar_mlkem():
    """
    Implementação da alternativa PQC (Capítulo 5.1)
    Realiza a execução experimental contendo: Keygen -> Encaps -> Decaps
    """

# Seleciona o algoritmo ML-KEM (Kyber-512 equivalente à segurança do AES-128)
kem_name = "Kyber512"

print("="*60)
print(f"Implementação da alternativa PQC ({kem_name}) - (Cápitulo 5.1)")
print("="*60)

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
    print("\n" + "-"*60)
    print("Verificação de integridade:")
    if shared_secret_sender == shared_secret_receiver:
        print("[✔] SUCESSO! O segredo compartilhado foi estabelecido"
        "\n    corretamente em ambas as pontas.")
        print(f"\n    Segredo (Hex): {shared_secret_sender.hex()[:32]}...")
    else:
        print("[✖] FALHA! Os segredos compartilhados não coincidem.")
    print("="*60)
if __name__ == "__main__":
    executar_mlkem