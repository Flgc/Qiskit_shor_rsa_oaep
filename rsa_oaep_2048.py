# Recuperação da chave no tamanho real: RSA-2048 com OAEP
# Item 7 da tabela 1 da atividade em grupo - 28/09/2026
# Alunos: Adriel Nascimento | Fábio Luís
# Disciplina: [2026.2] Computação Quântica para Defesa Cibernética

# Objetivo: fechar o elo "recuperação da chave" da cadeia pedida no enunciado
#   Algoritmo clássico -> Problema matemático -> Shor -> Recuperação da chave -> Limite experimental
# no tamanho de chave usado na prática.
#
# O shor_rsa_oaep.py recupera a chave de instâncias de até poucos bits, mas o OAEP não
# cabe em módulos tão pequenos (parte 2 abaixo). Este script mostra o outro lado: num
# RSA-2048 com OAEP-SHA256, quem conhece a chave pública (N, e) e um fator de N reconstrói
# a chave privada inteira e decifra o ciphertext. O padding OAEP protege contra ataques ao
# formato da mensagem, mas não muda o problema matemático: quem fatora N tem a chave.
#
# Ambiente controlado: o próprio script gera o par de chaves. Como o Shor não roda em
# 2048 bits em nenhum computador atual (capítulo 4), o fator p que ele devolveria é
# tirado da chave recém-gerada, fazendo o papel da saída do algoritmo.
#
# Execução: python3 rsa_oaep_2048.py
# Saída: resultados/oaep_2048.json (tamanhos, tempos e conferências; sem material de chave)

import json
import math
import os
import platform
import sys
import time

import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

TAMANHO_CHAVE = 2048
EXPOENTE_PUBLICO = 65537
TAMANHO_SEGREDO = 32  # bytes, como uma chave de sessão AES-256
PASTA_RESULTADOS = "resultados"

def oaep_sha256():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def cronometro():
    """Tempo de relógio e de CPU, como no shor_rsa_oaep.py."""
    return time.perf_counter(), time.process_time()

def decorrido(inicio):
    t, c = cronometro()
    return {"relogio_s": t - inicio[0], "cpu_s": c - inicio[1]}

"""
Parte 1: reconstrução da chave privada de um RSA-2048 com OAEP a partir de um fator
"""
def recuperacao_2048():
    print("="*76)
    print("PARTE 1: RECONSTRUÇÃO DA CHAVE EM RSA-2048 COM OAEP-SHA256")
    print("="*76)

    # 1. Dona da chave: gera o par e publica (N, e)
    inicio = cronometro()
    chave_original = rsa.generate_private_key(public_exponent=EXPOENTE_PUBLICO, key_size=TAMANHO_CHAVE)
    t_keygen = decorrido(inicio)
    publica = chave_original.public_key()
    N, e = publica.public_numbers().n, publica.public_numbers().e
    pub_der = publica.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = chave_original.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
    print(f"\n[1] Dona da chave gera o par ({t_keygen['relogio_s'] * 1e3:.1f} ms)")
    print(f"    - N com {N.bit_length()} bits, e = {e}")
    print(f"    - Chave pública (DER/SPKI): {len(pub_der)} bytes; privada (DER/PKCS#8): {len(priv_der)} bytes")

    # 2. Remetente: cifra um segredo só com a chave pública
    segredo = os.urandom(TAMANHO_SEGREDO)
    inicio = cronometro()
    ciphertext = publica.encrypt(segredo, oaep_sha256())
    t_cifra = decorrido(inicio)
    print(f"\n[2] Remetente cifra um segredo de {TAMANHO_SEGREDO} bytes com OAEP-SHA256 "
          f"({t_cifra['relogio_s'] * 1e3:.3f} ms)")
    print(f"    - Ciphertext: {len(ciphertext)} bytes")

    # 3. Resolvido o problema matemático (um fator de N), o resto é aritmética.
    #    Aqui p vem da própria chave gerada, no lugar da saída do Shor.
    p = chave_original.private_numbers().p
    inicio = cronometro()
    q = N // p
    assert p * q == N and 1 < p < N, "p não é fator de N"
    # O expoente privado padrão usa a função de Carmichael lambda(N) = lcm(p-1, q-1),
    # como no OpenSSL/PKCS#1; d = e^(-1) mod phi(N) também é válido e decifra igual.
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    d = pow(e, -1, lam)
    # Parâmetros do Teorema Chinês do Resto, que o formato PKCS#1 guarda junto com a chave
    dmp1 = rsa.rsa_crt_dmp1(d, p)
    dmq1 = rsa.rsa_crt_dmq1(d, q)
    iqmp = rsa.rsa_crt_iqmp(p, q)
    numeros = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, rsa.RSAPublicNumbers(e, N))
    chave_reconstruida = numeros.private_key()
    t_recon = decorrido(inicio)
    print(f"\n[3] Com (N, e) e o fator p, a chave privada é reconstruída ({t_recon['relogio_s'] * 1e3:.3f} ms)")
    print(f"    - Só aritmética: q = N/p, lambda(N) = lcm(p-1, q-1), d = e^(-1) mod lambda(N)")

    # 4. Decifra o ciphertext com a chave reconstruída e confere
    inicio = cronometro()
    decifrado = chave_reconstruida.decrypt(ciphertext, oaep_sha256())
    t_decifra = decorrido(inicio)
    confere_segredo = decifrado == segredo
    priv_recon_der = chave_reconstruida.private_bytes(serialization.Encoding.DER,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption())
    confere_chave = priv_recon_der == priv_der
    print(f"\n[4] A chave reconstruída decifra o ciphertext ({t_decifra['relogio_s'] * 1e3:.3f} ms)")
    print(f"    - Segredo recuperado: {'confere' if confere_segredo else 'NÃO confere'}")
    print(f"    - Chave reconstruída idêntica à original: {'sim' if confere_chave else 'não'}")
    print("\n    Conclusão: o OAEP protege o formato da mensagem, mas não o problema de fatorar N.")
    print("    Resolvido esse problema, a chave privada sai por aritmética elementar.")

    return {
        "tamanho_chave_bits": TAMANHO_CHAVE,
        "expoente_publico": e,
        "n_bits": N.bit_length(),
        "pub_der_bytes": len(pub_der),
        "priv_der_bytes": len(priv_der),
        "ciphertext_bytes": len(ciphertext),
        "segredo_bytes": TAMANHO_SEGREDO,
        "segredo_recuperado_confere": confere_segredo,
        "chave_reconstruida_identica": confere_chave,
        "tempo_keygen": t_keygen,
        "tempo_cifragem": t_cifra,
        "tempo_reconstrucao_chave": t_recon,
        "tempo_decifragem": t_decifra,
    }

"""
Parte 2: por que o OAEP não cabe nas instâncias reduzidas do Shor
"""
def limite_tamanho_oaep():
    print("\n" + "="*76)
    print("PARTE 2: TAMANHO MÍNIMO DE MÓDULO PARA O OAEP-SHA256")
    print("="*76)

    # RFC 8017, 7.1.1: a cifragem OAEP exige k >= 2*hLen + 2 bytes, em que k é o tamanho
    # do módulo em bytes e hLen o tamanho do hash. Com SHA-256, hLen = 32 bytes.
    h_len = 32
    k_min = 2 * h_len + 2
    print(f"\n    RFC 8017: k >= 2*hLen + 2. Com SHA-256 (hLen = {h_len} bytes):")
    print(f"    k >= {k_min} bytes, ou seja, módulo de pelo menos {8 * k_min} bits.")
    print(f"    As instâncias do shor_rsa_oaep.py têm no máximo 8 bits, longe desse mínimo:")
    print(f"    o OAEP só pode ser exercitado no tamanho real, como na Parte 1.\n")

    # Confirmação empírica: cifrar a mensagem vazia logo abaixo e logo acima do limite.
    testes = []
    for bits in (520, 528, 536):
        n = (1 << (bits - 1)) | 1  # ímpar com exatamente 'bits' bits (basta para testar o tamanho)
        chave_pub = rsa.RSAPublicNumbers(EXPOENTE_PUBLICO, n).public_key()
        try:
            c = chave_pub.encrypt(b"", oaep_sha256())
            resultado, ok = f"ok ({len(c)} bytes)", True
        except ValueError:
            resultado, ok = "falha (módulo pequeno demais)", False
        print(f"    Módulo de {bits} bits ({bits // 8} bytes), mensagem vazia: {resultado}")
        testes.append({"modulo_bits": bits, "modulo_bytes": bits // 8, "cifra_ok": ok})

    return {"hash": "SHA-256", "h_len_bytes": h_len, "k_min_bytes": k_min,
            "modulo_min_bits": 8 * k_min, "testes_empiricos": testes}

def info_ambiente():
    return {
        "data": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "sistema": platform.platform(),
        "processador": platform.processor() or platform.machine(),
    }

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    os.makedirs(PASTA_RESULTADOS, exist_ok=True)

    dados = {
        "descricao": "Reconstrução da chave privada de um RSA-2048-OAEP a partir de um fator, "
                     "e tamanho mínimo de módulo do OAEP-SHA256.",
        "ambiente": info_ambiente(),
        "parte1_reconstrucao_2048": recuperacao_2048(),
        "parte2_limite_oaep": limite_tamanho_oaep(),
    }
    caminho = f"{PASTA_RESULTADOS}/oaep_2048.json"
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    print(f"\n[✔] Dados salvos em '{caminho}'.\n")

if __name__ == "__main__":
    main()
