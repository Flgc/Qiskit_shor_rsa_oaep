# Verificação: tempos do RSA-2048-OAEP variam muito de uma execução para outra
#
# Subsídio para a Tabela 2 (capítulo 6.2). Mostra dois pontos:
#   1. Uma única medição não basta: o KeyGen do RSA sorteia primos e o tempo muda
#      bastante entre execuções; a primeira cifragem também costuma ser mais lenta.
#      Por isso a comparação deve usar várias repetições e a mediana.
#   2. Sem subtrair o instante inicial, time.perf_counter() devolve a leitura do
#      relógio (segundos desde um ponto arbitrário), não a duração. Foi o que
#      produziu os 35532 s de encapsulamento na versão anterior da Tabela 2.
#
# Execução (na raiz do repositório): python3 verificacao/variancia_rsa_2048.py
# Saída: resultados/verificacao/variancia_rsa_2048.json (todas as amostras)

import json
import os
import platform
import statistics
import sys
import time

import cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REP_KEYGEN = 30
REP_OPERACOES = 1000

oaep = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

keygen = []
for _ in range(REP_KEYGEN):
    t = time.perf_counter()
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keygen.append(time.perf_counter() - t)

publica = chave.public_key()
segredo = os.urandom(32)
cifragem, decifragem = [], []
for _ in range(REP_OPERACOES):
    t = time.perf_counter()
    c = publica.encrypt(segredo, oaep)
    cifragem.append(time.perf_counter() - t)
    t = time.perf_counter()
    publica_ok = chave.decrypt(c, oaep) == segredo
    decifragem.append(time.perf_counter() - t)
    assert publica_ok

def resumo(nome, v):
    ms = [x * 1e3 for x in v]
    print(f"{nome:<22} n={len(v):>4}  mín {min(ms):8.3f} ms  mediana {statistics.median(ms):8.3f} ms  "
          f"máx {max(ms):8.3f} ms  (máx/mín = {max(v) / min(v):5.1f}x)")
    return {"amostras_s": v, "min_s": min(v), "mediana_s": statistics.median(v), "max_s": max(v)}

print("RSA-2048 com OAEP-SHA256")
dados = {
    "keygen": resumo("KeyGen", keygen),
    "cifragem": resumo("Cifragem (encaps)", cifragem),
    "decifragem": resumo("Decifragem (decaps)", decifragem),
}
print(f"Primeira cifragem: {cifragem[0] * 1e3:.3f} ms; mediana: {statistics.median(cifragem) * 1e3:.3f} ms")

leitura = time.perf_counter()
print(f"\nSem subtrair o início, perf_counter() devolve {leitura:.3f}, que é a leitura do relógio,")
print("não a duração da operação. É o valor que aparecia como tempo de encapsulamento do RSA.")

dados["ambiente"] = {"python": platform.python_version(), "cryptography": cryptography.__version__,
                     "sistema": platform.platform(), "processador": platform.processor() or platform.machine()}
pasta = os.path.join(RAIZ, "resultados", "verificacao")
os.makedirs(pasta, exist_ok=True)
with open(os.path.join(pasta, "variancia_rsa_2048.json"), "w", encoding="utf-8") as f:
    json.dump(dados, f, ensure_ascii=False, indent=2)
print("Salvo em resultados/verificacao/variancia_rsa_2048.json")
