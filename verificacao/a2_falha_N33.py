# Verificação: com a = 2 fixo, o Shor não fatora N = 33
#
# A versão anterior do shor_rsa_oaep.py usava a = 2 em todas as instâncias e não
# fazia o pós-processamento, então não percebia que N = 33 nunca era fatorado.
# Motivo: a ordem de 2 mod 33 é r = 10 e 2^(r/2) = 2^5 = 32 = -1 (mod 33), o caso
# em que mdc(a^(r/2) +- 1, N) só devolve fatores triviais.
#
# O script roda o mesmo circuito com a = 2 e mostra que:
#   - nenhuma medição fatora N (probabilidade de sucesso 0%);
#   - o "maior pico", métrica usada antes, continua alto e não indica o problema.
#
# Execução (na raiz do repositório): python3 verificacao/a2_falha_N33.py
# Saída: resultados/verificacao/a2_falha_N33.json

import json
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from qiskit_aer import AerSimulator
from shor_rsa_oaep import executar_shor, ordem_classica

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

N, a = 33, 2
r = ordem_classica(a, N)
x = pow(a, r // 2, N)

print(f"N={N}, a={a}: ordem r={r}, a^(r/2) mod N = {x} (N-1 = {N - 1})")
res = executar_shor(N, a, AerSimulator())

print(f"Maior pico do histograma (métrica anterior): {100 * res['maior_pico']:.2f}% dos shots")
print(f"Shots que fatoram N (probabilidade de sucesso): {100 * res['prob_sucesso']:.2f}%")
print("Motivos de falha por shot:")
for motivo, c in sorted(res["motivos"].items(), key=lambda kv: -kv[1]):
    print(f"  {motivo}: {c}")

pasta = os.path.join(RAIZ, "resultados", "verificacao")
os.makedirs(pasta, exist_ok=True)
with open(os.path.join(pasta, "a2_falha_N33.json"), "w", encoding="utf-8") as f:
    json.dump({"N": N, "a": a, "r": r, "a_elevado_r_sobre_2_mod_N": x, **res},
              f, ensure_ascii=False, indent=2)
print("Salvo em resultados/verificacao/a2_falha_N33.json")
