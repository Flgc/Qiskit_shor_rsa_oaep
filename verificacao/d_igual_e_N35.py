# Verificação: com N = 35, a chave privada d é sempre igual ao expoente público e
#
# Para N = 35, phi(N) = 24, e todo e coprimo com 24 satisfaz e^2 = 1 (mod 24).
# Logo d = e^(-1) mod 24 = e para qualquer escolha de e, e "recuperar d" não mostra
# nada que já não estivesse na chave pública. Por isso a instância de 6 bits do
# experimento passou a ser N = 33 e a maior passou a ser N = 77. Em N = 15 e N = 21
# acontece o mesmo (phi = 8 e 12), o que é inevitável nesses tamanhos.
#
# O script lista, para cada N, quantos expoentes válidos têm d = e.
#
# Execução (na raiz do repositório): python3 verificacao/d_igual_e_N35.py
# Saída: resultados/verificacao/d_igual_e_N35.json

import json
import math
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

resultado = {}
for p, q in [(3, 5), (3, 7), (3, 11), (5, 7), (7, 11)]:
    N, phi = p * q, (p - 1) * (q - 1)
    pares = [(e, pow(e, -1, phi)) for e in range(3, phi) if math.gcd(e, phi) == 1]
    iguais = sum(1 for e, d in pares if e == d)
    resultado[N] = {"phi": phi, "pares_e_d": pares, "d_igual_e": iguais, "total": len(pares)}
    print(f"N={N:>2} (phi={phi:>2}): {iguais} de {len(pares)} expoentes válidos têm d = e  "
          f"-> {pares[:6]}{' ...' if len(pares) > 6 else ''}")

pasta = os.path.join(RAIZ, "resultados", "verificacao")
os.makedirs(pasta, exist_ok=True)
with open(os.path.join(pasta, "d_igual_e_N35.json"), "w", encoding="utf-8") as f:
    json.dump(resultado, f, ensure_ascii=False, indent=2)
print("Salvo em resultados/verificacao/d_igual_e_N35.json")
