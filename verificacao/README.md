# Verificações

Scripts que comprovam pontos usados na revisão do experimento. Cada um roda sozinho, na raiz do repositório e com o ambiente virtual ativo, e grava a saída em `resultados/verificacao/`.

| Script | O que mostra | Saída |
|---|---|---|
| `a2_falha_N33.py` | Com `a = 2` fixo, nenhuma medição fatora N = 33, porque 2^5 = 32 = -1 (mod 33). O "maior pico", métrica da versão anterior, fica em 12% dos shots e não revela a falha. Por isso `a` passou a ser sorteado, com nova tentativa quando falha. | `a2_falha_N33.json` |
| `d_igual_e_N35.py` | Com N = 35 (phi = 24), todo expoente válido tem d = e, então recuperar d não mostra nada além da chave pública. O mesmo vale para N = 15 e N = 21, inevitável nesses tamanhos. Com N = 33 (e = 3, d = 7) e N = 77 (e = 7, d = 43) a recuperação de d fica visível. | `d_igual_e_N35.json` |
| `variancia_rsa_2048.py` | Os tempos do RSA-2048-OAEP variam bastante entre execuções (KeyGen principalmente), então a Tabela 2 precisa de repetições e mediana. Mostra também que `time.perf_counter()` sem subtrair o início devolve a leitura do relógio, origem dos 35532 s de encapsulamento na versão anterior. | `variancia_rsa_2048.json` |

```bash
python3 verificacao/a2_falha_N33.py
python3 verificacao/d_igual_e_N35.py
python3 verificacao/variancia_rsa_2048.py
```

Os demais números citados na revisão saem do próprio `shor_rsa_oaep.py` e ficam em `resultados/shor_resultados.json`: a probabilidade de sucesso por instância (comparada ao maior pico) e os tempos separados de montagem do oráculo, transpilação e simulação, que mostram que a síntese do oráculo é o gargalo.
