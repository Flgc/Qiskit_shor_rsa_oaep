# Algoritmo de Shor - Avaliação experimental: Criptografia RSA-OAEP
# Item 7 da tabela 1 da atividade em grupo - 28/09/2026
# Alunos: Adriel Nascimento | Fábio Luís
# Disciplina: [2026.2] Computação Quântica para Defesa Cibernética

# Objetivo: Analisar experimentalmente a vulnerabilidade da fatoração de N=p*q
#           (problema subjacente ao RSA-OAEP) frente à computação quântica.
# Adaptações: Atendimento aos requisitos dos Capítulos 1 a 3.2 do documento de avaliação.
# O grupo deverá construir uma versão reduzida e experimentalmente tratável do problema
# criptográfico correspondente, aplicar o algoritmo de Shor ao problema matemático
# subjacente e, posteriormente, propor uma estratégia de migração para um algoritmo de
# criptografia pós-quântica, ou Post-Quantum Cryptography (PQC).

# Cadeia do experimento:
#   1. A "vítima" gera um par de chaves RSA reduzido (p, q, N, e, d).
#   2. O atacante recebe apenas a chave pública (N, e).
#   3. Parte quântica: o circuito de Shor estima a fase s/r, em que r é a ordem
#      de 'a' módulo N (o menor r com a^r = 1 mod N).
#   4. Parte clássica (pós-processamento): frações contínuas transformam a
#      medição em r; mdc(a^(r/2) +- 1, N) devolve p e q.
#   5. Com p e q, o atacante calcula phi(N) e d, e decifra uma mensagem.
#
# Execução:
#   python3 shor_rsa_oaep.py                       (instâncias padrão: 3x5 3x7 3x11 7x11)
#   python3 shor_rsa_oaep.py --instancias 3x5 7x11 (instâncias escolhidas, no formato p x q)
#
# Saídas em resultados/: shor_resultados.json (dados brutos, inclusive as contagens),
# shor_resumo.csv, um histograma por instância e os gráficos de crescimento (3.2).

import argparse
import csv
import json
import math
import os
import platform
import random
import sys
import time
from collections import Counter
from datetime import datetime
from fractions import Fraction

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import qiskit
import qiskit_aer
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import UnitaryGate

# Parâmetros do experimento (documentados em resultados/shor_resultados.json)

# A instância (5, 7) da versão anterior deu lugar a (7, 11): N=33 e N=35 têm os dois
# 6 bits, o que deixava só 3 tamanhos diferentes. Além disso, com N=35 todo expoente
# válido tem d = e (ver verificacao/d_igual_e_N35.py), e a recuperação de d não
# ficaria visível.
INSTANCIAS_PADRAO = [(3, 5), (3, 7), (3, 11), (7, 11)]  # N = 15, 21, 33, 77
SHOTS = 1024
SEED = 2026                                 # semente do sorteio de 'a', da transpilação e do simulador
MAX_TENTATIVAS = 5                          # valores de 'a' testados por instância
BASE_GATES = ["cx", "rz", "sx", "x"]        # conjunto de portas nativas típico dos processadores IBM
OTIMIZACAO = 1
PASTA_RESULTADOS = "resultados"

# Funções de matemática clássicas (Parâmetro RSA)

def modinv(a, m):
    """
    Calcula o inverso modular de 'a' mod 'm' para obter a chave privada 'd'.
    """
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def generate_rsa_params(p, q):
    """
    Gera os parâmetros criptográficos do RSA a partir dos primos "p" e "q".
    Representa a etapa de configuração da instância do problema.
    """
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while math.gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return N, phi, e, d

def ordem_classica(a, N):
    """
    Ordem de 'a' mod N por força bruta. Usada só para conferir o resultado do
    Shor (picos esperados e taxa de acerto de r); o ataque não usa esta função.
    """
    r, x = 1, a % N
    while x != 1:
        x = (x * a) % N
        r += 1
    return r

# Funções quânticas (Oráculo dinâmico e IQFT)

def get_U_matrix(a, N, m):
    """
    Constrói a matriz de permutação unitária para a função f(x) = (x * a) mod N.
    Devido às limitações de síntese clássica no Qiskit para N genérico sem
    implementar somadores quânticos complexos, sintetizamos a matriz exata para
    instâncias reduzidas.

    A matriz tem 2^m x 2^m entradas, e o custo de sintetizá-la em portas cresce
    exponencialmente com m. É esse custo clássico que limita o tamanho das
    instâncias neste experimento (ver tempo_montagem_s nos resultados).
    """
    size = 2**m
    U = np.zeros((size, size))
    for y in range(size):
        if y < N:
            target = (y * a) % N
            U[target, y] = 1
        else:
            U[y, y] = 1 # Identidade para estados além de N
    return U

def qft_dagger(n):
    """Transformada de Fourier Quântica Inversa (IQFT ou QFT†)"""
    qc = QuantumCircuit(n, name="QFT†")
    for qubit in range(n // 2):
        qc.swap(qubit, n - qubit - 1)
    for j in range(n):
        for m in range(j):
            qc.cp(-np.pi / float(2**(j - m)), m, j)
        qc.h(j)
    return qc.to_gate()

def montar_circuito(N, a):
    """
    Circuito de estimativa de fase para a ordem de 'a' mod N.
    Registrador de contagem com 2m qubits (precisão) e registrador alvo com m qubits.
    """
    m = math.ceil(math.log2(N))  # Qubits do registrador alvo
    n_count = 2 * m              # Qubits do registrador de contagem para precisão

    # 1. Inicialização
    qc = QuantumCircuit(n_count + m, n_count)
    for qubit in range(n_count):
        qc.h(qubit)
    qc.x(n_count)                # Eigenstate |1> no registrador alvo (LSB)

    # 2. Aplicação do Oráculo controlado
    for q_idx in range(n_count):
        a_power = pow(a, 2**q_idx, N)
        mat = get_U_matrix(a_power, N, m)
        gate = UnitaryGate(mat, label=f"U^{2**q_idx}").control(1)
        qc.append(gate, [q_idx] + list(range(n_count, n_count + m)))

    # 3. Aplicação da (IQFT / QFT†) e medição
    qc.append(qft_dagger(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))
    return qc, n_count, m

# Pós-processamento clássico (o que transforma a medição em chave privada)

def ordem_candidata(medida, n_count, N):
    """
    Frações contínuas: aproxima medida / 2^n_count por uma fração s/r com
    denominador r <= N e devolve r.
    """
    return Fraction(medida, 2**n_count).limit_denominator(N).denominator

def pos_processamento(bitstring, n_count, a, N):
    """
    Tenta obter os fatores de N a partir de uma única medição.
    Devolve (p, q, r, motivo). Se a medição não serve, p e q são None e
    'motivo' explica por quê.
    """
    medida = int(bitstring, 2)
    if medida == 0:
        return None, None, None, "medição 0 (não informa r)"
    r = ordem_candidata(medida, n_count, N)
    if pow(a, r, N) != 1:
        return None, None, r, "r candidato não é a ordem"
    if r % 2 == 1:
        return None, None, r, "ordem ímpar"
    x = pow(a, r // 2, N)
    if x == N - 1:
        return None, None, r, "a^(r/2) = -1 mod N"
    for fator in (math.gcd(x - 1, N), math.gcd(x + 1, N)):
        if 1 < fator < N:
            return fator, N // fator, r, "ok"
    return None, None, r, "mdc trivial"

def a_referencia(N):
    """
    Base usada só para medir o crescimento dos recursos (capítulo 3.2): o menor 'a'
    com a maior ordem possível mod N. No oráculo compilado, U^(2^j) vira a identidade
    quando r divide 2^j, e o circuito encolhe; com a ordem máxima isso acontece o
    mínimo possível, e o custo medido deixa de depender do 'a' sorteado no ataque.
    """
    candidatos = [a for a in range(2, N - 1) if math.gcd(a, N) == 1]
    ordens = {a: ordem_classica(a, N) for a in candidatos}
    r_max = max(ordens.values())
    return min(a for a in candidatos if ordens[a] == r_max)

def sortear_a(N, rng, descartados):
    """
    Sorteia 'a' em [2, N-2]. Se mdc(a, N) > 1, o fator sairia sem Shor; o
    sorteio é registrado e descartado, porque o objetivo é exercitar a parte quântica.
    """
    while True:
        a = rng.randrange(2, N - 1)
        if math.gcd(a, N) == 1:
            return a
        descartados.append(a)

def executar_shor(N, a, simulador):
    """
    Monta, transpila e simula o circuito para (N, a) e aplica o pós-processamento
    a cada medição. Devolve as métricas exigidas no capítulo 3.1.
    """
    # Dois relógios: perf_counter mede o tempo de parede (o que se espera na prática) e
    # process_time mede a CPU gasta por este processo, que quase não muda quando outros
    # programas disputam a máquina. Na simulação, process_time soma as threads do Aer.
    t0, c0 = time.perf_counter(), time.process_time()
    qc, n_count, m = montar_circuito(N, a)
    t1, c1 = time.perf_counter(), time.process_time()

    # Transpilação para portas nativas (cx, rz, sx, x): é sobre este circuito que
    # profundidade e número de portas são medidos, e é ele que vai ao simulador.
    qc_base = transpile(qc, basis_gates=BASE_GATES, optimization_level=OTIMIZACAO,
                        seed_transpiler=SEED)
    t2, c2 = time.perf_counter(), time.process_time()

    contagens = simulador.run(qc_base, shots=SHOTS, seed_simulator=SEED).result().get_counts()
    t3, c3 = time.perf_counter(), time.process_time()

    r_real = ordem_classica(a, N)
    sucessos, ordem_certa = 0, 0
    motivos = Counter()
    fatores = Counter()
    for bitstring, c in contagens.items():
        p_rec, q_rec, r_cand, motivo = pos_processamento(bitstring, n_count, a, N)
        motivos[motivo] += c
        if r_cand == r_real:
            ordem_certa += c
        if p_rec is not None:
            sucessos += c
            fatores[(min(p_rec, q_rec), max(p_rec, q_rec))] += c
    t4 = time.perf_counter()

    ops = dict(qc_base.count_ops())
    eh_2q = lambda instr: instr.operation.num_qubits == 2
    portas = sum(v for k, v in ops.items() if k not in ("measure", "barrier"))
    portas_2q = sum(1 for instr in qc_base.data if eh_2q(instr))

    return {
        "a": a,
        "r_verdadeiro": r_real,
        "qubits": qc.num_qubits,
        "qubits_contagem": n_count,
        "qubits_alvo": m,
        "profundidade": qc_base.depth(),
        "profundidade_2q": qc_base.depth(eh_2q),
        "portas_total": portas,
        "portas_2q": portas_2q,
        "portas_por_tipo": ops,
        "shots": SHOTS,
        "contagens": contagens,
        "prob_sucesso": sucessos / SHOTS,
        "prob_ordem_correta": ordem_certa / SHOTS,
        "maior_pico": max(contagens.values()) / SHOTS,
        "motivos": dict(motivos),
        "fatores_encontrados": {f"{p}x{q}": c for (p, q), c in fatores.items()},
        "tempo_montagem_s": t1 - t0,
        "tempo_transpilacao_s": t2 - t1,
        "tempo_simulacao_s": t3 - t2,
        "tempo_pos_processamento_s": t4 - t3,
        "tempo_total_s": t4 - t0,
        "cpu_montagem_s": c1 - c0,
        "cpu_transpilacao_s": c2 - c1,
        "cpu_simulacao_s": c3 - c2,
    }

def atacar_rsa(N, e, simulador):
    """
    O atacante conhece apenas a chave pública (N, e). Sorteia 'a', roda o Shor e,
    se nenhuma medição fatorar N, tenta outro 'a'. Com p e q recupera d.
    """
    rng = random.Random(SEED * 1000 + N)
    tentativas = []
    for t in range(1, MAX_TENTATIVAS + 1):
        descartados = []
        a = sortear_a(N, rng, descartados)
        res = executar_shor(N, a, simulador)
        res["tentativa"] = t
        res["a_descartados_mdc"] = descartados
        tentativas.append(res)

        if res["prob_sucesso"] > 0:
            print(f"    tentativa {t}: a={a}, sucesso em {100 * res['prob_sucesso']:.2f}% dos shots "
                  f"({res['tempo_total_s']:.1f} s)")
            fator_str = max(res["fatores_encontrados"], key=res["fatores_encontrados"].get)
            p_rec, q_rec = map(int, fator_str.split("x"))
            phi_rec = (p_rec - 1) * (q_rec - 1)
            d_rec = modinv(e, phi_rec)
            return tentativas, p_rec, q_rec, d_rec

        motivo = max(res["motivos"], key=res["motivos"].get)
        print(f"    tentativa {t}: a={a}, nenhuma medição fatorou N "
              f"(motivo mais comum: {motivo}); sorteando outro a")
    return tentativas, None, None, None

"""
Análise teórica e comparativa (exigências do capítulo 4 )
"""
def analise_capitulo4(bits_exp, qubits_exp, depth_exp, gates_exp):
    """
    Gera o relatório comparativo entre o experimento reduzido e um
    criptográfico utilizado em sistemas reais (RSA-2048). abordando
    as limitações do hardware quântico atual.
    """
    print("\n"+ "="*76)
    print("COMPARAÇÃO COM PARÂMETROS CRIPTOGRÁFICOS REAIS  (Cápitulo 4)")
    print("="*76)

    print(f"[1] COMPARAÇÃO DE ESCALA (Experimento vs. RSA-2048):")
    print("    ")
    print(f"    - Tamanho da chave........: {bits_exp} bits (Exp) vs 2048 bits (Real)")
    print(f"    - Qubits lógicos estimados: {qubits_exp} (Exp) vs ~4.096 a 6.144 (Real)")
    print(f"    - Profundidade do circuito: {depth_exp} (Exp) vs Trilhões de operações (Real)")

    print("\n[2] DISCUSSÃO DE VULNERABILIDADE (Teoria vs. prática):")
    print("    ")
    print("    Por que o experimento demonstra a vulnerabilidade algorítmica, mas")
    print("    não significa a quebra imediata de sistemas reais?")
    print("    ")
    print("    O algoritmo de Shor comprova matematicamente que a fatoração possui")
    print("    complexidade polinomial em computadores quânticos. No entanto, a")
    print("    execução para RSA-2048 em hardware real esbarra em severas limitações:")
    print("    ")
    print("    * Qubits físicos vs lógicos e QEC: Para obter ~4.000 qubits lógicos")
    print("      estáveis, devido à Correção Quântica de Erros (QEC), seriam")
    print("      necessários cerca de 20 milhões de qubits físicos ruidosos.")
    print("    ")
    print("    * Decoerência e fidelidade: O tempo de coerência dos qubits atuais")
    print("      é muito curto para suportar a profundidade extrema do oráculo modular")
    print("      do RSA-2048 sem que o ruído destrua a superposição.")
    print("    ")
    print("    * Conectividade e custo aritmético: Portas Toffoli e somadores quânticos")
    print("      exigem alta conectividade (SWAP gates). O custo de implementação de")
    print("      operações aritméticas quânticas cresce substancialmente na prática.")
    print("="*76)

# Saídas: histogramas, gráficos e dados brutos

def salvar_histograma(inst):
    """
    Distribuição das medições da tentativa bem-sucedida. As linhas tracejadas marcam
    os picos esperados j * 2^n / r (calculados com a ordem verdadeira, só para conferência).
    """
    N, a, n = inst["N"], inst["a"], inst["qubits_contagem"]
    xs_ok, ys_ok, xs_falha, ys_falha = [], [], [], []
    for bitstring, c in inst["contagens"].items():
        if pos_processamento(bitstring, n, a, N)[0] is not None:
            xs_ok.append(int(bitstring, 2)); ys_ok.append(c)
        else:
            xs_falha.append(int(bitstring, 2)); ys_falha.append(c)

    fig, ax = plt.subplots(figsize=(12, 5))
    r = inst["r_verdadeiro"]
    for j in range(r):
        ax.axvline(j * 2**n / r, color="tab:red", linestyle="--", linewidth=0.7, alpha=0.6,
                   label="picos esperados j·2^n/r" if j == 0 else None)
    ax.vlines(xs_falha, 0, ys_falha, color="tab:gray", linewidth=2, label="medição que não fatora N")
    ax.vlines(xs_ok, 0, ys_ok, color="tab:green", linewidth=2, label="medição que fatora N")
    ax.set_xlim(-0.01 * 2**n, 1.01 * 2**n)
    ax.set_ylim(bottom=0)
    ax.set_xlabel(f"Valor medido no registrador de contagem (0 a 2^{n} - 1)")
    ax.set_ylabel(f"Contagem ({inst['shots']} shots)")
    ax.set_title(f"Distribuição das medições para N={N}, a={a}, r={r} "
                 f"(sucesso em {100 * inst['prob_sucesso']:.1f}% dos shots)")
    ax.legend(loc="upper right")
    plt.tight_layout()
    caminho = f"{PASTA_RESULTADOS}/shor_histograma_N{N}.png"
    plt.savefig(caminho)
    plt.close(fig)
    return caminho

def salvar_graficos_crescimento(instancias):
    """
    Gráficos: (Crescimento do problema - exigência do capítulo 3.2)
    As linhas usam o circuito de referência ('a' de ordem máxima) de cada instância.
    Os pontos cinza são as tentativas do ataque: o custo do oráculo compilado também
    depende da ordem r do 'a' sorteado. Escala logarítmica onde o crescimento é exponencial.
    """
    bits_list = [i["bits"] for i in instancias]
    tentativas = [(i["bits"], t) for i in instancias for t in i["tentativas"]]

    def pontos_tentativas(ax, chave):
        ax.scatter([b for b, _ in tentativas], [t[chave] for _, t in tentativas], color="gray",
                   alpha=0.6, s=25, zorder=3, label="tentativas do ataque (custo depende de r)")

    fig, axs = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Crescimento do problema e recursos quânticos (Capítulo 3.2)\n"
                 "linhas: circuito de referência com 'a' de ordem máxima")

    axs[0, 0].plot(bits_list, [i["qubits"] for i in instancias], marker="o", color="b")
    axs[0, 0].set_title("Número de qubits x tamanho da chave")
    axs[0, 0].set_ylabel("Qubits lógicos")

    axs[0, 1].plot(bits_list, [i["ref_profundidade"] for i in instancias], marker="s", color="r", label="total")
    axs[0, 1].plot(bits_list, [i["ref_profundidade_2q"] for i in instancias], marker="s", color="r",
                   linestyle="--", label="só portas de 2 qubits")
    pontos_tentativas(axs[0, 1], "profundidade")
    axs[0, 1].set_title("Profundidade do circuito x tamanho da chave")
    axs[0, 1].set_ylabel("Profundidade (escala log)")

    axs[1, 0].plot(bits_list, [i["ref_portas_total"] for i in instancias], marker="^", color="g", label="total")
    axs[1, 0].plot(bits_list, [i["ref_portas_2q"] for i in instancias], marker="^", color="g",
                   linestyle="--", label="portas de 2 qubits (cx)")
    pontos_tentativas(axs[1, 0], "portas_total")
    axs[1, 0].set_title("Número de portas x tamanho da chave")
    axs[1, 0].set_ylabel("Portas (escala log)")

    axs[1, 1].plot(bits_list, [i["ref_tempo_montagem_s"] for i in instancias], marker="d", color="purple",
                   label="montagem do oráculo (síntese)")
    axs[1, 1].plot(bits_list, [i["ref_tempo_simulacao_s"] for i in instancias], marker="d", color="orange",
                   label="simulação")
    axs[1, 1].plot(bits_list, [i["ref_tempo_total_s"] for i in instancias], marker="d", color="black",
                   linestyle="--", label="total")
    pontos_tentativas(axs[1, 1], "tempo_total_s")
    axs[1, 1].set_title("Tempo de execução x tamanho da chave")
    axs[1, 1].set_ylabel("Tempo em segundos (escala log)")

    for ax in axs.flat:
        ax.set_xlabel("Tamanho da chave (bits)")
        ax.set_xticks(bits_list)
        ax.grid(alpha=0.3)
    for ax in (axs[0, 1], axs[1, 0], axs[1, 1]):
        ax.set_yscale("log")
        ax.legend()

    plt.tight_layout()
    caminho = f"{PASTA_RESULTADOS}/shor_crescimento_recursos.png"
    plt.savefig(caminho)
    plt.close(fig)

    # Probabilidade de sucesso por instância, ao lado da métrica usada na versão anterior
    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(instancias))
    largura = 0.38
    ax.bar(x - largura / 2, [100 * i["prob_sucesso"] for i in instancias], largura,
           color="tab:green", label="shots que fatoram N (probabilidade de sucesso)")
    ax.bar(x + largura / 2, [100 * i["maior_pico"] for i in instancias], largura,
           color="tab:gray", label="maior pico do histograma (métrica da versão anterior)")
    ax.set_xticks(x)
    ax.set_xticklabels([f"N={i['N']}\n({i['bits']} bits)" for i in instancias])
    ax.set_ylabel("% dos shots")
    ax.set_title("Probabilidade de obter a solução correta (Capítulo 3.1)")
    ax.legend()
    plt.tight_layout()
    caminho_prob = f"{PASTA_RESULTADOS}/shor_probabilidade_sucesso.png"
    plt.savefig(caminho_prob)
    plt.close(fig)
    return caminho, caminho_prob

def info_ambiente():
    """Versões e máquina, para a reprodução (capítulo 9)."""
    return {
        "data": datetime.now().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "qiskit": qiskit.__version__,
        "qiskit_aer": qiskit_aer.__version__,
        "numpy": np.__version__,
        "matplotlib": matplotlib.__version__,
        "sistema": platform.platform(),
        "processador": platform.processor() or platform.machine(),
        "nucleos_logicos": os.cpu_count(),
    }

def salvar_dados(instancias, ambiente):
    """Dados brutos (JSON, com as contagens de todas as tentativas) e resumo (CSV)."""
    dados = {
        "experimento": {
            "algoritmo": "RSA-OAEP (problema subjacente: fatoração de N = p*q)",
            "shots": SHOTS,
            "seed": SEED,
            "max_tentativas": MAX_TENTATIVAS,
            "base_gates": BASE_GATES,
            "optimization_level": OTIMIZACAO,
            "simulador": "AerSimulator (ideal, sem ruído)",
            "a_do_ataque": "sorteado com random.Random(seed * 1000 + N); nova tentativa se nenhuma medição fatorar N",
            "a_de_referencia_3_2": "menor a de ordem máxima mod N, usado só para os gráficos de crescimento",
        },
        "ambiente": ambiente,
        "instancias": instancias,
    }
    caminho_json = f"{PASTA_RESULTADOS}/shor_resultados.json"
    with open(caminho_json, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)

    colunas = ["N", "bits", "p", "q", "phi", "e", "d", "d_recuperado", "chave_confere", "a",
               "r_verdadeiro", "num_tentativas", "qubits", "profundidade", "profundidade_2q",
               "portas_total", "portas_2q", "shots", "prob_sucesso", "prob_ordem_correta",
               "maior_pico", "tempo_montagem_s", "tempo_transpilacao_s", "tempo_simulacao_s",
               "tempo_total_s", "tempo_todas_tentativas_s", "ref_a", "ref_r_verdadeiro",
               "ref_profundidade", "ref_profundidade_2q", "ref_portas_total", "ref_portas_2q",
               "ref_tempo_montagem_s", "ref_tempo_transpilacao_s", "ref_tempo_simulacao_s",
               "ref_tempo_total_s", "cpu_montagem_s", "cpu_simulacao_s", "ref_cpu_montagem_s",
               "ref_cpu_simulacao_s"]
    caminho_csv = f"{PASTA_RESULTADOS}/shor_resumo.csv"
    with open(caminho_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=colunas, extrasaction="ignore")
        w.writeheader()
        for inst in instancias:
            w.writerow(inst)
    return caminho_json, caminho_csv

def ler_instancias(argv):
    parser = argparse.ArgumentParser(description="Shor contra instâncias reduzidas de RSA")
    parser.add_argument("--instancias", nargs="+", metavar="PxQ",
                        help="pares de primos no formato p x q, por exemplo 3x5 7x11")
    args = parser.parse_args(argv)
    if not args.instancias:
        return INSTANCIAS_PADRAO
    return [tuple(int(v) for v in par.lower().split("x")) for par in args.instancias]

"""
Tratando exigências do capítulo 3.1 e 3.2 (Crescimento do problema)
Execução do experimento
"""
def main(argv=None):
    # Acentos e símbolos no terminal do Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    instancias_pq = ler_instancias(argv)
    os.makedirs(PASTA_RESULTADOS, exist_ok=True)
    simulador = AerSimulator()
    instancias = []

    print("=== Início da avaliação experimental: Shor vs RSA-OAEP ===")

    for idx, (p, q) in enumerate(instancias_pq):
        # Vítima: gera as chaves. O atacante só recebe (N, e).
        N, phi, e, d = generate_rsa_params(p, q)
        print(f"\n--- Analisando instância {idx+1}: N={N} ({N.bit_length()} bits), "
              f"chave pública (N, e) = ({N}, {e}) ---")

        tentativas, p_rec, q_rec, d_rec = atacar_rsa(N, e, simulador)
        if d_rec is None:
            print(f"    Nenhum dos {MAX_TENTATIVAS} valores de a fatorou N={N}.")
            continue

        # Teste da chave recuperada: decifrar uma mensagem cifrada com a chave pública.
        # Pontos fixos (m^e = m mod N) são evitados, porque neles cifrar não muda nada.
        rng_msg = random.Random(SEED + N)
        mensagem = rng_msg.randrange(2, N)
        while pow(mensagem, e, N) == mensagem:
            mensagem = rng_msg.randrange(2, N)
        cifrada = pow(mensagem, e, N)
        decifrada = pow(cifrada, d_rec, N)
        print(f"    p={p_rec}, q={q_rec} -> d recuperado={d_rec} "
              f"({'confere' if d_rec == d else 'NÃO confere'} com a chave original); "
              f"mensagem {mensagem} -> cifrada {cifrada} -> decifrada {decifrada}")

        final = tentativas[-1]
        inst = {
            "p": p, "q": q, "N": N, "bits": N.bit_length(), "phi": phi, "e": e, "d": d,
            "p_recuperado": p_rec, "q_recuperado": q_rec, "d_recuperado": d_rec,
            "chave_confere": d_rec == d,
            "mensagem": mensagem, "cifrada": cifrada, "decifrada": decifrada,
            "num_tentativas": len(tentativas),
            "tempo_todas_tentativas_s": sum(t["tempo_total_s"] for t in tentativas),
            **{k: v for k, v in final.items() if k != "tentativa"},
            "tentativas": tentativas,
        }
        inst["histograma"] = salvar_histograma(inst)

        # Circuito de referência para os gráficos de crescimento (3.2). Se o ataque já
        # usou esse 'a', a tentativa é reaproveitada.
        a_ref = a_referencia(N)
        ref = next((t for t in tentativas if t["a"] == a_ref), None)
        if ref is None:
            print(f"    circuito de referência para o 3.2: a={a_ref} "
                  f"(ordem máxima r={ordem_classica(a_ref, N)})")
            ref = executar_shor(N, a_ref, simulador)
        inst["referencia"] = {k: v for k, v in ref.items() if k != "tentativa"}
        for k in ("a", "r_verdadeiro", "profundidade", "profundidade_2q", "portas_total", "portas_2q",
                  "tempo_montagem_s", "tempo_transpilacao_s", "tempo_simulacao_s", "tempo_total_s",
                  "cpu_montagem_s", "cpu_simulacao_s"):
            inst[f"ref_{k}"] = ref[k]
        instancias.append(inst)

    if not instancias:
        print("\nNenhuma instância foi fatorada.")
        return

    # Relatório da maior instância solucionada (exigência do capítulo 3.1)
    maior = max(instancias, key=lambda i: i["N"])
    print("\n" + "="*76)
    print("RELATÓRIO DA MAIOR INSTÂNCIA SOLUCIONADA (3.1)")
    print("="*76)
    print(f"Algoritmo analisado: RSA-OAEP (problema subjacente: fatoração de N)")
    print(f"Tamanho da instância: {maior['bits']} bits")
    print(f"Chave pública (N, e): ({maior['N']}, {maior['e']})")
    print(f"Parâmetros criptográficos originais:")
    print(f"  p={maior['p']}, q={maior['q']}, N={maior['N']}, phi(N)={maior['phi']}, "
          f"e={maior['e']}, d={maior['d']}")
    print(f"Recuperado pelo Shor (a={maior['a']}, ordem r={maior['r_verdadeiro']}):")
    print(f"  p={maior['p_recuperado']}, q={maior['q_recuperado']}, "
          f"d={maior['d_recuperado']} (confere: {'sim' if maior['chave_confere'] else 'não'})")
    print(f"\nMétricas do Circuito Quântico (após transpilação para {', '.join(BASE_GATES)}):")
    print(f"  Número de Qubits: {maior['qubits']} "
          f"({maior['qubits_contagem']} de contagem + {maior['qubits_alvo']} alvo)")
    print(f"  Profundidade (Depth): {maior['profundidade']} "
          f"(só portas de 2 qubits: {maior['profundidade_2q']})")
    print(f"  Total de Gates: {maior['portas_total']}")
    print(f"  Gates de 2 qubits: {maior['portas_2q']}")
    print(f"  Shots executados: {maior['shots']}")
    print(f"  Distribuição das medições: {maior['histograma']}")
    print(f"  Probabilidade de sucesso (shots que fatoram N): {100 * maior['prob_sucesso']:.2f}%")
    print(f"  Probabilidade de obter a ordem exata r: {100 * maior['prob_ordem_correta']:.2f}%")
    print(f"  Tempo total de execução: {maior['tempo_total_s']:.2f} segundos "
          f"(montagem {maior['tempo_montagem_s']:.2f} s, transpilação "
          f"{maior['tempo_transpilacao_s']:.2f} s, simulação {maior['tempo_simulacao_s']:.2f} s)")
    if maior["num_tentativas"] > 1:
        print(f"  Tentativas até achar um 'a' útil: {maior['num_tentativas']} "
              f"({maior['tempo_todas_tentativas_s']:.2f} s no total)")
    print(f"  Circuito de referência do 3.2 (a={maior['ref_a']}, ordem máxima r={maior['ref_r_verdadeiro']}): "
          f"profundidade {maior['ref_profundidade']}, {maior['ref_portas_total']} gates, "
          f"{maior['ref_portas_2q']} de 2 qubits")
    print("="*76)

    # Resumo de todas as instâncias (capítulo 3.2)
    print("\nResumo das instâncias: circuito que recuperou a chave (Capítulo 3.1)")
    print(f"{'N':>4} {'bits':>4} {'a':>3} {'r':>3} {'qubits':>6} {'profund.':>9} {'portas':>9} "
          f"{'2 qubits':>9} {'sucesso':>8} {'montagem':>9} {'simulação':>9}")
    for i in instancias:
        print(f"{i['N']:>4} {i['bits']:>4} {i['a']:>3} {i['r_verdadeiro']:>3} {i['qubits']:>6} "
              f"{i['profundidade']:>9} {i['portas_total']:>9} {i['portas_2q']:>9} "
              f"{100 * i['prob_sucesso']:>7.2f}% {i['tempo_montagem_s']:>8.2f}s "
              f"{i['tempo_simulacao_s']:>8.2f}s")

    print("\nRecursos do circuito de referência, 'a' de ordem máxima (gráficos do Capítulo 3.2)")
    print(f"{'N':>4} {'bits':>4} {'a':>3} {'r':>3} {'qubits':>6} {'profund.':>9} {'portas':>9} "
          f"{'2 qubits':>9} {'montagem':>9} {'simulação':>9}")
    for i in instancias:
        print(f"{i['N']:>4} {i['bits']:>4} {i['ref_a']:>3} {i['ref_r_verdadeiro']:>3} {i['qubits']:>6} "
              f"{i['ref_profundidade']:>9} {i['ref_portas_total']:>9} {i['ref_portas_2q']:>9} "
              f"{i['ref_tempo_montagem_s']:>8.2f}s {i['ref_tempo_simulacao_s']:>8.2f}s")

    # Executa a análise do capítulo 4 passando os dados da maior instância
    analise_capitulo4(maior["bits"], maior["qubits"], maior["profundidade"], maior["portas_total"])

    graf, graf_prob = salvar_graficos_crescimento(instancias)
    caminho_json, caminho_csv = salvar_dados(instancias, info_ambiente())
    print(f"\n[✔] Histogramas salvos em '{PASTA_RESULTADOS}/shor_histograma_N*.png'.")
    print(f"[✔] Gráficos de crescimento salvos como: '{graf}'.")
    print(f"[✔] Probabilidade de sucesso por instância: '{graf_prob}'.")
    print(f"[✔] Dados brutos: '{caminho_json}' e '{caminho_csv}'.")
    print("    ")
    print(f"\n=== Experimento quântico concluído com sucesso (Capítulos 1 a 4) ===")
    print("    ")
    print("==> O fluxo segue agora para a mitigação no script 'pqc_mlkem_migration.py'.\n")

if __name__ == "__main__":
    main()
