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

import time
import math
import numpy as np
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.circuit.library import UnitaryGate
from qiskit.visualization import plot_histogram

# Funções de matemática clássicas (Parâmetro RSA)

def modinv(a, m):
    """
    Calcula o inverso modular de 'a' mod 'm' para obter a chave privada 'd'.
    """
    m0, x0, x1 = m, 0,1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1     

def generate_rsa_params(p, q):
    """
    Gera os parâmetros criptrográficos do RSA a partir dos primos "p" e "q".
    Representa a etapa de configuração da instância do problema.
    """
    N = p * q
    phi = (p -1) * (q - 1)
    e = 3
    while math.gcd(e, phi) !=1:
        e += 2
    d = modinv(e, phi)
    return N, phi, e, d

# Funções quânticas (Óráculo dinâmico e IQFT)

def get_U_matrix(a, N, m):
    """
    Constrói a matriz de permutação unitária para a função f(x) = (x * a) mod N.
    Devido às limitações de síntese clássica no Qiskit 1.x para N genérico sem
    implementar somadores quânticos complexo, sintetizamos a matriz exata para
    instâncias reduzidas.
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

""" 
Tratando exigências do capítulo 3.1 e 3.2 (Crescimento do problema) 
Execução do experimento

4 instâncias reduzidas progressivas;
Representam diferentes tamanhos de chave (N)
"""

instancias = [(3, 5), (3, 7), (3, 11), (5, 7)] 
resultados_metricas = []

simulador = AerSimulator()
shots = 1024

print("=== Início da avaliação experimental: Shor vs RSA-OAEP ===")

for idx, (p, q) in enumerate(instancias):
    N, phi, e, d = generate_rsa_params(p, q)
    tamanho_bits = N.bit_length()

    print(f"\n--- Analisando instância {idx+1}: N={N} ({tamanho_bits} bits) ---")

    # Configuração quântica
    a = 2                       # 'a' coprimo de todos os N escolhidos
    m = math.ceil(math.log2(N)) # Qubits do registrador alvo
    n_count = 2 * m             # Qubits do registrador de contagem para precisão
    total_qubits = n_count + m

    start_time = time.time()

    # 1. Inicialização
    qc = QuantumCircuit(total_qubits, n_count)
    for qubit in range(n_count):
        qc.h(qubit)
    qc.x(n_count)               # Eigenstate |1> no registrador alvo (LSB)

    # 2. Aplicação do Oráculo controlado
    for q_idx in range(n_count):
        a_power = pow(a, 2**q_idx, N)
        mat = get_U_matrix(a_power, N, m)
        gate = UnitaryGate(mat, label=f"U^{2**q_idx}").control(1)
        qc.append(gate, [q_idx] + list(range(n_count, n_count + m)))

    # 3. Aplicação da (IQFT / QFT†) e medição
    qc.append(qft_dagger(n_count), range(n_count))
    qc.measure(range(n_count), range(n_count))

    # 4. Transpilação e simulação
    # optimization_level=1 para balancear tempo de síntese das matrizes e otimização
    qc_transpilado = transpile(qc, simulador, optimization_level=1)

    job = simulador.run(qc_transpilado, shots=shots)
    contagens = job.result().get_counts()

    exec_time = time.time() - start_time

    # 5. Coleta das métricas (Exigência do capítulo 3.1)
    depth = qc_transpilado.depth()
    gates = dict(qc_transpilado.count_ops())
    total_gates = sum(gates.values())
    
    # Aproximação de gates multicontrolados sintetizados
    gates_2q = gates.get('cx', 0) + gates.get('cp', 0) + gates.get('cu', 0) 

    # Avaliando probabilidade do pico correto (Simplificado: os maiores picos)
    max_count = max(contagens.values())
    prob = (max_count / shots) * 100

    resultados_metricas.append({
        'N': N,
        'bits': tamanho_bits,
        'qubits': total_qubits,
        'depth': depth,
        'total_gates': total_gates,
        'time': exec_time
    })

    """ 
    Se for a maior instância (última do loop),
     imprime relatório completo (Exigência do capítulo 3.1 e 4)
    """
    if idx == len(instancias) - 1:
        print("\n" + "="*76)
        print("RELATÓRIO DA MAIOR INSTÂNCIA SOLUCIONADA (3.1)")
        print("="*76)
        print(f"Algoritmo analisado: RSA-OAEP")
        print(f"Tamanho da instância: {tamanho_bits} bits")
        print(f"Parâmetros criptográficos:")
        print(f"  p={p}, q={q}, N={N}, phi(N)={phi}")
        print(f"  Chave Pública (N, e): ({N}, {e})")
        print(f"  Chave Privada (d): {d} (Recuperável via Shor)")
        print(f"\nMétricas do Circuito Quântico:")
        print(f"  Número de Qubits: {total_qubits}")
        print(f"  Profundidade (Depth): {depth}")
        print(f"  Total de Gates: {total_gates}")
        print(f"  Shots executados: {shots}")
        print(f"  Maior probabilidade de pico: {prob:.2f}%")
        print(f"  Tempo total de execução: {exec_time:.2f} segundos")
        print("="*76)
        
        plot_histogram(contagens, title=f"Distribuição para N={N}", figsize=(12, 6))
        plt.savefig(f"shor_rsa_oaep_histograma_N{N}.png")
        print(f"\n[✔] Histograma da maior instância salvo como: \n'shor_rsa_oaep_histograma_N{N}.png'.")

        # Executa a análise do capítulo 4 passando os dados da maior instância
        analise_capitulo4(tamanho_bits, total_qubits, depth, total_gates)

"""
Gráficos: (Crescimento do problema - exigência do capítulo 3.2)
"""
bist_list   = [res['bits']        for res in resultados_metricas]
qubits_list = [res['qubits']      for res in resultados_metricas]
depth_list  = [res['depth']       for res in resultados_metricas]
gates_list  = [res['total_gates'] for res in resultados_metricas]
time_list   = [res['time']        for res in resultados_metricas]

fig, axs = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Crescimento do problema e recursos quânticos (Cápitulo 3.2)')

axs[0, 0].plot(bist_list, qubits_list, marker='o', color='b')
axs[0, 0].set_title('Número de qubit x tamanho da chave')
axs[0, 0].set_xlabel('Tamanho da chave (bits)')
axs[0, 0].set_ylabel('Qubits lógicos')

axs[0, 1].plot(bist_list, depth_list, marker='s', color='r')
axs[0, 1].set_title('Circuito Depth x tamanho da chave')
axs[0, 1].set_xlabel('Tamanho da chave (bits)')
axs[0, 1].set_ylabel('Profundidade do circuito')

axs[1, 0].plot(bist_list, gates_list, marker='^', color='g')
axs[1, 0].set_title('Número de gates x tamanho da chave')
axs[1, 0].set_xlabel('Tamanho da chave (bits)')
axs[1, 0].set_ylabel('Total de gates')

axs[1, 1].plot(bist_list, time_list, marker='d', color='purple')
axs[1, 1].set_title('Tempo de execução x tamanho da chave')
axs[1, 1].set_xlabel('Tamanho da chave (bits)')
axs[1, 1].set_ylabel('Tempo (segundos)')

plt.tight_layout()
plt.savefig("shor_rsa_oaep_crescimento_problema.png")
print(f"\n[✔] Gráficos de crescimento salvos como: \n'shor_rsa_oaep_crescimento_problema.png'.")
print(f"\n=== Experimento concluído com sucesso ===")