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
    mo0, x0, x1 = m, 0,1
    if m == 1:
        return 0
    while a > 1:
        q = z // m
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