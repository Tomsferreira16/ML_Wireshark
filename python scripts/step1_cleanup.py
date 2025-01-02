#!/usr/bin/env python

import pandas as pd
import sys
import ipaddress

# Verifica se o ficheiro foi fornecido como argumento
if len(sys.argv) < 2:
    print("Erro: Por favor, forneça o nome do ficheiro CSV como argumento.")
    sys.exit(1)

filename = sys.argv[1]

try:
    # Lê o ficheiro CSV
    file1 = pd.read_csv(filename)

    # Mostra os primeiros registos e verifica valores nulos
    print("Primeiros registos:")
    print(file1.head(10))
    print("\nValores nulos por coluna antes do preenchimento:")
    print(file1.isnull().sum())

    # Preenche valores nulos com 0
    update_file = file1.fillna(0)

    # Converte todos os valores True/False para 1/0
    update_file = update_file.replace({True: 1, False: 0})

    # Converte colunas específicas para inteiros (se necessário)
    try:
        update_file['ip.src'] = update_file['ip.src'].apply(lambda x: int(ipaddress.IPv4Address(x)) if pd.notnull(x) else 0)
        update_file['ip.dst'] = update_file['ip.dst'].apply(lambda x: int(ipaddress.IPv4Address(x)) if pd.notnull(x) else 0)
        update_file['tcp.flags'] = update_file['tcp.flags'].apply(lambda x: int(str(x), 16) if pd.notnull(x) else 0)
    except Exception as e:
        print(f"Erro ao converter colunas: {e}")
        sys.exit(1)

    # Salva o DataFrame atualizado em um novo ficheiro
    output_filename = 'updated_' + filename
    update_file.to_csv(output_filename, index=False)

    print(f"Ficheiro atualizado salvo como: {output_filename}")

except FileNotFoundError:
    print(f"Erro: O ficheiro '{filename}' não foi encontrado.")
except pd.errors.EmptyDataError:
    print(f"Erro: O ficheiro '{filename}' está vazio.")
except Exception as e:
    print(f"Ocorreu um erro: {e}")
