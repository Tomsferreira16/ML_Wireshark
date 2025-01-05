#!/usr/bin/env python

import os
import sys
import subprocess
import pandas as pd
import joblib
import ipaddress
import time

# Parameters for continuous packet capture
capture_duration = 60  # Capture for 60 seconds, adjust as needed
interface = "eth0"  # Replace with your network interface (e.g., eth0, wlan0)
pcap_output_dir = "/home/tomas/Desktop"  # Directory to save pcap files

# Function to start the packet capture and save it to a pcap file
def capture_packets():
    timestamp = int(time.time())  # Using the current timestamp as filename
    pcap_file = os.path.join(pcap_output_dir, f"capture_{timestamp}.pcap")

    capture_cmd = [
        "tshark", "-i", interface, "-a", f"duration:{capture_duration}", "-w", pcap_file
    ]

    try:
        subprocess.run(capture_cmd, check=True)
        print(f"Pacotes capturados e salvos em {pcap_file}")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao capturar pacotes: {e}")
        sys.exit(1)

    return pcap_file

# Step 1: Capture and convert pcap to CSV using tshark
def convert_pcap_to_csv(pcap_file):
    output_csv = pcap_file.replace(".pcap", ".csv")
    tshark_cmd = (
        f"tshark -r {pcap_file} -T fields -E header=y -E separator=, -E quote=d -E occurrence=f "
        "-e ip.src -e ip.dst -e ip.len -e ip.flags.df -e ip.flags.mf -e ip.fragment "
        "-e ip.fragment.count -e ip.fragments -e ip.ttl -e ip.proto -e tcp.window_size "
        "-e tcp.ack -e tcp.seq -e tcp.len -e tcp.stream -e tcp.urgent_pointer -e tcp.flags "
        "-e tcp.analysis.ack_rtt -e tcp.segments -e tcp.reassembled.length -e http.request -e udp.port "
        "-e frame.time_relative -e frame.time_delta -e tcp.time_relative -e tcp.time_delta "
        f"> {output_csv}"
    )

    try:
        subprocess.run(tshark_cmd, check=True, shell=True)
        print(f"PCAP convertido para CSV: {output_csv}")
    except subprocess.CalledProcessError as e:
        print(f"Erro ao converter o pcap para CSV: {e}")
        sys.exit(1)

    return output_csv

# Step 2: Clean the CSV file
def clean_csv(filename):
    try:
        file1 = pd.read_csv(filename)

        # Preenche valores nulos com 0
        update_file = file1.fillna(0)

        # Converte todos os valores True/False para 1/0
        update_file = update_file.replace({True: 1, False: 0})

        # Converte colunas específicas para inteiros
        update_file['ip.src'] = update_file['ip.src'].apply(lambda x: int(ipaddress.IPv4Address(x)) if pd.notnull(x) else 0)
        update_file['ip.dst'] = update_file['ip.dst'].apply(lambda x: int(ipaddress.IPv4Address(x)) if pd.notnull(x) else 0)
        update_file['tcp.flags'] = update_file['tcp.flags'].apply(lambda x: int(str(x), 16) if pd.notnull(x) else 0)

        # Salva o DataFrame atualizado em um novo ficheiro
        output_filename = 'updated_' + filename
        update_file.to_csv(output_filename, index=False)
        print(f"Ficheiro atualizado salvo como: {output_filename}")
        return output_filename
    except Exception as e:
        print(f"Erro ao limpar o ficheiro CSV: {e}")
        sys.exit(1)

# Step 3: Use the cleaned data for prediction
def predict_with_model(data_file):
    try:
        # Carrega o modelo treinado
        model = joblib.load("j48_model.pkl")

        # Carrega os dados limpos
        data = pd.read_csv(data_file)

        # Verifica se as colunas necessárias estão presentes
        expected_columns = [
            "ip.src", "ip.dst", "ip.len", "ip.flags.df", "ip.flags.mf", "ip.fragment", 
            "ip.fragment.count", "ip.fragments", "ip.ttl", "ip.proto", "tcp.window_size", 
            "tcp.ack", "tcp.seq", "tcp.len", "tcp.stream", "tcp.urgent_pointer", 
            "tcp.flags", "tcp.analysis.ack_rtt", "tcp.segments", "tcp.reassembled.length", 
            "http.request", "udp.port", "frame.time_relative", "frame.time_delta", 
            "tcp.time_relative", "tcp.time_delta"
        ]

        # Verifica se todas as colunas necessárias estão no ficheiro
        missing_columns = set(expected_columns) - set(data.columns)
        if missing_columns:
            raise ValueError(f"As seguintes colunas estão faltando no ficheiro: {missing_columns}")

        # Realiza as previsões
        predictions = model.predict(data)

        # Adiciona as previsões ao dataset
        data["Prediction"] = predictions

        # Salva as previsões em um novo arquivo
        output_path = "predicted_data.csv"
        data.to_csv(output_path, index=False)

        print(f"Previsões salvas em {output_path}")
    except Exception as e:
        print(f"Erro ao realizar previsões: {e}")
        sys.exit(1)

# Main execution
if __name__ == "__main__":
    # Continuously capture packets and process them
    while True:
        # Capture packets and convert them to CSV
        pcap_file = capture_packets()
        csv_file = convert_pcap_to_csv(pcap_file)

        # Clean the CSV data
        cleaned_file = clean_csv(csv_file)

        # Make predictions with the cleaned data
        predict_with_model(cleaned_file)

        # Wait for a short duration before capturing again (e.g., 60 seconds)
        print("\nAguardando antes da próxima captura...\n")
        time.sleep(60)  # Adjust the sleep time as needed
