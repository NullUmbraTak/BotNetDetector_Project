#!/bin/bash
echo "[*] A preparar o ambiente para o Botnet Detector..."

# Instalar Ruby se não existir
if ! command -v ruby &> /dev/null; then
    echo "[+] A instalar Ruby e ferramentas de compilação..."
    sudo apt-get update && sudo apt-get install -y ruby ruby-dev build-essential
fi

# Instalar as dependências do projeto
echo "[+] A instalar Gems necessárias (httparty, addressable, text)..."
sudo gem install httparty addressable text

# Descarregar a ferramenta diretamente do GitHub
echo "[+] A transferir o motor do Botnet Detector..."
curl -sSLO https://raw.githubusercontent.com/NullUmbraTak/BotNetDetector_Project/main/src_pt/botnet_detector.rb

echo "[*] Operação concluída com sucesso! Para iniciar, execute: ruby botnet_detector.rb"