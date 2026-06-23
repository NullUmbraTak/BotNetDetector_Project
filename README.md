# 🕸️ Botnet Detector

Bem-vindo ao repositório do **Botnet Detector**, uma ferramenta de *Threat Intelligence* e simulação de ameaças desenvolvida em Ruby. 

Este projeto foi desenhado para atuar em duas frentes:
1. **Simulação (Red Team):** Um motor de injeção de anomalias capaz de gerar ficheiros de log realistas, simulando ataques de força bruta, comunicações C2 (Beaconing com tolerância a Jitter) e resoluções de domínios maliciosos (DGA).
2. **Deteção (Blue Team):** Um motor de análise analítica que audita ficheiros de log à procura de Indicadores de Compromisso (IoCs), correlacionando IPs externos e calculando anomalias temporais.

## 📂 Arquitetura do Repositório

O repositório está organizado para suportar múltiplos idiomas. O código fonte e a respetiva estrutura de diretórios isolada encontram-se nas pastas correspondentes:

* `/src_pt/` - Código-fonte, documentação e estrutura de ficheiros em Português.

## 🚀 Como Executar

Escolha a abordagem que melhor se adapta ao seu ambiente de trabalho:

### 🛠️ Opção 1: Executável Direto (Windows)
Se descarregou a versão compilada para Windows (`botnet_detector.exe`), **não necessita de instalar o Ruby ou qualquer dependência (gems)**. O programa é totalmente autónomo.
1. Coloque o ficheiro `botnet_detector.exe` numa pasta dedicada à sua escolha.
2. Execute o ficheiro via duplo clique ou linha de comandos. 
*(Nota: As pastas de ambiente (`logs/`, `logs/generated_logs/` e `reports/`) serão geradas automaticamente na mesma diretoria do executável.)*


### 🐧 Opção 2: Instalação em Linux (Automática)
Execute o seguinte comando no terminal para transferir dependências e preparar o ambiente:

```bash
curl -sSL [https://raw.githubusercontent.com/NullUmbraTak/BotNetDetector_Project/main/src_pt/installer.sh](https://raw.githubusercontent.com/NullUmbraTak/BotNetDetector_Project/main/src_pt/installer.sh) | bash
```
*(Nota: Ao correr este comando, o script Bash tratará de criar a estrutura de pastas e descarregar a ferramenta pronta a funcionar).*

### 💻 Opção 3: Execução Manual por Código-Fonte (Desenvolvimento)
Para correr o programa (versão PT):
1. Navegue até ao diretório do idioma: `cd src_pt`
2. Garanta que tem as gems necessárias instaladas: `gem install httparty addressable text`
3. Execute a ferramenta: `ruby botnet_detector.rb`

*(Nota: Ao executar o programa, as pastas de `logs/` e `reports/` são criadas automaticamente para garantir a correta arrumação dos dados e dos anexos de evidências gerados).*

## 👨‍💻 Autor
Desenvolvido por **NullUmbraTak** no âmbito do curso de Técnico Especialista em Cibersegurança (Nível 5).
*UFCD 1482*

---
> 🌍 **Nota de Desenvolvimento:** Este projeto está atualmente disponível em Português. A estrutura para a versão internacional (`src_en/`) já está planeada e a tradução integral do código e documentação para Inglês será adicionada num *commit* futuro.

> 🌍 **Development Note:** This project is currently available in Portuguese. The architecture for the international version (`src_en/`) is already planned, and the full translation of the source code and documentation into English will be added in a future commit.