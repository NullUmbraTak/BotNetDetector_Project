# BOTNET DETECTOR
require 'time'
require 'fileutils'
require 'ipaddr'
require 'httparty'
require 'addressable' #urls e uris
require 'text' #dist lexical

# ==========================================
# CONSTANTES DO GERADOR
# ==========================================
DOMINIOS_NORMAIS = [
  "google.com", "microsoft.com", "github.com",
  "wikipedia.org", "openai.com", "youtube.com"
]

DOMINIOS_DGA = [
  "xjkqw91.net", "xjkqw92.net", "xjkqw93.net",
  "pqzr188.org", "abx991aa.com", "atr991qx.net", "meb774aa.org"
]

SEPARADOR = ","

# Variável global de sessão para armazenar os logs processados
@logs_carregados = []

# ==========================================
# MÉTODOS DE UTILIDADE E SISTEMA
# ==========================================
def limpar_ecra
  system("cls") || system("clear")
end

def pausa
  puts "\nPrima ENTER para continuar..."
  gets
end

def mostrar_ficheiro(caminho)
  limpar_ecra
  if File.exist?(caminho)
    puts File.read(caminho)
  else
    puts "Erro: ficheiro '#{caminho}' não encontrado."
  end
  pausa
end

# ==========================================
# FUNÇÕES AUXILIARES DO GERADOR
# ==========================================
def gerar_ips_internos(qtd)
  (1..qtd).map { |i| "192.168.1.#{i}" }
end

def gerar_ips_externos(qtd)
  ips = []
  while ips.size < qtd
    ips << "#{rand(1..223)}.#{rand(0..255)}.#{rand(0..255)}.#{rand(1..254)}"
  end
  ips.uniq
end

def data_aleatoria
  inicio = Time.new(2026, 6, 15, 0, 0, 0)
  tempo = inicio + rand(0..86400)
  formatos = [
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d-%m-%Y %H:%M:%S"
  ]
  tempo.strftime(formatos.sample)
end

def ruido(texto)
  texto = "#{texto} " if rand < 0.15
  texto = " #{texto}" if rand < 0.15
  if rand < 0.20
    texto = texto.downcase
  elsif rand < 0.20
    texto = texto.capitalize
  end
  texto
end

# ==========================================
# MÓDULO: CARREGAR LOGS (OPÇÃO 1)
# ==========================================
def carregar_logs(caminho = "logs/generated_logs/generated_logs.log")
  limpar_ecra
  unless File.exist?(caminho)
    puts "Erro: O ficheiro '#{caminho}' não existe."
    puts "Verifique se o colocou na pasta 'logs' ou corra a Opção 2 para gerar um novo."
    pausa
    return
  end
  
  print "A carregar e normalizar logs... Por favor, aguarde.\n"
  
  print "A carregar e normalizar logs... Por favor, aguarde.\n"
  @logs_carregados = []
  contador_linhas = 0
  
  File.foreach(caminho) do |linha|
    contador_linhas += 1
    # 1. Separar os campos por vírgula
    campos = linha.chomp.split(",")
    
    # Se a linha estiver mal estruturada, ignora
    next unless campos.size == 5
    data_bruta, componente, origem, destino, mensagem = campos
    
    # 2. NORMALIZAÇÃO DO RUÍDO
    componente = componente.strip.upcase
    mensagem = mensagem.strip.upcase
    
    # 3. NORMALIZAÇÃO DA DATA
    data_limpa = data_bruta.strip
    begin
      objeto_tempo = Time.parse(data_limpa)
    rescue ArgumentError
      objeto_tempo = data_limpa
    end
    
    # 4. Guardar num formato estruturado
    @logs_carregados << {
      data: objeto_tempo,
      componente: componente,
      origem: origem.strip,
      destino: destino.strip,
      mensagem: mensagem
    }
  end
  
  puts "\n[Sucesso] Foram processadas #{contador_linhas} linhas."
  puts "Exemplo de log normalizado na memória:"
  puts @logs_carregados.first.inspect if @logs_carregados.any?
  pausa
end

# ==========================================
# MÓDULO: GERADOR DE LOGS (OPÇÃO 2)
# ==========================================
def gerar_logs
  limpar_ecra
  puts "============================="
  puts "   GERADOR DE LOGS BOTNET    "
  puts "============================="
  
  print "1-Número total de linhas desejado: "
  num_linhas = gets.chomp.to_i
  
  print "2-% eventos suspeitos adicionais (DGA): "
  percent_suspeitos = gets.chomp.to_i
  
  print "3-Nº de máquinas internas: "
  num_maquinas = gets.chomp.to_i
  
  print "4-Nº de IPs externos: "
  num_ips_externos = gets.chomp.to_i
  
  print "5-Nº de eventos de beaconing: "
  num_beaconing = gets.chomp.to_i
  
  jitter_percent = 0
  intervalo_base = 0
  if num_beaconing > 0
    print "  -> Intervalo base do beacon (em segundos, ex: 300): "
    intervalo_base = gets.chomp.to_i
    print "  -> % de variação (Jitter) máxima (ex: 10 para 10%): "
    jitter_percent = gets.chomp.to_i
  end
  
  print "6-Nº de eventos brute force: "
  num_bruteforce = gets.chomp.to_i
  
  print "7-Nº de eventos DNS suspeitos: "
  num_dns_suspeitos = gets.chomp.to_i

  print "8-Nome do ficheiro a gerar (ex: teste1): "
  nome_base = gets.chomp.strip
  nome_base = "generated_logs" if nome_base.empty?
  nome_base = nome_base.sub(/\.log$/, '')

  ips_internos = gerar_ips_internos(num_maquinas)
  ips_externos = gerar_ips_externos(num_ips_externos)
  linhas = []

  extra = ((num_linhas * percent_suspeitos) / 100.0).to_i
  num_normais = num_linhas - (num_beaconing + num_bruteforce + num_dns_suspeitos + extra)
  num_normais = 0 if num_normais < 0

  num_normais.times do
    data = data_aleatoria
    caso = rand(1..100)
    
    if caso < 25
      linhas << [data, ruido("AUTH"), ips_internos.sample, "SERVER01", ruido("LOGIN SUCCESS user")].join(SEPARADOR)
    elsif caso < 55
      linhas << [data, ruido("DNS"), ips_internos.sample, DOMINIOS_NORMAIS.sample, ruido("QUERY")].join(SEPARADOR)
    else
      linhas << [data, ruido("NET"), ips_internos.sample, ips_externos.sample, "TCP #{rand(100..3000)}"].join(SEPARADOR)
    end
  end

  if num_beaconing > 0
    ip_origem = ips_internos.sample
    ip_destino = ips_externos.sample
    tempo_atual = Time.new(2026, 6, 15, 8, 0, 0)
    
    num_beaconing.times do
      desvio_maximo = (intervalo_base * (jitter_percent / 100.0)).to_i
      variacao = desvio_maximo > 0 ? rand(-desvio_maximo..desvio_maximo) : 0
      intervalo_real = intervalo_base + variacao
      tempo_atual += intervalo_real
      data = tempo_atual.strftime("%Y-%m-%d %H:%M:%S")
      
      linhas << [data, "NET", ip_origem, ip_destino, "TCP 100"].join(SEPARADOR)
    end
  end

  if num_bruteforce > 0
    atacante = ips_internos.sample
    tempo_ataque = Time.new(2026, 6, 15, 23, 0, 0)
    
    num_bruteforce.times do
      tempo_ataque += rand(1..3)
      linhas << [tempo_ataque.strftime("%Y-%m-%d %H:%M:%S"), "AUTH", atacante, "SERVER01", "FAILED LOGIN admin"].join(SEPARADOR)
    end
  end

  if num_dns_suspeitos > 0
    host = ips_internos.sample
    num_dns_suspeitos.times do
      linhas << [data_aleatoria, "DNS", host, DOMINIOS_DGA.sample, "QUERY"].join(SEPARADOR)
    end
  end

  extra.times do
    linhas << [data_aleatoria, "DNS", ips_internos.sample, DOMINIOS_DGA.sample, "QUERY"].join(SEPARADOR)
  end

  linhas.shuffle!
  
  pasta_destino = File.join("logs", "generated_logs")
  FileUtils.mkdir_p(pasta_destino)
  
  caminho_final = File.join(pasta_destino, "#{nome_base}.log")
  contador = 1
  
  while File.exist?(caminho_final)
    caminho_final = File.join(pasta_destino, "#{nome_base}_#{contador}.log")
    contador += 1
  end

  File.open(caminho_final, "w") do |f|
    linhas.each { |linha| f.puts linha }
  end

  puts "\nFicheiro '#{caminho_final}' criado com sucesso!"
  puts "Total de eventos injetados: #{linhas.size}"
  pausa
end

# ==========================================
# MÓDULOS DE ANÁLISE (OPÇÕES 3 a 7)
# ==========================================
def analisar_autenticacoes_falhadas
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  puts "============================================================"
  puts " ANÁLISE: AUTENTICAÇÕES FALHADAS"
  puts "============================================================"
  puts
  
  falhas = @logs_carregados.select do |log|
    log[:componente] == "AUTH" && log[:mensagem].include?("FAILED LOGIN")
  end
  
  if falhas.empty?
    puts "Nenhuma autenticação falhada encontrada no dataset atual."
  else
    puts "Últimas falhas detetadas (Amostra de segurança):"
    puts "------------------------------------------------"
    falhas.first(15).each do |log|
      # Verifica se a data é um objeto Time antes de usar strftime
      data_str = log[:data].is_a?(Time) ? log[:data].strftime('%Y-%m-%d %H:%M:%S') : log[:data]
      puts "[ALERTA] #{data_str} | Origem: #{log[:origem]} | Alvo: #{log[:destino]} | #{log[:mensagem]}"
    end
    
    puts "\nTOTAL DE FALHAS DETETADAS: #{falhas.size}"
    puts "\nSuspeitos por volume de ataques (Top IPs):"
    
    contagem_por_ip = Hash.new(0)
    falhas.each { |log| contagem_por_ip[log[:origem]] += 1 }
    
    contagem_por_ip.sort_by { |_, total| -total }.each do |ip, total|
      puts " -> IP: #{ip} | Tentativas Falhadas: #{total}"
    end
  end
  pausa
end

def analisar_picos_atividade
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  puts "============================================================"
  puts " ANÁLISE: PICOS DE ATIVIDADE"
  puts "============================================================"
  puts
  
  distribuicao_horaria = Hash.new(0)
  (0..23).each { |hora| distribuicao_horaria[hora] = 0 }
  
  @logs_carregados.each do |log|
    if log[:data].is_a?(Time)
      hora = log[:data].hour
      distribuicao_horaria[hora] += 1
    end
  end
  
  puts "Volume de eventos por hora:"
  puts "---------------------------"
  distribuicao_horaria.sort.each do |hora, total|
    hora_formatada = sprintf("%02d:00", hora)
    barra = total > 0 ? "█" * (total / 20) : ""
    sinalizador = total > 100 ? " [ALERTA DE PICO]" : ""
    puts "#{hora_formatada} | Total Eventos: #{sprintf("%4d", total)} #{barra}#{sinalizador}"
  end
  
  hora_pico, max_eventos = distribuicao_horaria.max_by { |_, total| total }
  puts "\nResultado da Telemetria:"
  puts " -> Hora Crítica: #{sprintf("%02d:00", hora_pico)} com um pico de #{max_eventos} eventos detetados."
  pausa
end

def analisar_beaconing
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  puts "============================================================"
  puts " ANÁLISE: DETEÇÃO DE BEACONING"
  puts "============================================================"
  puts "A analisar intervalos temporais (tolerância a Jitter)..."
  puts
  
  historico_ligacoes = Hash.new { |h, k| h[k] = [] }
  @logs_carregados.each do |log|
    if log[:componente] == "NET" && log[:data].is_a?(Time)
      chave_par = "#{log[:origem]} -> #{log[:destino]}"
      historico_ligacoes[chave_par] << log[:data]
    end
  end
  
  alertas_encontrados = 0
  
  historico_ligacoes.each do |par, timestamps|
    next if timestamps.size < 4
    
    tempos_ordenados = timestamps.sort
    intervalos = []
    
    (0...tempos_ordenados.size - 1).each do |i|
      intervalos << (tempos_ordenados[i+1] - tempos_ordenados[i]).to_i
    end
    
    media_intervalo = intervalos.sum / intervalos.size.to_f
    soma_variancia = intervalos.map { |int| (int - media_intervalo)**2 }.sum
    desvio_padrao = Math.sqrt(soma_variancia / intervalos.size.to_f)
    
    if desvio_padrao < 30 && media_intervalo > 10
      alertas_encontrados += 1
      puts "[ALERTA CRÍTICO] Comunicação Persistente Detetada!"
      puts " Canal: #{par}"
      puts " Total de Contactos: #{timestamps.size}"
      puts " Intervalo Médio Calculado: #{media_intervalo.round(1)} segundos (~#{(media_intervalo/60).round(1)} min)"
      puts " Flutuação Média (Jitter): ±#{desvio_padrao.round(1)} segundos\n\n"
    end
  end
  
  if alertas_encontrados == 0
    puts "Nenhum padrão de beaconing ou comunicação automatizada detetado."
  else
    puts "TOTAL DE CANAIS DE BEACONING DETETADOS: #{alertas_encontrados}"
  end
  pausa
end

def analisar_dns_suspeito
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  dominios_perigosos = ["XJKQW91.NET", "XJKQW92.NET", "XJKQW93.NET", "PQZR188.ORG", "ABX991AA.COM", "ATR991QX.NET", "MEB774AA.ORG"]
  dominios_legitimos = ["google.com", "microsoft.com", "github.com", "wikipedia.org"]
  
  puts "============================================================"
  puts " ANÁLISE: DNS AVANÇADO (Addressable & Levenshtein)"
  puts "============================================================"
  puts
  
  alertas_dns = 0
  
  @logs_carregados.each do |log|
    next unless log[:componente] == "DNS"
    
    uri = Addressable::URI.parse(log[:destino].downcase.start_with?('http') ? log[:destino] : "http://#{log[:destino]}")
    host_normalizado = uri.host || log[:destino].downcase
    
    e_malicioso = false
    motivo = ""
    
    if dominios_perigosos.include?(host_normalizado.upcase)
      e_malicioso = true
      motivo = "Coincidência direta com assinatura DGA conhecida"
    else
      dominios_legitimos.each do |legitimo|
        distancia = Text::Levenshtein.distance(host_normalizado, legitimo)
        if distancia > 0 && distancia <= 2
          e_malicioso = true
          motivo = "Possível Typosquatting/Phishing (Semelhança com #{legitimo})"
          break
        end
      end
    end
    
    if e_malicioso
      alertas_dns += 1
      data_str = log[:data].is_a?(Time) ? log[:data].strftime('%Y-%m-%d %H:%M:%S') : log[:data]
      puts "[PERIGO DNS] #{data_str}"
      puts " Origem: #{log[:origem]} -> Destino: #{host_normalizado}"
      puts " Motivo: #{motivo}\n\n"
    end
  end
  
  puts "TOTAL DE ALERTAS DNS INTELIGENTES: #{alertas_dns}"
  pausa
end

def analisar_ips_externos
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  puts "============================================================"
  puts " ANÁLISE: AUDITORIA DE IPs (IPAddr & HTTParty)"
  puts "============================================================"
  puts "A filtrar IPs públicos e a geolocalizar ameaças em tempo real..."
  puts
  
  ips_auditados = []
  
  @logs_carregados.each do |log|
    next unless log[:componente] == "NET"
    ips_auditados << log[:destino] unless ips_auditados.include?(log[:destino])
  end
  
  total_publicos = 0
  
  ips_auditados.first(5).each do |ip_texto|
    begin
      ip_objeto = IPAddr.new(ip_texto)
      next if ip_objeto.private?
      
      total_publicos += 1
      puts "A geolocalizar IP Público: #{ip_texto}..."
      
      resposta = HTTParty.get("http://ip-api.com/json/#{ip_texto}", timeout: 3)
      if resposta.code == 200 && resposta["status"] == "success"
        pais = resposta["country"] || "Desconhecido"
        isp = resposta["isp"] || "Desconhecido"
        organizacao = resposta["org"] || "Desconhecida"
        puts "  [INFO] País: #{pais} | ISP: #{isp} [#{organizacao}]"
      else
        puts "  [AVISO] Não foi possível obter detalhes de geolocalização para este IP."
      end
      puts
      sleep(0.5)
    rescue ArgumentError, HTTParty::Error, StandardError => e
      puts "  [Erro] Falha ao analisar IP #{ip_texto}: #{e.message}\n\n"
    end
  end
  
  puts "\nAuditoria concluída para uma amostra de IPs públicos."
  pausa
end

def executar_analise_completa
  limpar_ecra
  if @logs_carregados.nil? || @logs_carregados.empty?
    puts "Erro: Nenhum log carregado em memória. Escolha primeiro a Opção 1."
    pausa
    return
  end
  
  puts "============================================================"
  puts " SISTEMA: COMPILAÇÃO DA ANÁLISE AVANÇADA (TI)"
  puts "============================================================"
  print "A correlacionar vetores e a consultar inteligência de rede... Por favor, aguarde.\n\n"
  
  @evidencias = { bruteforce: [], dga: [], beaconing: [] }
  
  # 1. Filtro Brute Force
  falhas_auth = @logs_carregados.select { |log| log[:componente] == "AUTH" && log[:mensagem].include?("FAILED LOGIN") }
  @evidencias[:bruteforce] = falhas_auth
  
  # 2. Filtro DNS
  dominios_perigosos = ["XJKQW91.NET", "XJKQW92.NET", "XJKQW93.NET", "PQZR188.ORG", "ABX991AA.COM", "ATR991QX.NET", "MEB774AA.ORG"]
  dominios_legitimos = ["google.com", "microsoft.com", "github.com", "wikipedia.org"]
  total_alertas_dns = 0
  
  @logs_carregados.each do |log|
    next unless log[:componente] == "DNS"
    uri = Addressable::URI.parse(log[:destino].downcase.start_with?('http') ? log[:destino] : "http://#{log[:destino]}")
    host = uri.host || log[:destino].downcase
    
    e_malicioso = false
    if dominios_perigosos.include?(host.upcase)
      e_malicioso = true
    else
      dominios_legitimos.each do |legitimo|
        distancia = Text::Levenshtein.distance(host, legitimo)
        if distancia > 0 && distancia <= 2
          e_malicioso = true
          break
        end
      end
    end
    
    if e_malicioso
      total_alertas_dns += 1
      @evidencias[:dga] << { data: log[:data], origem: log[:origem], destino: host }
    end
  end
  
  # 3. Filtro Beaconing
  historico = Hash.new { |h, k| h[k] = [] }
  @logs_carregados.each { |l| historico["#{l[:origem]} -> #{l[:destino]}"] << l[:data] if l[:componente] == "NET" && l[:data].is_a?(Time) }
  
  total_beacons = 0
  ip_c2_detetado = "N/A"
  
  historico.each do |par, ts|
    next if ts.size < 4
    to = ts.sort
    intervals = (0...to.size - 1).map { |i| (to[i+1] - to[i]).to_i }
    media = intervals.sum / intervals.size.to_f
    variance = intervals.map { |int| (int - media)**2 }.sum
    stdev = Math.sqrt(variance / intervals.size.to_f)
    
    if stdev < 30 && media > 10
      total_beacons += 1
      ip_c2_detetado = par.split(" -> ").last
      @evidencias[:beaconing] << { par: par, total_contactos: ts.size, intervalo: media.round(1) }
    end
  end
  
  localizacao_c2 = "Desconhecida (IP Privado/Inativo)"
  if ip_c2_detetado != "N/A"
    begin
      ip_obj = IPAddr.new(ip_c2_detetado)
      unless ip_obj.private?
        resposta = HTTParty.get("http://ip-api.com/json/#{ip_c2_detetado}", timeout: 3)
        if resposta.code == 200 && resposta["status"] == "success"
          localizacao_c2 = "#{resposta['country']} (#{resposta['isp']})"
        end
      end
    rescue
      localizacao_c2 = "Erro na consulta de localização"
    end
  end
  
  puts "\n INDICADOR DE RISCO              | STATUS    | QTD"
  puts "----------------------------------------------------"
  puts " Ataques de Brute Force          | #{falhas_auth.any? ? 'PERIGO   ' : 'LIMPO    '} | #{sprintf('%3d', falhas_auth.size)}"
  puts " Resoluções de Domínio DGA/Typo  | #{total_alertas_dns > 0 ? 'PERIGO   ' : 'LIMPO    '} | #{sprintf('%3d', total_alertas_dns)}"
  puts " Canais Ativos de Beaconing      | #{total_beacons > 0 ? 'PERIGO   ' : 'LIMPO    '} | #{sprintf('%3d', total_beacons)}"
  puts "\n LOCALIZAÇÃO DO SERVIDOR C2      | #{localizacao_c2}\n\n"
  
  @analise_executada = true
  @resumo_alertas = {
    bruteforce: falhas_auth.size,
    dga: total_alertas_dns,
    beaconing: total_beacons,
    localizacao: localizacao_c2
  }
  
  puts "[Sucesso] Análise de inteligência integrada concluída!"
  pausa
end

# ==========================================
# MÓDULOS DE RESULTADOS (OPÇÕES 8 a 11)
# ==========================================
def ver_alertas
  limpar_ecra
  if @analise_executada.nil? || !@analise_executada
    puts "Erro: A análise completa ainda não foi executada. Escolha primeiro a Opção 8."
    pausa
    return
  end
  
  puts "============================================================"
  puts " RESULTADOS: ALERTAS DE SEGURANÇA"
  puts "============================================================"
  puts
  
  total_alertas = 0
  
  if @resumo_alertas[:bruteforce] > 0
    total_alertas += 1
    puts "[ALERTA 01] -> Ataque de força bruta detetado em sistemas de autenticação (AUTH)."
    puts "  Volume: #{@resumo_alertas[:bruteforce]} tentativas falhadas acumuladas.\n\n"
  end
  
  if @resumo_alertas[:dga] > 0
    total_alertas += 1
    puts "[ALERTA 02] -> Atividade de Algoritmo de Geração de Domínio (DGA) identificada."
    puts "  Volume: #{@resumo_alertas[:dga]} consultas a infraestruturas C2 suspeitas.\n\n"
  end
  
  if @resumo_alertas[:beaconing] > 0
    total_alertas += 1
    puts "[ALERTA 03] -> Canal de comunicação persistente e automatizado ativo (Beaconing)."
    puts "  Volume: #{@resumo_alertas[:beaconing]} canal(ais) de Comando e Controlo (C2) estabelecido(s).\n\n"
  end
  
  if total_alertas == 0
    puts "Nenhum alerta crítico ativo na memória do sistema."
  else
    puts "------------------------------------------------------------"
    puts "TOTAL DE ALERTAS CRÍTICOS DISPARADOS: #{total_alertas}"
  end
  pausa
end

def mostrar_estatisticas
  limpar_ecra
  if @analise_executada.nil? || !@analise_executada
    puts "Erro: A análise completa ainda não foi executada. Escolha primeiro a Opção 8."
    pausa
    return
  end
  
  puts "============================================================"
  puts " RESULTADOS: MÉTRICAS E ESTATÍSTICAS"
  puts "============================================================"
  puts
  
  total_global = @logs_carregados.size
  total_malicioso = @resumo_alertas[:bruteforce] + @resumo_alertas[:dga] + @resumo_alertas[:beaconing]
  total_legitimo = total_global - total_malicioso
  
  percent_malicioso = total_global > 0 ? ((total_malicioso.to_f / total_global) * 100).round(2) : 0
  percent_legitimo = total_global > 0 ? ((total_legitimo.to_f / total_global) * 100).round(2) : 0
  
  puts "Distribuição Geral do Dataset:"
  puts "------------------------------"
  puts " Volume Total Analisado: #{total_global} linhas."
  puts " Tráfego Legítimo:       #{total_legitimo} eventos (#{percent_legitimo}%)"
  puts " Tráfego Malicioso:      #{total_malicioso} eventos (#{percent_malicioso}%)"
  puts
  
  puts "Peso Relativo das Ameaças Detetadas:"
  puts "------------------------------------"
  if total_malicioso > 0
    p_brute = ((@resumo_alertas[:bruteforce].to_f / total_malicioso) * 100).round(1)
    p_dga = ((@resumo_alertas[:dga].to_f / total_malicioso) * 100).round(1)
    p_beacon = ((@resumo_alertas[:beaconing].to_f / total_malicioso) * 100).round(1)
    
    puts " -> Força Bruta (AUTH):  #{sprintf('%5d', @resumo_alertas[:bruteforce])} eventos | #{p_brute}% do tráfego malicioso"
    puts " -> Consultas DGA (DNS): #{sprintf('%5d', @resumo_alertas[:dga])} eventos | #{p_dga}% do tráfego malicioso"
    puts " -> Beaconing (NET):     #{sprintf('%5d', @resumo_alertas[:beaconing])} eventos | #{p_beacon}% do tráfego malicioso"
  else
    puts " Sem dados de ameaças para decompor."
  end
  pausa
end

def gerar_relatorio_txt
  limpar_ecra
  if @analise_executada.nil? || !@analise_executada
    puts "Erro: A análise completa ainda não foi executada. Escolha primeiro a Opção 8."
    pausa
    return
  end
  
  puts "============================================================"
  puts " SYSTEM: EXPORTAÇÃO DE RELATÓRIO AVANÇADO"
  puts "============================================================"
  
  # esta funcao permite dar nome ou em caso de em branco gera nome incrementado
  print "Nome do relatório a gerar (ex: cliente_x): "
  nome_base = gets.chomp.strip
  nome_base = "relatorio_seguranca" if nome_base.empty?
  nome_base = nome_base.sub(/\.txt$/, '')

  # esta funcao cria a pasta report
  pasta_destino = "reports"
  FileUtils.mkdir_p(pasta_destino)
  
  caminho_relatorio = File.join(pasta_destino, "#{nome_base}.txt")
  contador = 1
  
  while File.exist?(caminho_relatorio)
    caminho_relatorio = File.join(pasta_destino, "#{nome_base}_#{contador}.txt")
    contador += 1
  end

  puts "A gravar relatório com dados de geolocalização e evidências..."
  puts
  
  File.open(caminho_relatorio, "w") do |f|
    f.puts "============================================================"
    f.puts "        RELATÓRIO DE AUDITORIA E THREAT INTELLIGENCE"
    f.puts "============================================================"
    f.puts " Gerado em: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
    f.puts " Status Geral: #{(@resumo_alertas[:bruteforce] + @resumo_alertas[:dga] + @resumo_alertas[:beaconing]) > 0 ? 'ALERTA CRÍTICO DE INFEÇÃO' : 'SISTEMA LIMPO'}"
    f.puts "============================================================"
    f.puts
    f.puts " [1. TELEMETRIA DO DATASET]"
    f.puts "------------------------------------------------------------"
    f.puts " Total de Linhas Analisadas:   #{@logs_carregados.size}"
    
    total_malicioso = @resumo_alertas[:bruteforce] + @resumo_alertas[:dga] + @resumo_alertas[:beaconing]
    total_legitimo = @logs_carregados.size - total_malicioso
    
    f.puts " Eventos de Tráfego Legítimo:  #{total_legitimo}"
    f.puts " Eventos de Tráfego Malicioso: #{total_malicioso}"
    f.puts
    f.puts " [2. INTELIGÊNCIA DE AMEAÇAS (TI) & VETORES DETETADOS]"
    f.puts "------------------------------------------------------------"
    f.puts " [AUTH] Força Bruta (Brute Force):      #{@resumo_alertas[:bruteforce]} eventos"
    f.puts " [DNS]  Domínios Suspeitos DGA/Typo:    #{@resumo_alertas[:dga]} consultas"
    f.puts " [NET]  Canais Ativos de Beaconing:     #{@resumo_alertas[:beaconing]} canal(ais)"
    f.puts " [C2]   Geolocalização Alvo (C2):       #{@resumo_alertas[:localizacao]}"
    f.puts
    
    # ---SECÇÃO DE EVIDÊNCIAS ---
    f.puts " [3. ANEXO TÉCNICO - EVIDÊNCIAS E IoCs]"
    f.puts "------------------------------------------------------------"
    
    if @evidencias[:bruteforce].any?
      f.puts " >> Amostra de Autenticações Falhadas (Brute Force):"
      @evidencias[:bruteforce].first(15).each do |log|
        data_str = log[:data].is_a?(Time) ? log[:data].strftime('%Y-%m-%d %H:%M:%S') : log[:data]
        f.puts "    [#{data_str}] Origem: #{log[:origem]} | Alvo: #{log[:destino]}"
      end
      f.puts
    end
    
    if @evidencias[:dga].any?
      f.puts " >> Amostra de Resoluções DNS Maliciosas:"
      @evidencias[:dga].first(15).each do |log|
        data_str = log[:data].is_a?(Time) ? log[:data].strftime('%Y-%m-%d %H:%M:%S') : log[:data]
        f.puts "    [#{data_str}] Máquina Interna: #{log[:origem]} | Consulta: #{log[:destino]}"
      end
      f.puts
    end
    
    if @evidencias[:beaconing].any?
      f.puts " >> Canais de Comando e Controlo (Beaconing):"
      @evidencias[:beaconing].each do |b|
        f.puts "    Canal: #{b[:par]} | Total Contactos: #{b[:total_contactos]} | Intervalo Médio: #{b[:intervalo]}s"
      end
      f.puts
    end
    
    if total_malicioso == 0
      f.puts " Nenhuma evidência de atividade maliciosa registada."
      f.puts
    end
    # ---------------------------------
    
    f.puts "============================================================"
    f.puts "                    FIM DO RELATÓRIO"
    f.puts "                  BOTNET DETECTOR"
    f.puts "============================================================"
  end
  
  puts "[Sucesso] Ficheiro '#{caminho_relatorio}' exportado com êxito!"
  puts "O relatório agora contém dados reais de atribuição geográfica e evidências em anexo."
  pausa
end

# ==========================================
# ARRANQUE DO SISTEMA
# ==========================================
# esta funcao cria as pastas logs e generated_logs
FileUtils.mkdir_p(File.join("logs", "generated_logs"))
# esta funcao cria a pasta report
FileUtils.mkdir_p("reports")

# ==========================================
# INTERFACE PRINCIPAL DO UTILIZADOR
# ==========================================
def mostrar_menu
  puts " ██████╗  ██████╗ ████████╗███╗   ██╗███████╗████████╗"
  puts " ██╔══██╗██╔═══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝"
  puts " ██████╔╝██║   ██║   ██║   ██╔██╗ ██║█████╗     ██║   "
  puts " ██╔══██╗██║   ██║   ██║   ██║╚██╗██║██╔══╝     ██║   "
  puts " ██████╔╝╚██████╔╝   ██║   ██║ ╚████║███████╗   ██║   "
  puts " ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   "
  puts " ██████╗ ███████╗████████╗███████╗████████╗ ██████╗ ██████╗ "
  puts " ██╔══██╗██╔════╝╚══██╔══╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗"
  puts " ██║  ██║█████╗     ██║   █████╗     ██║   ██║   ██║██████╔╝"
  puts " ██║  ██║██╔══╝     ██║   ██╔══╝     ██║   ██║   ██║██╔══██╗"
  puts " ██████╔╝███████╗   ██║   ███████╗   ██║   ╚██████╔╝██║  ██║"
  puts " ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝"
  puts "                                   v1.0 | by NullUmbraTak™  "
  puts ""
  puts "============================================================"
  puts "1 - Carregar logs"
  puts "2 - Gerar logs"
  puts "============================================================"
  puts "*** Análise                                              ***"
  puts "3 - Autenticações falhadas"
  puts "4 - Picos de atividade"
  puts "5 - Beaconing"
  puts "6 - DNS suspeito"
  puts "7 - Análise de IPs externos"
  puts "8 - Executar análise completa"
  puts "============================================================"
  puts "*** Resultados                                           ***"
  puts "9 - Ver alertas"
  puts "10 - Estatísticas"
  puts "11 - Gerar relatório"
  puts "============================================================"
  puts "*** Informação                                           ***"
  puts "12 - Ajuda"
  puts "13 - Sobre"
  puts "0 - Sair"
  puts "============================================================"
  print "Opção: "
end

loop do
  limpar_ecra
  mostrar_menu
  
  opcao = gets.chomp.to_i
  
  case opcao
  when 1
    print "\nNome do ficheiro a carregar (deixe em branco para o mais recente): "
    nome_ficheiro = gets.chomp.strip
    
    if nome_ficheiro.empty?
      # Procura todos os logs tanto na pasta principal como na subpasta
      todos_arquivos = Dir.glob("logs/*.log") + Dir.glob("logs/generated_logs/*.log")
      
      if todos_arquivos.empty?
        caminho = "logs/nenhum_log_encontrado.log" # Força um erro limpo
      else
        # Carrega automaticamente o ficheiro que foi modificado/adicionado há menos tempo
        caminho = todos_arquivos.max_by { |f| File.mtime(f) }
      end
    else
      nome_ficheiro += ".log" unless nome_ficheiro.end_with?(".log")
      
      # Inteligência de procura: procura primeiro em 'logs/' (externos), depois em 'logs/generated_logs/'(para logs gerados)
      if File.exist?(File.join("logs", nome_ficheiro))
        caminho = File.join("logs", nome_ficheiro)
      else
        caminho = File.join("logs", "generated_logs", nome_ficheiro)
      end
    end
    carregar_logs(caminho)
  when 2
    gerar_logs
  when 3
    analisar_autenticacoes_falhadas
  when 4
    analisar_picos_atividade
  when 5
    analisar_beaconing
  when 6
    analisar_dns_suspeito
  when 7
    analisar_ips_externos
  when 8
    executar_analise_completa
  when 9
    ver_alertas
  when 10
    mostrar_estatisticas
  when 11
    gerar_relatorio_txt
  when 12
    mostrar_ficheiro("docs/ajuda.txt")
  when 13
    mostrar_ficheiro("docs/sobre.txt")
  when 0
    puts "\nA terminar o programa..."
    break
  else
    puts "\nOpção inválida."
    pausa
  end
end