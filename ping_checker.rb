require 'msf/core' #libreria principale di Metasploit

class MetasploitModule < Msf::Auxiliary #crea una nuova classe che eredita da auxiliary
  include Msf::Auxiliary::Scanner #aggiunge supporto per rhosts, range e subnet
  include Msf::Auxiliary::Report #aggiunge supporto per salvare nel database

  def initialize(info = {}) #metodo che viene eseguito al caricamento del modulo
    super(update_info(info,
      'Name'        => 'Ping checker',
      'Description' => 'Verifica se un host è raggiungibile tramite ping',
      'Author'      => ['pippo'],
      'License'     => MSF_LICENSE
    ))

    register_options([ #opzioni che l'utente può impostare con il set
      OptInt.new('COUNT',   [false, 'Numero di pacchetti da inviare', 3]),
      OptInt.new('TIMEOUT', [false, 'Timeout in secondi', 1])
      #OptInt.new('TIME', [false, 'Numero di salti prima di abortire', 10]) -t
    ])
  end

  def ping_host(ip) #metodo che esegue il ping sull'ip ricevuto
    count   = datastore['COUNT']   #legge il valore impostato 
    timeout = datastore['TIMEOUT'] 
    #time = datastore['TIME']

    #posso immettere anche un dominio al posto dell'ip
    require 'resolv'
    begin
      resolved_ip = Resolv.getaddress(ip) #converte il dominio in ip
      ip = resolved_ip

    rescue Resolv::ResolvError #se il dominio non esiste
      return {reachable: false, latency: nil, raw: ''}
    end

    #costruisce il comando ping in base al sistema operativo
    cmd = if RUBY_PLATFORM =~ /mingw|mswin/ # controlla se è windows ed esegue il comando
            "ping -n #{count} -w #{timeout * 1000} #{ip}"
          else
            "ping -c #{count} -W #{timeout} #{ip}" #se non è windows esegue il comando per linux/macos
          end

    output  = `#{cmd} 2>&1` #eseguito il comando e cattura l'output
    success = $?.exitstatus == 0 #0 = successo altrimenti fail


    #estrae solo la latenza e count dall'output con tre espressioni diverse per compatibilità
    latency ||= output.match(/[Tt]ime[=<]([\d.]+)\s*ms/)&.captures&.first #linux/macos
    #count ||= output.match(/(\d+)\s+packets transmitted/)&.captures&.first
    latency ||= output.match(/Average\s*=\s*([\d.]+)\s*ms/)&.captures&.first #windows
    #count ||= output.match(/Packets:\s+Sent\s*=\s*(\d+)/i)&.captures&.first
    latency ||= output.match(/min\/avg\/max[^=]+=\s*[\d.]+\/([\d.]+)/)&.captures&.first #macos
    #count ||= output.match(/(\d+)\s+packets transmitted/i)&.captures&.first

    {reachable: success, latency: latency} #restituisce i risultati
    #{reachable: success, latency: latency, count:count , output: output} 
  end

  def run_host(ip) #metodo chiamato automaticamente dallo scanner per ogni ip
    result = ping_host(ip) #chiama il metodo ping_host

    if result[:reachable] #se il ping ha avuto successo
      latency_str = "(#{result[:latency]}ms)"
      #count_str = "#{result[:count]}"
      #print("Numero pacchetti inviati: #{count_str}\n")
      #output_str = "#{result[:output]}" print("#{output_str}\n")
      puts "\n"
      print_good("#{ip} Risponde #{latency_str}\n")
      


      #salva l'host come raggiungibile nel database di metasploit
      report_host(
        host:  ip,
        state: Msf::HostState::Alive,
        info:  "risposta ICMP #{latency_str}",
        comments: 'raggiungibile'
      )

      #salva ip e latenza nelle note del database
      report_note(
        host: ip,
        type: 'host.ping',
        data: { latency_in_ms: result[:latency], reachable: true} #pacchetti_inviati: result[:count]
      )

    else #se il ping non ha avuto successo
      puts "\n"
      print_status("#{ip} è down o blocca comunicazioni ICMP\n") 

      #salva l'host come sconosciuto nel database
      report_host(
        host:  ip,
        state: Msf::HostState::Unknown,
        comments: 'non raggiungibile o non risponde'

      )
    end
  end
end
