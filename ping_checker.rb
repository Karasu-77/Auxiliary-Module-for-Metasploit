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
      OptInt.new('COUNT',   [false, 'Numero di pacchetti da inviare', 2]),
      OptInt.new('TIMEOUT', [false, 'Timeout in secondi', 3])
    ])
  end

  def ping_host(ip) #metodo che esegue il ping sull'ip ricevuto
    count   = datastore['COUNT']   #legge il valore impostato 
    timeout = datastore['TIMEOUT'] 

    #posso immettere anche un dominio al posto dell'ip
    require 'resolv'
    begin
      resolved_ip = Resolv.getaddress(ip) #converte il dominio in ip
      if resolved_ip != ip
        print_status("#{ip} risolto in #{resolved_ip}")
      end
      ip = resolved_ip
    rescue Resolv::ResolvError #se il dominio non esiste
      print_error("Impossibile trovare il dominio: #{ip}")
      return { reachable: false, latency: nil, raw: '' }
    end

    #costruisce il comando ping in base al sistema operativo
    cmd = if RUBY_PLATFORM =~ /mingw|mswin/ # controlla se è windows ed esegue il comando
            "ping -n #{count} -w #{timeout * 1000} #{ip}"
          else
            "ping -c #{count} -W #{timeout} #{ip}" #se non è windows esegue il comando per linux/macos
          end

    output  = `#{cmd} 2>&1` #eseguito il comando e cattura l'output
    success = $?.exitstatus == 0 #0 = successo altrimenti fail

    #estrae la latenza dall'output con tre espressioni diverse per compatibilità
    latency  = output.match(/[Tt]ime[=<]([\d.]+)\s*ms/)&.captures&.first #linux
    latency ||= output.match(/Average\s*=\s*([\d.]+)\s*ms/)&.captures&.first  #windows
    latency ||= output.match(/min\/avg\/max[^=]+=\s*[\d.]+\/([\d.]+)/)&.captures&.first #macos

    { reachable: success, latency: latency, raw: output } # restituisce i risultati
  end

  def run_host(ip) #metodo chiamato automaticamente dallo scanner per ogni ip
    result = ping_host(ip) #chiama il metodo ping_host

    if result[:reachable] #se il ping ha avuto successo
      latency_str = result[:latency] ? " (#{result[:latency]}ms)" : ""
      print_good("#{ip} Risponde#{latency_str}") 

      #salva l'host come raggiungibile nel database di metasploit
      report_host(
        host:  ip,
        state: Msf::HostState::Alive,
        info:  "Risposta ICMP#{latency_str}"
      )

      #salva la latenza come nota nel database
      report_note(
        host: ip,
        type: 'host.ping',
        data: { latency_ms: result[:latency], reachable: true }
      )
    else #se il ping non ha avuto successo
      print_status("#{ip} è down o blocca comunicazioni ICMP") 

      #salva l'host come sconosciuto nel database
      report_host(
        host:  ip,
        state: Msf::HostState::Unknown
      )
    end
  end
end
