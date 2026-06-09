require 'msf/core' #standard library for the metasploit frameworks
require 'socket' #library for creating and use a socket
require 'resolv' #library for resolving domains into ip addresses 

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Ping checker',
      'Description' => 'Verify if a host is reachable by ICMP request',
      'Author'      => ['Karasu-77'],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptInt.new('COUNT', [false, 'Number of packets to send', 3]),
      OptInt.new('TIMEOUT', [false, 'Timeout between each packet sent', 1]),
      OptString.new('MESSAGE', [false, 'Message in the payload', 'hello'])
    ])
  end

  #cheksum method used to verify the integrity of the packet
  def check_sum(data)
    data += "\x00" if data.length.odd?
    sum = data.scan(/../).map { |b| b.unpack1('n') }.sum
    sum = (sum >> 16) + (sum & 0xffff) while sum > 0xffff
    ~sum & 0xffff
  end

  #method to create our own packet for the ICMP request
  def create_packet(ip, message)
    type = 8 #echo request
    code = 0
    checksum = 0
    id = Process.pid & 0xffff
    seq = 1
    payload = message.encode('ASCII')

    header = [type, code, checksum, id, seq].pack('C2n3')
    checksum = check_sum(header + payload)

    [type, code, checksum, id, seq].pack('C2n3') + payload
  end

  #creating the socket we need to send and recive the packet
  def send_packet(ip, packet, timeout)
    socket = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    #using timeout for each system
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [timeout, 0].pack('l_2'))
    socket.send(packet, 0, Socket.pack_sockaddr_in(0, ip))
    socket.recv(1024)  #to wait the ICMP answer 
    socket.close
  end

  #method for creating a packet and sending it 
  def ping_host(ip)
    count = datastore['COUNT']
    timeout = datastore['TIMEOUT']
    message = datastore['MESSAGE']

    #in the case it's needed to resolve a domain 
    begin
      ip = Resolv.getaddress(ip)
    rescue Resolv::ResolvError
      print_error("Impossible to find the domain: #{ip}")
      return {reachable: false, latency: nil}
    end

    #method to create each packet by using the method ceate_packet
    packet = create_packet(ip, message)
    print_status("Packet created for #{ip} with message: #{message}")

    #varibales and array
    latencies = [] 
    recived = 0
    success = false

    count.times do |i|
      begin
        the_start = Time.now 
        send_packet(ip, packet, timeout)  #waiting for the answer 
        the_end = Time.now

        latency = ((the_end - the_start) * 1000).round(2)
        latencies  << latency
        recived += 1
        success = true
        print_status("Packet #{i+1}/#{count} -> #{ip} (#{latency}ms)")
      rescue => e
        print_error("Packet #{i+1} lost: #{e.message}")
      end
      sleep timeout
    end
   
    #if something goes wrong
    if latencies.empty?
      return {reachable: false, latency: nil, min: nil, max: nil, loss: 100.0, jitter: nil}
    end

    min = latencies.min
    max = latencies.max
    avg = (latencies.sum / latencies.size).round(2)
    loss = (((count - recived).to_f / count) * 100).round(1)
    jitter = if latencies.size > 1
               diffs = latencies.each_cons(2).map {|a, b| (b - a).abs }
               (diffs.sum / diffs.size).round(2)
             else
               0.0
             end

    return {reachable: success, latency: avg, min: min, max: max, loss: loss, jitter: jitter}
  end

  def run_host(ip)
    result = ping_host(ip)

    if result[:reachable] #if the host is alive
      puts "\n"
      print_good("#{ip} is up!")
      puts "\n"
      print_status("Latency = min: #{result[:min]}ms  average: #{result[:latency]}ms  max: #{result[:max]}ms\n")
      print_status("Jitter = #{result[:jitter]}ms\n")
      print_status("Packet loss = #{result[:loss]}%\n")

      #reporting everything on the database
      report_host(
        host: ip,
        state: Msf::HostState::Alive,
        info: "ICMP min:#{result[:min]}ms avg:#{result[:latency]}ms max:#{result[:max]}ms loss:#{result[:loss]}%",
        comments: 'reachable'
      )

      report_note(
        host: ip,
        type: 'host.ping',
        data: { #hashing all the infos
          latency_min: result[:min],
          latency_avg: result[:latency],
          latency_max: result[:max],
          jitter:      result[:jitter],
          packet_loss: result[:loss]
        }
      )
    else #when the host is down or blocked
      print_error("#{ip}, the host is down or blocking ICMP requests.\n")

      report_host(
        host: ip,
        state: Msf::HostState::Unknown,
        comments: 'unreachable or blocked'
      )
    end
  end
end
