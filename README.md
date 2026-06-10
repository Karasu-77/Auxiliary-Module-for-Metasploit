Auxiliary module for the Metasploit framework.

Remember, to create and send raw packets the root privileges are needed, use "sudo msfconsole".

The ping checker uses personalized ICMP packets (echo request with chosen payload) to verify if one or multiple hosts are reachable or not on the internet.
You can set 1 or more ip addresses domains included (RHOST/RHOSTS), the number of packets you want to send (COUNT), also the waiting time for a response (TIMEOUT), the number of process (THREADS) and the payload (MESSAGE) too.
After the execution (RUN) the output has host up or down, latency (min, max, average), packet loss and jitter.
If the host is alive it will be saved in the database with those information and in the notes with the hash of the same information (HOSTS, NOTES).
If the host is down or protected by a firewall it will be saved too but reported as unreachable or blocked.



