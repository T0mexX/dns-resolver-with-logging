# Introduction
`dns.py`, `dns_classes.py` and `dns_logger.py` implement a working Domain Name Server with the following main characteristics:
- Works as the pc resolver in the browser (tested with Chrome and Firefox on Linux), speed is not great but it was not implemented for speed. 
- Useful logging, both for debugging and understanding how dns works. Logging and server settings can be changed modifying `dns_config.ini`.
- The server offers recursive resolution and caching.
- Parsing of raw byte messages are (somewhat) explained in the related functions.

# Server Settings
What can be changed:
- Ip address and ports of both IPv6 and IPv4 sockets
- Server behaviour in case of a truncated message is received (establish tcp or not)
- UDP and TCP socket timeouts 
- Settings can also be provided as arguments on the command line, in that case the command line settings have the precedence on the config file

```
[ServerSettings]
use_tcp_for_truncated_responses = FALSE
ipv4_ip = localhost
ipv4_port = 53
ipv6_ip = ::1
ipv6_port = 53
udp_recv_timeout = 1
tcp_recv_timeout = 2
```
# Set As Computer DNS Resolver

### Linux
Edit `/etc/resolv.conf`, you should have a file like this:
```
nameserver 127.0.0.53
options edns0 trust-ad
search .
```

Modify it like this:
```
nameserver 127.0.0.1
#nameserver 127.0.0.53
options edns0 trust-ad
search .
```
> **WARNING:** 
> This file is restored to default in some cases, remember to check if this happened occasionally


The server settings in `dns_config.ini` need to reflect these changes, the default port for the computer resolver is 53 and it **cannot** be changed. Modify the file accordingly, for example:
```
[ServerSettings]
ipv4_ip = localhost
ipv4_port = 53
ipv6_ip = ::1
ipv6_port = 53
```
> **WARNING:**
> port 53 can be bound only if the program is runned as privileged user!!! -> `sudo python3 dns.py`



### Windows
IDK

# Logging
What can be logged:
- Formatted initial, final, and in between (during recursion) messages.
- Raw inital, final, and in between (during recursion) messages.
- Current state of cache and responses fetched from cache.
- Various error and warning messages (timeout, dropped queries, unrecognized resource records etc.).

Personalize logging by modifying `dns_config_ini` (*All logging options are explained in the file*).
Log messages can be written to a file providing the file name as `target_file` entry as below:
```
[Log]
target_file = dns.log 
initial_query = TRUE 
final_response = TRUE 
sent_query = FALSE
received_responses = FALSE 
timeout_error = FALSE 
unrecognized_rr_warning = FALSE 
dropped_query = TRUE 
sent_msg_as_bytes = FALSE 
received_msg_as_bytes = FALSE 
no_answer_for_query = TRUE 
error = TRUE 
cache = True 
cache_fetch = True
```

### Some Logging Examples (with different settings):

Formatted messages:
> ![](formatted_msgs.png) 
---
From query bytes to query message:
> ![](msg_from_query_bytes.png)
---
Final response from message to bytes:
>![](final_response_to_bytes.png)
---
Cahe fetch:
> ![](cache_fetch.png)
---
Cache and Root Servers pings statuses:
> ![](cache&rootservers_status.png)
---
Example of recursive behaviour while solving a query:
> ![](recursion.png)


# CodeGrade
Automatic tests work locally but not on codegrade unless a single python file is uploaded. Hence a merged version of the code is provided in `codegrade_dns.py`. If you want to test it on codegrade you need to change the file name to `dns.py` (careful to not override the `dns.py` original file) and submit the new `dns.py` with `dns_config.ini`.
```
cp dns.py dns.bak
cp codegrade_dns.py dns.py
```
![bo](codegrade_example.png)
> **WARNING:** Tests expect the dns server to listen to 'localhost' port 8000, modify `dns_config.ini` accordingly:
```
[ServerSettings]
...
ipv4_ip = localhost
ipv4_port = 8000
ipv6_ip = ::1
ipv6_port = 8000
...

```


# Conclusions
Now you should be able to navigate using this dns server, you will notice it is not as fast as the default one (and speed is highly dependant on the server settings you are using). The program was not written for speed, and being python it would not be fast anyway xD, nevertheless now you can analyze your browser behavior and how domain name resolution works behind the scene for everyday tasks!
