import argparse
from ipaddress import IPv6Address, ip_address, IPv4Address
from dns_classes import RootServer, RR, Msg, Question
import socket
from threading import Thread
import threading
from time import sleep, time
from dns_logger import DNS_Logger, LogType
from configparser import ConfigParser


# =============== Argument Parsing ===============
parser = argparse.ArgumentParser()


parser.add_argument('--ipv4only', type=bool, default=None)
parser.add_argument('--address', type=str, default=None)
parser.add_argument('--port', type=str, default=None)

parser.add_argument('--ipv6address', type=str, help='Server IP address')
parser.add_argument('--ipv6port', type=int, help='Server Port') # smallest port usable by unprivileged users
parser.add_argument('--ipv4address', type=str, help='Server IP address')
parser.add_argument('--ipv4port', type=int, help='Server Port')
parser.add_argument('--udptimeout', type=float, help='time the server waits for an udp response')
parser.add_argument('--tcptimeout', type=float, help='time the server waits for a tcp response (no effect if tcp is not used)')
parser.add_argument('--usetcp', action='store_true', help='if this option is anabled the dns server will establish a tcp connection whenever a received msg is truncated')

args = parser.parse_args()

# =============== Config Parsing =================
config_file: ConfigParser = ConfigParser()
config_file.read("dns_config.ini")

HostPort = tuple[str, int]
IPv6_HOSTPORT: HostPort = (
    args.ipv6address if args.ipv6address else config_file.get("ServerSettings", "ipv6_ip", fallback="::1"),
    args.ipv6port if args.ipv6port else config_file.getint("ServerSettings", "ipv6_port", fallback=53)
)
IPv4_HOSTPORT: HostPort = (
    args.ipv4address if args.ipv4address else config_file.get("ServerSettings", "ipv4_ip", fallback="localhost"),
    args.ipv4port if args.ipv4port else config_file.getint("ServerSettings", "ipv4_port", fallback=53)
)
TCP_ENABLED: bool = args.usetcp if args.usetcp else config_file.getboolean("ServerSettings", "use_tcp_for_truncated_responses", fallback=False)
UDP_RECV_TIMEOUT: float = args.udptimeout if args.udptimeout else  config_file.getfloat("ServerSettings", "udp_recv_timeout", fallback=1)
TCP_RECV_TIMEOUT: float = args.tcptimeout if args.tcptimeout else config_file.getfloat("ServerSettings", "tcp_recv_timeout", fallback=2)

print(f"Serving DNS on port {IPv6_HOSTPORT} and {IPv4_HOSTPORT}")

# =============== Logger =========================
logger = DNS_Logger()
logger.read_config("./dns_config.ini")

root_servers: list[tuple[str, str]]= [
    ("198.41.0.4", "2001:503:ba3e::2:30"), ("170.247.170.2", "2801:1b8:10::b"), ("192.33.4.12", "2001:500:2::c"),
    ("199.7.91.13", "2001:500:2d::d"), ("192.203.230.10", "2001:500:a8::e"), ("192.5.5.241", "2001:500:2f::f"),
    ("192.112.36.4", "2001:500:12::d0d"), ("198.97.190.53", "2001:500:1::53"), ("192.36.148.17", "2001:7fe::53"),
    ("192.58.128.30", "2001:503:c27::2:30"), ("193.0.14.129", "2001:7fd::1"), ("199.7.83.42", "2001:500:9f::42"),
    ("202.12.27.33", "2001:dc3::35")
]

root_servers: tuple[RootServer, ...] = tuple(map(
    lambda t: RootServer(ipv4_ip=IPv4Address(t[0]),ipv6_ip=IPv6Address(t[1])), root_servers
))

def _sort_root_servers(): 
    global root_servers
    root_servers = tuple(sorted(root_servers, key=lambda s: s.ping))

recv_sock_ipv4: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock_ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
recv_sock_ipv4.bind(IPv4_HOSTPORT)
recv_sock_ipv6: socket.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
recv_sock_ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
recv_sock_ipv6.bind(IPv6_HOSTPORT)

TCP_BUFF_SIZE: int = 8192
MAX_MSG_SIZE: int = 512
DEFAULT_DNS_PORT: int = 53


class QuerySolver(Thread):

    def __init__(self, query: Msg, requester_hostport: HostPort):
        Thread.__init__(self, daemon=True)
        self.__requester_hostport: HostPort = requester_hostport
        self.__original_query: Msg = query
        self.__sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__sock.settimeout(UDP_RECV_TIMEOUT)
        logger.info(f"Serving query by {requester_hostport}:{query}", LogType.INIT_QUERY)


    def __query_timeout(self):
        self.__send_result()
        logger.error(f"Dropped query from {self.__requester_hostport}: {self.__original_query}", LogType.DROPPED_QUERY)
        exit()

    def run(self):
        timeout_timer: threading.Timer= threading.Timer(20, lambda: self.__query_timeout())
        final_response: Msg | None = None

        final_response= cache.get_if_present(self.__original_query.questions[0])
        if final_response: logger.info(f"Fetched from cache answer to: {self.__original_query.questions[0]}")

        #if answer not cached and recursion is desired
        if not final_response and self.__original_query.is_rec_desired():
            final_response = self.__solve_query_from_root(query=self.__original_query)

        timeout_timer.cancel()
        self.__send_result(final_response) #None => default with no answers
        

    def __solve_query_from_root(self, query: Msg) -> Msg | None:
        root_servers_snapshot: tuple[RootServer, ...] = root_servers
        
        for s in root_servers_snapshot:
            s.start_stopwatch()
            response: Msg = self.__send_and_get_response(query, s.ipv4_hostport())
            s.stop_stopwatch()

            response: Msg = self.__recursive_query(query, previous_response=response)
            if response: return response

        return None
                

    def __recursive_query(self, query: Msg, previous_response: Msg) -> Msg | None:
        if previous_response is None: return previous_response
        
        target_rr_type: RR.QType = query.questions[0].qtype
        for rr in previous_response.answers:
            if rr.type == target_rr_type: return previous_response # we got our answers
            elif rr.type == RR.QType.CNAME:
                '''
                CNAME just represent an alternative name for our query name, some dns servers just 
                return the CNAME records as response, but we can also proceed with a new query for 
                the new name (when returning the response though the rrs in question and answers 
                sections need to have the original name for Chrome, not needed for Firefox)
                '''
                new_query: Msg = Msg.Builder() \
                        .set_id(query.id) \
                        .set_rec_desired(False) \
                        .add_question(Question(qname=rr.data, qtype=target_rr_type, qclass=RR.QClass.IN)) \
                        .to_msg()
                new_q_response: Msg = self.__solve_query_from_root(new_query)
                if new_q_response: return new_q_response

        for rr in previous_response.additional_rrs + previous_response.auth_name_servers:
            '''
            We start from additional rrs since often NS records in authoritative section have their 
            A, AAAA rrs in the additional section, therfore we can proceed contacting those servers 
            instead of starting a new qury from root for the authoritative name server.
            '''
            if rr.clas_s not in [RR.QClass.IN, RR.QClass.ALL]: continue

            match rr.type:
                case RR.QType.A: 
                    response: Msg = self.__send_and_get_response(query, hostport=(rr.data, 53))
                    rec_response: Msg = self.__recursive_query(query, previous_response=response)
                    if rec_response: return rec_response
                case RR.QType.AAAA: pass #usually both A and AAAA are received for the same RR
                case RR.QType.NS:
                    '''
                    If we get to NS rrs probably these NS records did not have their corresponding A, AAAA rrs 
                    in the additional section, therefore we proceed starting a new qury from root
                    '''
                    new_query: Msg = Msg.Builder() \
                        .set_id(query.id) \
                        .set_rec_desired(False) \
                        .add_question(Question(qname=rr.data, qtype=RR.QType.A, qclass=RR.QClass.IN)) \
                        .to_msg()
                    
                    resp_to_new_query: Msg = self.__solve_query_from_root(query=new_query)
                    if resp_to_new_query is None: continue
                    for rr_type_A in resp_to_new_query.answers:
                        response: Msg = self.__send_and_get_response(query, hostport=(rr_type_A.data, 53))
                        if response is None: continue
                        rec_response: Msg = self.__recursive_query(query, response)
                        if rec_response is not None: return rec_response

                case _: logger.warning(f"RR type {rr.type.name} not supported, skipping...", LogType.UNRECOGNIZED_RR)

        return None

    def __send_and_get_response(self, query: Msg, hostport: HostPort) -> Msg | None:
        logger.info(f"Sending to {hostport} msg: {query}", LogType.SENT_QUERY)
        logger.info(f"Sending to {hostport} bytes: \n{query.as_bytes()}", LogType.SENT_MSG_AS_BYTES)

        self.__sock.sendto(query.as_bytes(), hostport)
        response: Msg = self.__recv_full_msg(query, hostport)

        logger.info(f"Received response from {hostport}: {response}", LogType.RECVD_RESP)
        return response


    def __recv_full_msg(self, query: Msg, hostport: HostPort) -> Msg | None:
        try:
            while True:
                resp_bytes: bytes = self.__sock.recv(MAX_MSG_SIZE)
                if TCP_ENABLED and Msg.is_byte_msg_truncated(resp_bytes): return self.__send_and_get_resp_tcp(query, hostport)
                response: Msg = Msg.from_bytes(resp_bytes)
                if response.id == query.id: 
                    logger.info(f"Received bytes from {hostport}:\n{resp_bytes}", LogType.RECVD_MSG_AS_BYTES)
                    return response
        except TimeoutError: 
            logger.warning(f"Timeout reached for hostport {hostport}", LogType.TIMEOUT)
            return None

    def __send_and_get_resp_tcp(self, query: Msg, hostport: HostPort) -> Msg | None:
        '''If message is truncated tcp connection can be established (some servers not even support it though)'''
        logger.info(f"Message truncated, using tcp...")
        try:
            tcp_sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tcp_sock.connect(hostport)
            tcp_sock.settimeout(TCP_RECV_TIMEOUT)
            tcp_sock.send(query.as_bytes())
            resp_bytes: bytes = tcp_sock.recv(TCP_BUFF_SIZE)
        except: return None

        logger.info(f"Received bytes from {hostport}:\n{resp_bytes}", LogType.RECVD_MSG_AS_BYTES)

        return Msg.from_bytes(resp_bytes)
    
    def __send_result(self, final_response: Msg = None):
        '''
        Sends back to requester the final response if defined, 
        otherwise sends back a default reponse with no answers
        '''

        if not final_response: logger.warning(f"No answer to {self.__original_query}", LogType.NO_ANSWER)

        original_question: Question = self.__original_query.questions[0]

        final_response: Msg = Msg.Builder() \
            .set_id(self.__original_query.id) \
            .set_rec_available(True) \
            .set_rec_desired(self.__original_query.is_rec_desired()) \
            .set_as_response()\
            .set_auth_answer(False) \
            .add_question(original_question) \
            .add_answer(  *map(lambda rr: RR(original_question.qname, rr.type, rr.clas_s, rr.ttl, rr.data), final_response.answers) if final_response else [] ) \
            .to_msg()
        '''Replacing the answers names with the original query names (in case CNAME was resolved) is needed for chrome but not for firefox (not tested with other browsers)'''
        
        if final_response.answers: cache.add_to_cache(final_response)
        
        logger.info(f"Sending response to {self.__requester_hostport}: {final_response}", LogType.FIN_RESPONSE)
        logger.info(f"Sending bytes to {self.__requester_hostport}: \n{final_response.as_bytes()}", LogType.SENT_MSG_AS_BYTES)

        requester_ip: str = self.__requester_hostport[0]
        if ip_address(requester_ip).version == 6: 
            recv_sock_ipv6.sendto(final_response.as_bytes(), self.__requester_hostport)
        else: recv_sock_ipv4.sendto(final_response.as_bytes(), self.__requester_hostport)


class Cache:

    class EntryValue:
        def __init__(self, msg: Msg):
            self.msg: Msg = msg
            self.when_cached: float = time()

    def __init__(self):
        self.__cached: dict[Question, Cache.EntryValue] = dict()
    
    def __str__(self) -> str:
        return str(self.__cached.keys())

    def add_to_cache(self, response_msg: Msg):
        for question in response_msg.questions:
            self.__cached.update({question : Cache.EntryValue(response_msg)})

    def clear_cache(self):
        #filter expired answers in response messages (usually all answers have the same ttl but you never know)
        for _, entry in self.__cached.items():
            now: float = time()
            entry.msg.answers = [a for a in entry.msg.answers if now - entry.when_cached < a.ttl]
            
        #filter response messages with no still valid answers
        self.__cached = dict({q:entry for q, entry in self.__cached.items() if len(entry.msg.answers) > 0})

    def get_if_present(self, question: Question) -> Msg | None:
        '''Question::__hash__ and __eq__ are overrided to provide attribute equality'''
        entry: Cache.EntryValue = self.__cached.get(question)
        return entry.msg if entry else None
            



def _recv_questions_thread_fun(sock: socket.socket):
    msg_bytes: bytes
    requester_hostport: HostPort
    while True:
        try:
            msg_bytes, requester_hostport = sock.recvfrom(512) # max dns message size
            logger.info(f"Received query bytes: \n{msg_bytes}", LogType.RECVD_MSG_AS_BYTES)
            QuerySolver(Msg.from_bytes(msg_bytes), requester_hostport).start()
        except Exception as e: logger.error(e)
    

cache: Cache = Cache()
ipv6_thread: Thread = Thread(target=_recv_questions_thread_fun, daemon=True, args=(recv_sock_ipv6,)).start()
ipv4_thread: Thread = Thread(target=_recv_questions_thread_fun, daemon=True, args=(recv_sock_ipv4,)).start()

logger.info( "\n==================== NEW SESSION ==========================")

while True:
    sleep(5)
    _sort_root_servers()
    cache.clear_cache()
    logger.info(f"Current cache: {cache}", LogType.CACHE)
    logger.info("Current root servers by ping:\n"  + '\n'.join(map(lambda s: str(s), root_servers)), LogType.ROOT_SRVRS)
