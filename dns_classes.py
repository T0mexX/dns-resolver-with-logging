from __future__ import annotations
from ipaddress import IPv6Address, IPv4Address
from time import time
from enum import Enum
from collections.abc import Iterable
from typing import TypeVar, Generic
from inspect import cleandoc
from typing import final


def _qname_as_lbls(qname: str) -> bytes:
        domains: list[str] = qname.split(".")
        buf: bytes = b''
        for d in domains:
            buf += len(d).to_bytes(1, "big") + d.encode()
        
        buf += b'\x00'
        
        return buf

# ==================== Root Server ========================

class RootServer:
    '''
    Attributes:

    ping: response time of server, used to select the root server to use first
    '''

    def __init__(self, ipv4_ip: IPv4Address, ipv6_ip: IPv6Address, ping: int = 0, port = 53):
        self.ipv_4: IPv4Address = ipv4_ip
        self.ipv_6: IPv6Address = ipv6_ip
        self.ping: int = ping
        self.port: int = port
        self.__starting_time: int #in milliseconds

    def __str__(self) -> str:
        return f"[RootServer = ipv6: {self.ipv_6}, ipv4: {self.ipv_4} ping: {self.ping}]"
    
    __repr__ = __str__

    def ipv6_hostport(self) -> tuple[str, int]: return (str(self.ipv_6), self.port)
    def ipv4_hostport(self) -> tuple[str, int]: return (str(self.ipv_4), self.port)

    def start_stopwatch(self):
        self.__starting_time = time() * 1000

    def stop_stopwatch(self):
        self.ping = time() * 1000 - self.__starting_time


# ==================== Message ============================

class Msg:
    '''
    All communications inside of the domain protocol are carried in a single format called a message.  
    The top level format of message is divided into 5 sections: headers, questions, answers, 
    authoritative rrs and additionla rrs. (See Msg::from_bytes for additional info)
    '''
    

    qr_mask: int = 1 << 15
    op_code_mask: int = 15 << 11
    auth_answer_mask: int = 1 << 10
    trunc_mask: int = 1 << 9
    rec_desired_mask: int = 1 << 8
    rec_available_mask: int = 1 << 7
    resp_code_maks: int = 15

    @staticmethod
    def __extract_op_code(header: int | bytes) -> int: #if bytes it should be 2
        header: int = header if isinstance(header, int) else int.from_bytes(header, "big")
        return (header & Msg.op_code_mask) >> 11

    class OpCode(Enum):
        STDQUERY    = 0, "a standard query (QUERY)"
        IQUERY      = 1, "an inverse query (IQUERY)"
        STATUS      = 2, "a server status request (STATUS)"

        def __new__(cls, code: int, description: str) -> RR.QType:
            obj = object.__new__(cls)
            obj._value_ = code
            return obj

        def __init__(self, code: int, description: str):
            self.code: int = code
            self.description: str = description

    class RespCode(Enum):
        NO_ERR      =   0, "No error condition"
        FORMAT_ERR  =   1, "The name server was unable to interpret the query."
        SERVER_FAIL =   2, "Problem with the name server."
        NAME_ERROR  =   3, "Domain name referenced in the query does not exist."
        NOT_IMPL    =   4, "The name server does not support the requested kind of query."
        REFUSED     =   5, "The name server refuses to perform the specified operation for policy reasons."

        def __new__(cls, code: int, description: str) -> RR.QType:
            obj = object.__new__(cls)
            obj._value_ = code
            return obj

        def __init__(self, code: int, description: str):
            self.code: int = code
            self.description: str = description

    def __init__(self, 
                 id: int, 
                 query_or_response: bool, 
                 op_code: OpCode,
                 auth_answer: bool,     #authorative answer
                 truncated: bool,       #if msg is truncated due to excessive length
                 rec_desired: bool,      #recursion desired (NOT ALLOWED IN THE ASSIGNMENT)
                 rec_available: bool,
                 resp_code: RespCode,
                 questions: tuple[Question], #tuples in python are immutable
                 answers: tuple[RR],
                 auth_name_servers: tuple[RR],
                 additional_rrs: tuple[RR]
                 ):
        self.__id: int = id
        self.__query_or_response: bool = query_or_response
        self.__op_code: Msg.OpCode = op_code
        self.__auth_answer: bool = auth_answer
        self.__truncated: bool = truncated
        self.__rec_desired: bool = rec_desired
        self.__rec_available: bool = rec_available
        self.__resp_code: Msg.RespCode = resp_code
        self.questions: tuple[Question] = questions
        self.answers: tuple[RR] = answers
        self.auth_name_servers: tuple[RR] = auth_name_servers
        self.additional_rrs: tuple[RR] = additional_rrs

    def __str__(self) -> str:
        return \
            "\n" + cleandoc(
                f"""
                ========== Message ==================================================
                | id:                         {self.__id}
                | {'RESPONSE' if self.is_resp() else 'QUERY'}
                """ + \
                (f'''| response code:              {self.__resp_code.name}
                ''' if self.is_resp() else '')    + \
                f"""| op code:                    {self.__op_code.name}
                """ + \
                ('| Authorative Answer' if self.__auth_answer else '') + \
                ('| Truncated' if self.__truncated else '') + \
                ('| Recursive Desired' if self.__rec_desired else '') + \
                ('| Recursive Available' if self.__rec_available else '')
            ) + "\n" + cleandoc(
                f"""
                | questions:                  {'''
                |                             '''.join(map(lambda q: str(q), self.questions))}
                | answers:                    {'''
                |                             '''.join(map(lambda q: str(q), self.answers))}
                | authoritative name servers: {'''
                |                             '''.join(map(lambda q: str(q), self.auth_name_servers))}
                | additional resource records:{'''
                |                             '''.join(map(lambda q: str(q), self.additional_rrs))}
                =====================================================================
                """
            )

    __repr__ = __str__
    
    @property
    def id(self) -> int: return self.__id
    @property
    def op_code(self) -> Msg.OpCode: return self.__op_code
    @property
    def resp_code(self) ->          int: return self.__resp_code
    def is_resp(self) ->            bool: return self.__query_or_response
    def is_query(self) ->           bool: return not self.__query_or_response
    def is_truncated(self) ->       bool: return self.__truncated
    def is_auth(self) ->            bool: return self.__auth_answer
    def is_rec_desired(self) ->     bool: return self.__rec_desired
    def is_rec_available(self) ->   bool: return self.__rec_available

    def as_bytes(self) -> bytes:
        buf: bytes =  \
            self.__id.to_bytes(2, "big")                    + \
            self.__construct_header()                       + \
            len(self.questions).to_bytes(2, "big")          + \
            len(self.answers).to_bytes(2, "big")            + \
            len(self.auth_name_servers).to_bytes(2, "big")  + \
            len(self.additional_rrs).to_bytes(2, "big")      
        
        for q  in self.questions:           buf += q.as_bytes()
        for rr in self.answers:             buf += rr.as_bytes()
        for rr in self.auth_name_servers:   buf += rr.as_bytes()
        for rr in self.additional_rrs:      buf += rr.as_bytes()

        return buf
            
    def __construct_header(self) -> bytes:
        header: int = 0
        if self.is_resp():          header |= Msg.qr_mask
        if self.__auth_answer:      header |= Msg.auth_answer_mask
        if self.__rec_desired:      header |= Msg.rec_desired_mask
        if self.__rec_available:    header |= Msg.rec_available_mask
        if self.__truncated:        header |= Msg.trunc_mask
        
        header |= (self.__op_code.code << 11)
        header |= self.__resp_code.code

        return header.to_bytes(2, "big")


    @staticmethod
    def from_bytes(byte_msg) -> Msg: 
        '''
        Message format(0,...15 are bits, 1 octect = 16 bits): 

            ID:     A 16 bit identifier assigned by the program that
                    generates any kind of query.  This identifier is copied
                    the corresponding reply and can be used by the requester
                    to match up replies to outstanding queries.
            QR:     A one bit field that specifies whether this message is a
                    query (0), or a response (1).
            OPCODE: A four bit field that specifies kind of query in this
                    message.  This value is set by the originator of a query
                    and copied into the response.  The values are:
            AA:     Authoritative Answer - this bit is valid in responses,
                    and specifies that the responding name server is an
                    authority for the domain name in question section.
            TC:     TrunCation - specifies that this message was truncated
                    due to length greater than that permitted on the
                    transmission channel.
            RD:     Recursion Desired. If RD is set, it directs
                    the name server to pursue the query recursively.
                    Recursive query support is optional.
            RA:     Recursion Available - this be is set or cleared in a
                    response, and denotes whether recursive query support is
                    available in the name server.
            Z:      Reserved for future use.  Must be zero in all queries and responses.
            RCODE:  Response code - this 4 bit field is set as part of responses.  
                    The values have the following interpretation:

            QDCOUNT:    An unsigned 16 bit integer specifying the number of
                        entries in the question section.
            ANCOUNT:    An unsigned 16 bit integer specifying the number of
                        resource records in the answer section.
            NSCOUNT:    An unsigned 16 bit integer specifying the number of name
                        server resource records in the authority records section.
            ARCOUNT:    An unsigned 16 bit integer specifying the number of
                        resource records in the additional records section.

                                        1  1  1  1  1  1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        '''

        parser: _Parser = _Parser(byte_msg)
        msg_builder: Msg.Builder = Msg.Builder()
        header: int
        parser.set_index(0)

        msg_builder.set_id( int.from_bytes(  parser.get_next(2), "big"  )  ) 
        header = int.from_bytes(  parser.get_next(2), "big"  )

        num_questions: int =            int.from_bytes(  parser.get_next(2), "big"  )
        num_answers: int =              int.from_bytes(  parser.get_next(2), "big"  )
        num_auth_name_servers: int =    int.from_bytes(  parser.get_next(2), "big"  )
        num_additional_rrs: int =       int.from_bytes(  parser.get_next(2), "big"  )

        if header & Msg.qr_mask:    msg_builder.set_as_response()
        else: msg_builder.set_as_query()

        msg_builder.set_op_code (  Msg.OpCode(Msg.__extract_op_code(header))  ) \
            .set_auth_answer    (  header & Msg.auth_answer_mask  ) \
            .set_truncated      (  header & Msg.trunc_mask  ) \
            .set_rec_desired    (  header & Msg.rec_desired_mask  ) \
            .set_rec_available  (  header & Msg.rec_available_mask  ) \
            .set_resp_code      (  Msg.RespCode(header & Msg.resp_code_maks)  )

        for _ in range(num_questions):          msg_builder.add_question        (  Question.from_bytes(byte_msg, parser=parser))
        for _ in range(num_answers):            msg_builder.add_answer          (  RR.from_bytes(byte_msg, parser=parser)  )
        for _ in range(num_auth_name_servers):  msg_builder.add_auth_name_server(  RR.from_bytes(byte_msg, parser=parser)  )
        for _ in range(num_additional_rrs):     
            '''This avoids adding OPT pseudotype (which is added by the browser) to the query'''
            add_rr = RR.from_bytes(byte_msg, parser=parser)
            # if add_rr.type not in [RR.QType.OPT, RR.QType.UNKNOWN]: 
            if add_rr.type not in [RR.QType.OPT, RR.QType.UNKNOWN]: msg_builder.add_additional_rr(add_rr)

        return msg_builder.to_msg()

    @staticmethod
    def is_byte_msg_truncated(b: bytes) -> bool:
        return bool(Msg.trunc_mask & int.from_bytes(b[:2], "big"))


    class Builder:
        def __init__(self):
            self.__id: int
            self.__query_or_resp: bool = False
            self.__op_code: Msg.OpCode = Msg.OpCode.STDQUERY
            self.__auth_answer: bool = False
            self.__truncated: bool = False
            self.__rec_desired: bool = False
            self.__rec_available: bool = False
            self.__resp_code: Msg.RespCode = Msg.RespCode.NO_ERR
            self.__questions: list[Question] = []
            self.__answers: list[RR] = []
            self.__auth_name_servers: list[RR] = []
            self.__additional_rrs: list[RR] = []
        
        def set_id(self, id: int)                     -> Msg.Builder: self.__id = id; return self
        def set_op_code(self, op_code)                -> Msg.Builder: self.__op_code = op_code; return self
        def set_as_query(self)                        -> Msg.Builder: self.__query_or_resp = 0; return self
        def set_as_response(self)                     -> Msg.Builder: self.__query_or_resp = 1; return self
        def set_query_or_res(self, b: bool)           -> Msg.Builder: self.__query_or_resp = b; return self
        def set_auth_answer(self, b: bool)            -> Msg.Builder: self.__auth_answer = b; return self
        def set_truncated(self, b: bool)              -> Msg.Builder: self.__truncated = b; return self
        def set_rec_desired(self, b: bool)            -> Msg.Builder: self.__rec_desired = b; return self
        def set_rec_available(self, b: bool)          -> Msg.Builder: self.__rec_available = b; return self
        def set_resp_code(self, code: Msg.RespCode)   -> Msg.Builder: self.__resp_code = code; return self
        def add_question(self, *q: list[Question])    -> Msg.Builder: self.__questions.extend(q); return self
        def add_answer(self, *rr: list[RR])           -> Msg.Builder: self.__answers.extend(rr); return self
        def add_auth_name_server(self, *rr: list[RR]) -> Msg.Builder: self.__auth_name_servers.extend(rr); return self
        def add_additional_rr(self, *rr: list[RR])    -> Msg.Builder: self.__additional_rrs.extend(rr); return self

        def to_msg(self) -> Msg:
            if self.__id is None or self.__op_code is None or (self.__query_or_resp and self.__resp_code is None):
                raise AttributeError("id, op_code and resp_code(if it is a response) must be specified.")
            
            return Msg(
                id=                 self.__id,
                query_or_response=  self.__query_or_resp,
                op_code=            self.__op_code,
                auth_answer=        self.__auth_answer,
                truncated=          self.__truncated,
                rec_desired=        self.__rec_desired,
                rec_available=      self.__rec_available,
                resp_code=          self.__resp_code,
                questions=          tuple(self.__questions),
                answers=            tuple(self.__answers),
                auth_name_servers=  tuple(self.__auth_name_servers),
                additional_rrs=     tuple(self.__additional_rrs)
            )

        @staticmethod        
        def from_msg(msg: Msg) -> Msg.Builder:
            return Msg.Builder() \
                .set_id(msg.id) \
                .set_query_or_res(msg.is_resp()) \
                .set_op_code(msg.op_code) \
                .set_auth_answer(msg.is_auth()) \
                .set_truncated(msg.is_truncated()) \
                .set_rec_desired(msg.is_rec_desired()) \
                .set_rec_available(msg.is_rec_available()) \
                .set_resp_code(msg.resp_code) \
                .add_question(*msg.questions) \
                .add_answer(*msg.answers) \
                .add_auth_name_server(*msg.auth_name_servers) \
                .add_additional_rr(*msg.additional_rrs)

        

# ==================== Question ===========================

@final
class Question:
    """
    The question section is used to carry the "question" in most queries,
    i.e., the parameters that define what is being asked. (See Question::from_bytes for additional info)
    """
    
    def __init__(self, qname: str, qtype: RR.QType, qclass: RR.QClass):
        self.qname: str = qname
        self.qtype: RR.QType = qtype
        self.qclass: RR.QClass = qclass

    def __str__(self) -> str:
        return f"[Question = name: {self.qname}, qtype: {self.qtype.name}, qclass: {self.qclass.name}]"
    
    __repr__ = __str__

    def __hash__(self): return hash((self.qname, self.qtype, self.qclass))

    def __eq__(self, other: object) -> bool:
        '''Need __hash__ and __eq__ for attribute equality for question keys in chache dictionary'''
        return isinstance(other, Question) and self.qname == other.qname \
            and self.qtype == other.qtype and self.qclass == other.qclass

    def as_bytes(self) -> bytes:
        return _qname_as_lbls(self.qname) + \
            self.qtype.code.to_bytes(2, "big") + \
            self.qclass.code.to_bytes(2, "big")

    @staticmethod
    def from_bytes(byte_qst: bytes, parser: _Parser = None) -> Question:
        """""" """
        Section contains QDCOUNT (usually 1) entries, each of the following format:
                                            1  1  1  1  1  1
            0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                                               |
            /                     QNAME                     /
            /                                               /
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     QTYPE                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                     QCLASS                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        QNAME           a domain name represented as a sequence of labels, where
                        each label consists of a length octet followed by that
                        number of octets.  The domain name terminates with the
                        zero length octet for the null label of the root.  Note
                        that this field may be an odd number of octets; NO PADDING.
        QTYPE           a two octet code which specifies the type of the query.
                        The values for this field include all codes valid for a
                        TYPE field, together with some more general codes which
                        can match more than one type of RR.
        QCLASS          a two octet code that specifies the class of the query.
                        For example, the QCLASS field is IN for the Internet.
        """
        parser = _Parser(byte_qst) if parser is None else parser
        qname: str = parser.parse_name()
        qtype: RR.QType = RR.QType(  int.from_bytes(parser.get_next(2), "big")  )
        qclass: RR.QClass = RR.QClass(  int.from_bytes(parser.get_next(2), "big")  )

        return Question(qname, qtype, qclass)




    
    

# ==================== Resource Record ====================

@final
class RR:
    ptr_mask: int = 3 << 6  
    '''
    a pointer (1 byte) is distinguished from label size (00XXXXXX) by the 2 most significant bits set to 11 (11XXXXXX) where XXXXXX is the actual pointer
    '''

    class QType(Enum): # Type is also a QType, python std library does not allow extending enums
        # Types
        A       = 1, "a host address"
        NS      = 2, "an authoritative name server"
        MD      = 3, "a mail destination (Obsolete - use MX)"
        MF      = 4, "a mail forwarder (Obsolete - use MX)"
        CNAME   = 5, "the canonical name for an alias"
        SOA     = 6, "marks the start of a zone of authority"
        MB      = 7, "a mailbox domain name (EXPERIMENTAL)"
        MG      = 8, "a mail group member (EXPERIMENTAL)"
        MR      = 9, "a mail rename domain name (EXPERIMENTAL)"
        NULL    = 10, "a null RR (EXPERIMENTAL)"
        WKS     = 11, "a well known service description"
        PTR     = 12, "a domain name pointer"
        HINFO   = 13, "host information"
        MINFO   = 14, "mailbox or mail list information"
        MX      = 15, "mail exchange"
        TXT     = 16, "text strings"
        AAAA    = 28, "IPv6 address record"  #in rfc 3596
        HTTPS   = 65, "improves performance for clients that need to resolve many resources to access a domain." #in rfc 9460
        # there are more

        # Pseudo Types:
        OPT = 41, "different format, specified in RFC 6891, fucks up parsing"


        # QTypes (superclass of type, same enum since python does not allow enum inheritance)
        AXFR = 252, "Request for a transfer of an entire zone"
        MAILB = 253, "Request for mailbox-related records (MB, MG or MR)"
        MAILA = 254, "Request for mail agent RRs (Obsolete - see MX)"
        ALL = 245, "request for all records"

        UNKNOWN = 0, "Unknown type, not specified in RFC 1035 or 3596"

        def __new__(cls, code: int, description: str) -> RR.QType:
            obj = object.__new__(cls)
            obj._value_ = code
            return obj

        def __init__(self, code: int, description: str):
            self.code: int = code
            self.description: str = description

        @classmethod
        def _missing_(cls, _) -> RR.QType: return RR.QType.UNKNOWN


    class QClass(Enum):
        # Classes
        IN  = 1, "Internet" #the only one that we use
        CS  = 2, "CSNET class (Obsolete - used only for examples in some obsolete RFCs)"
        CH  = 3, "Chaos class"
        HS  = 4, "Hesiod [Dyer 87]"

        # QClasses (same as QTypes)
        ALL = 255, "any class (Qclass)"

        UNKNOWN = 0, "Unknown class, not specified in RFC 1035 or 3596"

        def __new__(cls, code: int, description: str) -> RR.QType:
            obj = object.__new__(cls)
            obj._value_ = code
            return obj

        def __init__(self, code: int, description: str):
            self.code: int = code
            self.description: str = description

        @classmethod
        def _missing_(cls, _) -> RR.QClass: return RR.QClass.UNKNOWN    

    def __init__(self, name: str, type: RR.QType, clas_s: RR.QClass , ttl: int, data: str):
        self.name: str = name
        self.type: RR.QType = type
        self.clas_s: RR.QClass = clas_s
        self.ttl: int = ttl #ttl = time to live
        self.data: str = data

    def __str__(self) -> str:
        return f"[RR = name: {self.name}, type: {self.type.name}, class: {self.clas_s.name}, ttl: {self.ttl}, data: {self.data}]"

    __repr__ = __str__

    def as_bytes(self) -> bytes: 
        data_bytes: bytes = self.__data_to_bytes()
        return _qname_as_lbls(self.name) + \
            self.type.code.to_bytes(2, "big") + \
            self.clas_s.code.to_bytes(2, "big") + \
            self.ttl.to_bytes(4, "big") + \
            len(data_bytes).to_bytes(2, "big") + \
            data_bytes

    @staticmethod
    def from_bytes(byte_rr: bytes, parser: _Parser = None) -> RR:
        ''''''
        '''
            labels          63 octets or less
            names           255 octets or less
            TTL             positive values of a signed 32 bit number.
            UDP messages    512 octets or less

            RR format(0,...15 are bits, 1 octect = 16 bits): 
                NAME:   an owner name, i.e., the name of the node to which this resource record pertains.
                TYPE:   two octets containing one of the RR TYPE codes.
                CLASS:  two octets containing one of the RR CLASS codes.
                TTL:    a 32 bit signed integer that specifies the time interval
                        that the resource record may be cached before the source
                        of the information should again be consulted.
                RDLENGT:an unsigned 16 bit integer that specifies the length in
                        octets of the RDATA field.

                                            1  1  1  1  1  1
              0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                                               |
            /                                               /
            /                      NAME                     /
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TYPE                     |
            |                     CLASS                     |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                      TTL                      |
            |                                               |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            |                   RDLENGTH                    |
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
            /                     RDATA                     /
            /                                               /
            +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        '''

        name: str
        type: RR.QType
        clas_s: RR.QClass
        ttl: int
        data: str | bytes
        parser: _Parser = _Parser(byte_rr) if parser is None else parser

        name = parser.parse_name()

        type = RR.QType(  int.from_bytes(parser.get_next(2), "big")  )
        clas_s = RR.QClass(  int.from_bytes(parser.get_next(2), "big")  )
        ttl = int.from_bytes(parser.get_next(4), "big")
        data_length: int = int.from_bytes(parser.get_next(2), "big")

        match type:
            case RR.QType.A: data = str(  IPv4Address(parser.get_next(data_length))  )
            case RR.QType.AAAA: data = str(  IPv6Address(parser.get_next(data_length))  )
            case RR.QType.CNAME | RR.QType.NS: data = parser.parse_name()
            case _: data = parser.get_next(data_length)

        # logger.debug(f"data: {data}")
        return RR(name, type, clas_s, ttl, data)

    def __data_to_bytes(self) -> bytes:
        match self.type:
            case RR.QType.A: return IPv4Address(self.data).__int__().to_bytes(4, "big")
            case RR.QType.AAAA: return IPv6Address(self.data).__int__().to_bytes(16, "big")
            case RR.QType.CNAME | RR.QType.NS: return _qname_as_lbls(self.data)
            case _: return self.data


        

# ==================== Parser =============================

T = TypeVar("T")
class _Parser(Generic[T]):
    def __init__(self, iterable: Iterable[T], index: int = 0):
        self.__iterable: Iterable = iterable
        self.__index: int = index #next elem to read

    def get_next(self, num_elements: int = 1) ->  Iterable[T]:
        elems_to_return: Iterable[T] = self.__iterable[self.__index : self.__index + num_elements]
        self.__index += num_elements
        return elems_to_return

    def next(self, num_elements: int = 1):
        return self.__iterable[self.__index : self.__index + num_elements - 1]        
        
    def set_index(self, idx: int) -> _Parser:
        self.__index = idx
        return self

    def idx(self) -> int: return self.__index

    def parse_name(self) -> str: #for qname it must be aligned, for the datafield it doesn't
        name_domains: list[str] = []
        byte: bytes
        bytes_read: int = 0

        while True:
            byte = self.get_next(1); bytes_read +=1
            if not byte: raise RuntimeError("Parsing failed (reached EOmsg), msg received is invalid.")
            if byte == b"\x00": break #name finished
            elif self.__is_pointer(byte):
                '''
                In order to reduce the size of messages, the domain system utilizes a compression scheme which eliminates the repetition of domain names in a
                message.  In this scheme, an entire domain name or a list of labels at the end of a domain name is replaced with a pointer to a prior occuranceof the same name.

                The pointer takes the form of a two octet sequence:
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                    | 1  1|                OFFSET                   |
                    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

                The first two bits are ones.  This allows a pointer to be distinguished from a label, since the label must begin with two zero bits because
                labels are restricted to 63 octets or less.  (The 10 and 01 combinations are reserved for future use.)  The OFFSET field specifies an offset from
                the start of the message (i.e., the first octet of the ID field in the domain header).  A zero offset specifies the first byte of the ID field,etc.

                The compression scheme allows a domain name in a message to be
                represented as either:
                - a sequence of labels ending in a zero octet
                - a pointer
                - a sequence of labels ending with a pointer
                '''
                name_domains.append(
                    self.__get_pointed_lbl(byte + self.get_next(1))
                )
                break
            else:
                lbl_size: int = int.from_bytes(byte, "big")
                name_domains.append(
                    self.get_next(lbl_size).decode()
                )
                bytes_read += lbl_size

        return ".".join(name_domains)
                
    def __is_pointer(self, byte: bytes | int) -> bool:
        uint8: int = byte if isinstance(byte, int) else int.from_bytes(byte, "big")
        return RR.ptr_mask & uint8
    
    def __get_pointed_lbl(self, byte_ptr: bytes) -> str:
        lbl: str
        ptr_mask: int = 0x3fff        
        idx_bak: int = self.idx()
        ptr: int = int.from_bytes(byte_ptr, "big") & ptr_mask
        lbl = self.set_index(ptr).parse_name()
        self.set_index(idx_bak)

        return lbl
