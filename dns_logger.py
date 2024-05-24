from __future__ import annotations
import logging
from enum import Enum, auto
import sys
from pprint import pformat

logging.basicConfig(filename=None, level=logging.DEBUG)

class LogType(Enum):
    INIT_QUERY = auto(), "initial_query"
    FIN_RESPONSE = auto(), "final_response"
    SENT_QUERY = auto(), "sent_query"
    RECVD_RESP = auto(), "received_responses"
    TIMEOUT = auto(), "timeout_error"
    UNRECOGNIZED_RR = auto(), "unrecognized_rr_warning"
    DROPPED_QUERY = auto(), "dropped_query"
    SENT_MSG_AS_BYTES = auto(), "sent_msg_as_bytes"
    RECVD_MSG_AS_BYTES = auto(), "received_msg_as_bytes"
    NO_ANSWER = auto(), "no_answer_for_query"
    CACHE = auto(), "cache"
    ERROR = auto(), "error"
    ROOT_SRVRS = auto(), "root_servers"

    def __new__(cls, val, _: str) -> LogType:
        obj = object.__new__(cls)
        obj._value_ = val
        return obj

    def __init__(self, val: int, entry_name: str):
        self.val = val
        self.entry_name: str = entry_name

    def __str__(self) -> str: return self.name
    __repr__ = __str__


default_config: dict[LogType, bool] = \
{
    LogType.INIT_QUERY          : True,
    LogType.FIN_RESPONSE        : True,
    LogType.SENT_QUERY          : False,
    LogType.RECVD_RESP          : False,
    LogType.TIMEOUT             : False, 
    LogType.UNRECOGNIZED_RR     : False,
    LogType.DROPPED_QUERY       : True,
    LogType.SENT_MSG_AS_BYTES   : False,
    LogType.RECVD_MSG_AS_BYTES  : False,
    LogType.NO_ANSWER           : True,
    LogType.ERROR               : True,
    LogType.ROOT_SRVRS          : False
}


class DNS_Logger:
    def __init__(self):
        self.__logger = logging.getLogger()
        self.__log_config: dict[LogType, bool] = default_config.copy()

    def warning(self, msg: str, log_type: LogType):
        if self.__log_config.get(log_type): self.__logger.warning(msg)

    def error(self, msg: str):
        if self.__log_config.get(LogType.ERROR): self.__logger.error(msg)

    def info(self, msg: str, log_type: LogType | None = None):
        if not log_type: self.__logger.info(msg); return
        if self.__log_config.get(log_type): self.__logger.info(msg)

    def read_config(self, path: str):
        from configparser import ConfigParser
        config_file = ConfigParser()
        try:
            config_file.read(path)
        except:
            self.__logger.error(f"Unable to read config file {path}, no changes to settings took place")
            return

        for log_type in LogType:
            self.__log_config.update(
                {log_type : config_file.getboolean(
                    "Log", log_type.entry_name, fallback=default_config.get(log_type)
                )}
            )

        target_file: str = config_file.get("Log", "target_file", fallback=None)
        print(f"Logger outputs to : {target_file if target_file else 'stdout'}")
        if target_file:
            out_handler = logging.FileHandler(target_file)
        else:
            out_handler = logging.StreamHandler(sys.stdout)
        
        formatter = logging.Formatter(fmt='%(asctime)s.%(msecs)003d :: %(levelname)-8s :: %(message)s', datefmt='%H:%M:%S')
        out_handler.setFormatter(formatter)
        self.__logger.handlers.clear()
        self.__logger.addHandler(out_handler)
        self.__logger.info(f"\n==================== Log Configuration ====================\n{pformat(self.__log_config)}")


