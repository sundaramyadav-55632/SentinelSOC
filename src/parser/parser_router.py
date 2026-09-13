from src.parser.linux_auth_parser import LinuxAuthParser
from src.parser.network_parser import NetworkParser


class ParserRouter:

    def __init__(self):
        self.linux_parser = LinuxAuthParser()
        self.network_parser = NetworkParser()

    def parse(self, log):

        source_file = log["source_file"]
        raw_log = log["raw_log"]

        if source_file.endswith("auth.log"):
            return self.linux_parser.parse(raw_log)

        if source_file.endswith("port_scan.log"):
            return self.network_parser.parse(raw_log)

        return None