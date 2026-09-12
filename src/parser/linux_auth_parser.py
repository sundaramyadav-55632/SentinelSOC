import re
from datetime import datetime

from src.utils.event_schema import SecurityEvent


class LinuxAuthParser:

    FAILED_LOGIN_PATTERN = re.compile(
        r"Failed password for (?:invalid user )?"
        r"(?P<username>\S+) from "
        r"(?P<source_ip>\d+\.\d+\.\d+\.\d+) "
        r"port (?P<source_port>\d+)"
    )

    SUCCESS_LOGIN_PATTERN = re.compile(
        r"Accepted password for "
        r"(?P<username>\S+) from "
        r"(?P<source_ip>\d+\.\d+\.\d+\.\d+) "
        r"port (?P<source_port>\d+)"
    )

    def parse(self, log_line):

        if "Failed password" in log_line:
            return self._parse_failed_login(log_line)

        if "Accepted password" in log_line:
            return self._parse_successful_login(log_line)

        return None

    def _extract_timestamp(self, log_line):
        match = re.match(
            r"(?P<month>\w{3}) "
            r"(?P<day>\d{1,2}) "
            r"(?P<time>\d{2}:\d{2}:\d{2})",
            log_line
        )

        if not match:
            return datetime.now().isoformat()

        return (
            f"2026-{datetime.strptime(match.group('month'), '%b').month:02d}-"
            f"{int(match.group('day')):02d}T"
            f"{match.group('time')}"
        )

    def _parse_failed_login(self, log_line):

        match = self.FAILED_LOGIN_PATTERN.search(log_line)

        if not match:
            return None

        return SecurityEvent(
            timestamp=self._extract_timestamp(log_line),
            source="linux",
            event_type="authentication_failure",
            severity="medium",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            destination_port=22,
            message=log_line
        )

    def _parse_successful_login(self, log_line):

        match = self.SUCCESS_LOGIN_PATTERN.search(log_line)

        if not match:
            return None

        return SecurityEvent(
            timestamp=self._extract_timestamp(log_line),
            source="linux",
            event_type="authentication_success",
            severity="low",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            destination_port=22,
            message=log_line
        )


if __name__ == "__main__":

    parser = LinuxAuthParser()

    test_log = (
        "Sep 12 17:30:01 server sshd[1001]: "
        "Failed password for admin from 192.168.1.50 "
        "port 52341 ssh2"
    )

    event = parser.parse(test_log)

    if event:
        print(event.to_json())