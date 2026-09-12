import re

from src.utils.event_schema import SecurityEvent


class NetworkParser:

    PATTERN = re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?"
        r"from\s+"
        r"(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
        r":(?P<source_port>\d+)"
        r"\s+to\s+"
        r"(?P<destination_ip>\d+\.\d+\.\d+\.\d+)"
        r":(?P<destination_port>\d+)"
    )

    def parse(self, log):

        match = self.PATTERN.search(log)

        if not match:
            return None

        data = match.groupdict()

        timestamp = self._normalize_timestamp(
            data["timestamp"]
        )

        return SecurityEvent(
            timestamp=timestamp,
            source="firewall",
            event_type="connection_attempt",
            severity="low",
            source_ip=data["source_ip"],
            source_port=int(data["source_port"]),
            destination_ip=data["destination_ip"],
            destination_port=int(data["destination_port"]),
            protocol="TCP",
            action="ALLOW",
            message=log
        )

    def _normalize_timestamp(self, timestamp):

        parts = timestamp.split()

        month = parts[0]
        day = parts[1]
        time = parts[2]

        month_numbers = {
            "Jan": "01",
            "Feb": "02",
            "Mar": "03",
            "Apr": "04",
            "May": "05",
            "Jun": "06",
            "Jul": "07",
            "Aug": "08",
            "Sep": "09",
            "Oct": "10",
            "Nov": "11",
            "Dec": "12"
        }

        return (
            f"2026-{month_numbers[month]}-{int(day):02d}T{time}"
        )


if __name__ == "__main__":

    parser = NetworkParser()

    with open(
        "data/samples/port_scan.log",
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            event = parser.parse(line.strip())

            if event:
                print(event.to_json())