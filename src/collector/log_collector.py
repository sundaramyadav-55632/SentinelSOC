from pathlib import Path


class LogCollector:
    def __init__(self, log_file):
        self.log_file = Path(log_file)

    def collect(self):
        if not self.log_file.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.log_file}"
            )

        with self.log_file.open("r", encoding="utf-8") as file:
            return [
                line.strip()
                for line in file
                if line.strip()
            ]


if __name__ == "__main__":
    collector = LogCollector("data/samples/auth.log")

    logs = collector.collect()

    print(f"Collected {len(logs)} log events")

    for log in logs:
        print(log)