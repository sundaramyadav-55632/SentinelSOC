import json

from src.collector.log_collector import LogCollector
from src.parser.linux_auth_parser import LinuxAuthParser


class SecurityEventPipeline:

    def __init__(self, input_file, output_file):
        self.collector = LogCollector(input_file)
        self.parser = LinuxAuthParser()
        self.output_file = output_file

    def process(self):
        raw_logs = self.collector.collect()

        events = []

        for log in raw_logs:
            event = self.parser.parse(log)

            if event:
                events.append(event)

        with open(self.output_file, "w", encoding="utf-8") as file:
            for event in events:
                file.write(
                    json.dumps(event.to_dict()) + "\n"
                )

        return events


if __name__ == "__main__":

    pipeline = SecurityEventPipeline(
        "data/samples/auth.log",
        "data/normalized/auth_events.jsonl"
    )

    events = pipeline.process()

    print(f"Processed {len(events)} security events")
    print("Output: data/normalized/auth_events.jsonl")