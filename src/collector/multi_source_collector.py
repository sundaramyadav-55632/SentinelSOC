class MultiSourceCollector:

    def __init__(self, input_files):
        self.input_files = input_files

    def collect(self):

        all_logs = []

        for file_path in self.input_files:

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8"
                ) as file:

                    for line in file:

                        line = line.strip()

                        if line:
                            all_logs.append({
                                "source_file": file_path,
                                "raw_log": line
                            })

            except FileNotFoundError:

                print(
                    f"[!] File not found: {file_path}"
                )

        return all_logs


if __name__ == "__main__":

    collector = MultiSourceCollector([
        "data/samples/auth.log",
        "data/samples/port_scan.log"
    ])

    logs = collector.collect()

    print(
        f"Collected logs: {len(logs)}"
    )

    for log in logs:

        print(
            f"[{log['source_file']}] "
            f"{log['raw_log']}"
        )