from src.collector.log_collector import LogCollector
from src.parser.linux_auth_parser import LinuxAuthParser
from src.detectors.detection_manager import DetectionManager
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine


class SentinelEngine:

    def __init__(self, input_file):

        self.collector = LogCollector(input_file)
        self.parser = LinuxAuthParser()

        self.detection_manager = DetectionManager()

        self.correlation = CorrelationEngine(
            correlation_window_seconds=60
        )

        self.risk_engine = RiskEngine()

    def run(self):

        print("=" * 60)
        print("SENTINELSOC SECURITY OPERATIONS ENGINE")
        print("=" * 60)

        # 1. Collect logs
        raw_logs = self.collector.collect()

        print(f"\n[+] Collected logs: {len(raw_logs)}")

        # 2. Parse logs
        events = []

        for log in raw_logs:

            event = self.parser.parse(log)

            if event:
                events.append(event)

        print(f"[+] Parsed security events: {len(events)}")

        # 3. Detect attacks
        alerts = self.detection_manager.detect(events)

        print(f"[+] Detection alerts: {len(alerts)}")

        # 4. Correlate events
        incidents = self.correlation.correlate(
            events,
            alerts
        )

        print(f"[+] Correlated incidents: {len(incidents)}")

        # 5. Calculate risk
        final_incidents = []

        for incident in incidents:

            risk = self.risk_engine.calculate_score(
                incident
            )

            final_incident = {
                **incident,
                **risk
            }

            final_incidents.append(
                final_incident
            )

        # 6. Display incidents
        print("\n" + "=" * 60)
        print("SECURITY INCIDENTS")
        print("=" * 60)

        for incident in final_incidents:

            print("\n🚨 INCIDENT DETECTED")

            print(
                f"Type: {incident['incident_type']}"
            )

            print(
                f"Source IP: {incident['source_ip']}"
            )

            print(
                f"Username: {incident['username']}"
            )

            print(
                f"Failed Attempts: "
                f"{incident['failed_attempts']}"
            )

            print(
                f"Risk Score: "
                f"{incident['risk_score']}/100"
            )

            print(
                f"Severity: "
                f"{incident['severity'].upper()}"
            )

            print("\nReasons:")

            for reason in incident["reasons"]:

                print(f"  - {reason}")

        return final_incidents


if __name__ == "__main__":

    engine = SentinelEngine(
        "data/samples/auth.log"
    )

    engine.run()