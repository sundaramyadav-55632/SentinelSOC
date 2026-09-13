from src.collector.multi_source_collector import MultiSourceCollector
from src.parser.parser_router import ParserRouter
from src.detectors.detection_manager import DetectionManager
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine
from src.response.response_engine import ResponseEngine
from src.database.incident_store import IncidentStore


class SentinelEngine:

    def __init__(self, input_files):

        self.collector = MultiSourceCollector(
            input_files
        )

        self.parser_router = ParserRouter()

        self.detection_manager = DetectionManager()

        self.correlation = CorrelationEngine(
            correlation_window_seconds=60
        )

        self.risk_engine = RiskEngine()

        self.response_engine = ResponseEngine()

        self.incident_store = IncidentStore()

    def run(self):

        print("=" * 70)
        print("SENTINELSOC UNIFIED SECURITY OPERATIONS ENGINE")
        print("=" * 70)

        # --------------------------------------------------
        # 1. COLLECT
        # --------------------------------------------------

        raw_logs = self.collector.collect()

        print(
            f"\n[+] Collected logs: {len(raw_logs)}"
        )

        # --------------------------------------------------
        # 2. PARSE
        # --------------------------------------------------

        events = []

        for log in raw_logs:

            event = self.parser_router.parse(log)

            if event:
                events.append(event)

        print(
            f"[+] Parsed security events: {len(events)}"
        )

        # --------------------------------------------------
        # 3. SAVE EVENTS
        # --------------------------------------------------

        for event in events:

            self.incident_store.save_event(
                event
            )

        print(
            f"[+] Events stored in database: "
            f"{len(events)}"
        )

        # --------------------------------------------------
        # 4. DETECT
        # --------------------------------------------------

        alerts = self.detection_manager.detect(
            events
        )

        print(
            f"[+] Detection alerts: {len(alerts)}"
        )

        # --------------------------------------------------
        # 5. SAVE ALERTS
        # --------------------------------------------------

        for alert in alerts:

            self.incident_store.save_alert(
                alert
            )

        # --------------------------------------------------
        # 6. CORRELATE
        # --------------------------------------------------

        incidents = self.correlation.correlate(
            events,
            alerts
        )

        print(
            f"[+] Correlated incidents: "
            f"{len(incidents)}"
        )

        # --------------------------------------------------
        # 7. RISK + RESPONSE + DATABASE
        # --------------------------------------------------

        final_incidents = []

        for incident in incidents:

            risk = self.risk_engine.calculate_score(
                incident
            )

            final_incident = {
                **incident,
                **risk
            }

            response = (
                self.response_engine.generate_response(
                    final_incident
                )
            )

            final_incident[
                "recommended_actions"
            ] = response.get(
                "recommended_actions",
                []
            )

            incident_id = (
                self.incident_store.save_incident(
                    final_incident
                )
            )

            final_incident[
                "id"
            ] = incident_id

            final_incidents.append(
                final_incident
            )

        print(
            f"[+] Incidents stored in database: "
            f"{len(final_incidents)}"
        )

        # --------------------------------------------------
        # 8. DISPLAY
        # --------------------------------------------------

        print("\n" + "=" * 70)
        print("SECURITY INCIDENTS")
        print("=" * 70)

        if not final_incidents:

            print(
                "\nNo security incidents detected."
            )

        for incident in final_incidents:

            print(
                "\n🚨 INCIDENT DETECTED"
            )

            print(
                f"Incident ID: "
                f"{incident.get('id')}"
            )

            print(
                f"Type: "
                f"{incident.get('incident_type', 'unknown')}"
            )

            print(
                f"Source IP: "
                f"{incident.get('source_ip', 'N/A')}"
            )

            print(
                f"Username: "
                f"{incident.get('username', 'N/A')}"
            )

            print(
                f"Failed Attempts: "
                f"{incident.get('failed_attempts', 0)}"
            )

            print(
                f"Unique Users: "
                f"{incident.get('unique_users', 0)}"
            )

            print(
                f"Unique Ports: "
                f"{incident.get('unique_ports', 0)}"
            )

            print(
                f"Risk Score: "
                f"{incident.get('risk_score', 0)}/100"
            )

            print(
                f"Severity: "
                f"{incident.get('severity', 'low').upper()}"
            )

            print("\nReasons:")

            for reason in incident.get(
                "reasons",
                []
            ):

                print(
                    f"  - {reason}"
                )

            print(
                "\nRecommended Response:"
            )

            for number, action in enumerate(
                incident.get(
                    "recommended_actions",
                    []
                ),
                start=1
            ):

                print(
                    f"  {number}. {action}"
                )

        return final_incidents


if __name__ == "__main__":

    engine = SentinelEngine(
        [
            "data/samples/auth.log",
            "data/samples/port_scan.log"
        ]
    )

    engine.run()