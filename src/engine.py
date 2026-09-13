from src.collector.multi_source_collector import MultiSourceCollector
from src.parser.parser_router import ParserRouter
from src.detectors.detection_manager import DetectionManager
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine
from src.response.response_engine import ResponseEngine
from src.database.database import Database
from src.database.incident_store import IncidentStore
from src.intelligence.incident_intelligence import IncidentIntelligence


class SentinelEngine:

    def __init__(self, input_files):

        self.input_files = input_files

        self.collector = MultiSourceCollector(
            input_files
        )

        self.parser_router = ParserRouter()

        self.detection_manager = DetectionManager()

        self.correlation_engine = CorrelationEngine()

        self.risk_engine = RiskEngine()

        self.response_engine = ResponseEngine()

        self.database = Database()

        self.store = IncidentStore(
            self.database
        )

        self.intelligence = IncidentIntelligence()

    # =========================================================
    # RUN SOC PIPELINE
    # =========================================================

    def run(self):

        print("=" * 65)
        print("SENTINELSOC UNIFIED SECURITY OPERATIONS ENGINE")
        print("=" * 65)

        # =====================================================
        # 1. COLLECT LOGS
        # =====================================================

        logs = self.collector.collect()

        print(
            f"\n[+] Collected logs: {len(logs)}"
        )

        # =====================================================
        # 2. PARSE LOGS
        # =====================================================

        events = []

        for log in logs:

            try:

                event = self.parser_router.parse(
                    log
                )

                if event is not None:

                    events.append(event)

            except Exception as error:

                print(
                    f"[!] Parser error: {error}"
                )

        print(
            f"[+] Parsed security events: "
            f"{len(events)}"
        )

        # =====================================================
        # 3. STORE EVENTS
        # =====================================================

        stored_events = 0

        for event in events:

            try:

                if hasattr(
                    event,
                    "to_dict"
                ):

                    event_data = event.to_dict()

                elif isinstance(
                    event,
                    dict
                ):

                    event_data = event

                else:

                    event_data = vars(event)

                self.store.save_event(
                    event_data
                )

                stored_events += 1

            except Exception as error:

                print(
                    f"[!] Event storage error: {error}"
                )

        print(
            f"[+] Events processed for database: "
            f"{stored_events}"
        )

        # =====================================================
        # 4. DETECTION
        # =====================================================

        alerts = []

        try:

            # IMPORTANT:
            # DetectionManager expects SecurityEvent
            # objects, NOT dictionaries.

            alerts = self.detection_manager.detect(
                events
            )

        except Exception as error:

            print(
                f"[!] Detection error: {error}"
            )

        print(
            f"[+] Detection alerts: "
            f"{len(alerts)}"
        )

        # =====================================================
        # 5. STORE ALERTS
        # =====================================================

        stored_alerts = 0

        for alert in alerts:

            try:

                if hasattr(
                    alert,
                    "to_dict"
                ):

                    alert_data = alert.to_dict()

                elif isinstance(
                    alert,
                    dict
                ):

                    alert_data = alert

                else:

                    alert_data = vars(alert)

                self.store.save_alert(
                    alert_data
                )

                stored_alerts += 1

            except Exception as error:

                print(
                    f"[!] Alert storage error: {error}"
                )

        print(
            f"[+] Alerts processed for database: "
            f"{stored_alerts}"
        )

        # =====================================================
        # 6. CORRELATION
        # =====================================================

        incidents = []

        try:

            incidents = (
                self.correlation_engine.correlate(
                    alerts,
                    events
                )
            )

        except Exception as error:

            print(
                f"[!] Correlation error: {error}"
            )

        print(
            f"[+] Correlated incidents: "
            f"{len(incidents)}"
        )

        # =====================================================
        # 7. ENRICH INCIDENTS
        # =====================================================

        final_incidents = []

        for incident in incidents:

            # -------------------------------------------------
            # Risk scoring
            # -------------------------------------------------

            try:

                risk = (
                    self.risk_engine.calculate_score(
                        incident
                    )
                )

                incident.update(
                    risk
                )

            except Exception as error:

                print(
                    f"[!] Risk engine error: {error}"
                )

            # -------------------------------------------------
            # Threat intelligence / MITRE enrichment
            # -------------------------------------------------

            try:

                intelligence = (
                    self.intelligence.enrich(
                        incident
                    )
                )

                if intelligence:

                    incident[
                        "intelligence"
                    ] = intelligence

            except Exception as error:

                print(
                    f"[!] Intelligence enrichment error: "
                    f"{error}"
                )

            # -------------------------------------------------
            # Response recommendation
            # -------------------------------------------------

            try:

                response = (
                    self.response_engine.generate_response(
                        incident
                    )
                )

                incident[
                    "response"
                ] = response

            except Exception as error:

                print(
                    f"[!] Response engine error: "
                    f"{error}"
                )

            final_incidents.append(
                incident
            )

        # =====================================================
        # 8. STORE INCIDENTS
        # =====================================================

        stored_incidents = 0

        for incident in final_incidents:

            try:

                incident_id = (
                    self.store.save_incident(
                        incident
                    )
                )

                incident[
                    "id"
                ] = incident_id

                stored_incidents += 1

            except Exception as error:

                print(
                    f"[!] Incident storage error: "
                    f"{error}"
                )

        print(
            f"[+] Incidents processed for database: "
            f"{stored_incidents}"
        )

        # =====================================================
        # 9. DISPLAY INCIDENTS
        # =====================================================

        print(
            "\n" + "=" * 65
        )

        print(
            "SECURITY INCIDENTS"
        )

        print(
            "=" * 65
        )

        for incident in final_incidents:

            print(
                "\n🚨 INCIDENT DETECTED"
            )

            print(
                f"Incident ID: "
                f"{incident.get('id', 'N/A')}"
            )

            print(
                f"Type: "
                f"{incident.get('incident_type')}"
            )

            print(
                f"Source IP: "
                f"{incident.get('source_ip')}"
            )

            print(
                f"Username: "
                f"{incident.get('username')}"
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
                f"{str(incident.get('severity', 'low')).upper()}"
            )

            print(
                f"Confidence: "
                f"{incident.get('confidence', 0)}%"
            )

            print(
                f"Attack Types: "
                f"{incident.get('attack_types', [])}"
            )

            print(
                "\nDescription:"
            )

            print(
                f"  {incident.get('description', '')}"
            )

            print(
                "\nReasons:"
            )

            for reason in incident.get(
                "reasons",
                []
            ):

                print(
                    f"  - {reason}"
                )

            print(
                "\nEvidence:"
            )

            for item in incident.get(
                "evidence",
                []
            ):

                print(
                    f"  - {item}"
                )

            print(
                "\nRecommended Response:"
            )

            print(
                incident.get(
                    "response",
                    {}
                )
            )

        print(
            "\n" + "=" * 65
        )

        return final_incidents


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    engine = SentinelEngine(
        [
            "data/samples/auth.log",
            "data/samples/port_scan.log"
        ]
    )

    engine.run()