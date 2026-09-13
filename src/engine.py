from src.collector.multi_source_collector import MultiSourceCollector
from src.parser.parser_router import ParserRouter
from src.detectors.detection_manager import DetectionManager
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine
from src.response.response_engine import ResponseEngine
from src.database.incident_store import IncidentStore
from src.intelligence.incident_intelligence import IncidentIntelligence


class SentinelEngine:

    def __init__(
        self,
        input_files,
        correlation_window_seconds=300
    ):

        self.input_files = input_files

        # ---------------------------------------------------------
        # Core pipeline components
        # ---------------------------------------------------------

        self.collector = MultiSourceCollector(
            input_files
        )

        self.parser = ParserRouter()

        self.detector = DetectionManager()

        self.correlation = CorrelationEngine(
            correlation_window_seconds
        )

        self.risk_engine = RiskEngine()

        self.response_engine = ResponseEngine()

        self.store = IncidentStore()

        # ---------------------------------------------------------
        # Security intelligence layer
        # MITRE + confidence + evidence
        # ---------------------------------------------------------

        self.intelligence = IncidentIntelligence()

    def run(self):

        print(
            "=" * 70
        )

        print(
            "SENTINELSOC UNIFIED SECURITY OPERATIONS ENGINE"
        )

        print(
            "=" * 70
        )

        # =========================================================
        # 1. COLLECT LOGS
        # =========================================================

        logs = self.collector.collect()

        print(
            f"\n[+] Collected logs: {len(logs)}"
        )

        # =========================================================
        # 2. PARSE LOGS
        # =========================================================

        events = []

        for log in logs:

            try:

                event = self.parser.parse(
                    log
                )

                if event is not None:

                    events.append(
                        event
                    )

            except Exception as error:

                print(
                    f"[!] Parser error: {error}"
                )

        print(
            f"[+] Parsed security events: "
            f"{len(events)}"
        )

        # =========================================================
        # 3. STORE EVENTS
        # =========================================================

        stored_events = 0

        for event in events:

            try:

                self.store.save_event(
                    event
                )

                stored_events += 1

            except Exception as error:

                print(
                    f"[!] Event storage error: "
                    f"{error}"
                )

        print(
            f"[+] Events stored in database: "
            f"{stored_events}"
        )

        # =========================================================
        # 4. DETECTION
        # =========================================================

        alerts = []

        try:

            alerts = self.detector.detect(
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

        # =========================================================
        # 5. STORE ALERTS
        # =========================================================

        stored_alerts = 0

        for alert in alerts:

            try:

                self.store.save_alert(
                    alert
                )

                stored_alerts += 1

            except Exception as error:

                print(
                    f"[!] Alert storage error: "
                    f"{error}"
                )

        # =========================================================
        # 6. CORRELATION
        # =========================================================

        incidents = []

        try:

            incidents = self.correlation.correlate(
                alerts,
                events
            )

        except Exception as error:

            print(
                f"[!] Correlation error: "
                f"{error}"
            )

        print(
            f"[+] Correlated incidents: "
            f"{len(incidents)}"
        )

        # =========================================================
        # 7. INCIDENT INTELLIGENCE
        #
        # Adds:
        # - MITRE ATT&CK
        # - confidence
        # - evidence
        # - richer descriptions
        # =========================================================

        enriched_incidents = []

        for incident in incidents:

            try:

                incident = self.intelligence.enrich(
                    incident
                )

                enriched_incidents.append(
                    incident
                )

            except Exception as error:

                print(
                    f"[!] Intelligence error: "
                    f"{error}"
                )

                enriched_incidents.append(
                    incident
                )

        incidents = enriched_incidents

        # =========================================================
        # 8. RISK SCORING
        # =========================================================

        final_incidents = []

        for incident in incidents:

            try:

                risk = self.risk_engine.calculate_score(
                    incident
                )

                incident.update(
                    risk
                )

            except Exception as error:

                print(
                    f"[!] Risk scoring error: "
                    f"{error}"
                )

                incident.setdefault(
                    "risk_score",
                    0
                )

                incident.setdefault(
                    "severity",
                    "low"
                )

                incident.setdefault(
                    "reasons",
                    []
                )

            # -----------------------------------------------------
            # Preserve intelligence information
            # -----------------------------------------------------

            incident.setdefault(
                "confidence",
                50
            )

            incident.setdefault(
                "evidence",
                []
            )

            incident.setdefault(
                "mitre",
                {}
            )

            # -----------------------------------------------------
            # Default incident status
            # -----------------------------------------------------

            incident.setdefault(
                "status",
                "open"
            )

            final_incidents.append(
                incident
            )

        # =========================================================
        # 9. RESPONSE RECOMMENDATIONS
        # =========================================================

        for incident in final_incidents:

            try:

                response = (
                    self.response_engine
                    .generate_response(
                        incident
                    )
                )

                incident[
                    "recommended_response"
                ] = response

            except AttributeError:

                # Compatibility with an older
                # ResponseEngine implementation.
                incident[
                    "recommended_response"
                ] = []

            except Exception as error:

                print(
                    f"[!] Response engine error: "
                    f"{error}"
                )

                incident[
                    "recommended_response"
                ] = []

        # =========================================================
        # 10. STORE INCIDENTS
        # =========================================================

        stored_incidents = 0

        for incident in final_incidents:

            try:

                incident_id = (
                    self.store.save_incident(
                        incident
                    )
                )

                incident[
                    "incident_id"
                ] = incident_id

                stored_incidents += 1

            except Exception as error:

                print(
                    f"[!] Incident storage error: "
                    f"{error}"
                )

        print(
            f"[+] Incidents stored in database: "
            f"{stored_incidents}"
        )

        # =========================================================
        # 11. DISPLAY INCIDENTS
        # =========================================================

        print(
            "\n"
            + "=" * 70
        )

        print(
            "SECURITY INCIDENTS"
        )

        print(
            "-" * 70
        )

        for incident in final_incidents:

            print(
                "\n🚨 INCIDENT DETECTED"
            )

            print(
                f"Incident ID: "
                f"{incident.get('incident_id', 'N/A')}"
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
                f"{str(incident.get('severity', 'low')).upper()}"
            )

            print(
                f"Confidence: "
                f"{incident.get('confidence', 0)}%"
            )

            # -----------------------------------------------------
            # MITRE ATT&CK
            # -----------------------------------------------------

            mitre = incident.get(
                "mitre",
                {}
            )

            if mitre:

                print(
                    "\nMITRE ATT&CK:"
                )

                print(
                    f"  Technique ID: "
                    f"{mitre.get('technique_id', 'N/A')}"
                )

                print(
                    f"  Technique: "
                    f"{mitre.get('technique_name', 'N/A')}"
                )

                print(
                    f"  Tactic: "
                    f"{mitre.get('tactic', 'N/A')}"
                )

            # -----------------------------------------------------
            # Description
            # -----------------------------------------------------

            description = incident.get(
                "description"
            )

            if description:

                print(
                    "\nDescription:"
                )

                print(
                    f"  {description}"
                )

            # -----------------------------------------------------
            # Reasons
            # -----------------------------------------------------

            reasons = incident.get(
                "reasons",
                []
            )

            if reasons:

                print(
                    "\nReasons:"
                )

                for reason in reasons:

                    print(
                        f"  - {reason}"
                    )

            # -----------------------------------------------------
            # Evidence
            # -----------------------------------------------------

            evidence = incident.get(
                "evidence",
                []
            )

            if evidence:

                print(
                    "\nEvidence:"
                )

                for item in evidence:

                    print(
                        f"  - {item}"
                    )

            # -----------------------------------------------------
            # Recommended response
            # -----------------------------------------------------

            response = incident.get(
                "recommended_response",
                []
            )

            if response:

                print(
                    "\nRecommended Response:"
                )

                if isinstance(
                    response,
                    list
                ):

                    for index, action in enumerate(
                        response,
                        start=1
                    ):

                        print(
                            f"  {index}. {action}"
                        )

                else:

                    print(
                        f"  {response}"
                    )

        print(
            "\n"
            + "=" * 70
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