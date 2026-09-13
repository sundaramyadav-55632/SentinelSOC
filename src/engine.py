from src.collector.multi_source_collector import MultiSourceCollector
from src.parser.parser_router import ParserRouter
from src.detectors.detection_manager import DetectionManager
from src.correlation.correlation_engine import CorrelationEngine
from src.risk.risk_engine import RiskEngine
from src.response.response_engine import ResponseEngine
from src.intelligence.intelligence_engine import IntelligenceEngine
from src.database.incident_store import IncidentStore


class SentinelEngine:

    def __init__(self, input_files):
        self.collector = MultiSourceCollector(input_files)
        self.parser_router = ParserRouter()

        self.detection_manager = DetectionManager()
        self.correlation_engine = CorrelationEngine()
        self.risk_engine = RiskEngine()
        self.response_engine = ResponseEngine()
        self.intelligence = IntelligenceEngine()
        self.store = IncidentStore()

    def run(self):

        print("\n========== SENTINELSOC ENGINE ==========\n")

        raw_logs = self.collector.collect()

        events = []

        # Parse logs
        for log in raw_logs:

            try:
                event = self.parser_router.parse(log)

                if event:
                    events.append(event)

            except Exception as e:
                print("Parser error:", e)

        print(f"Parsed events: {len(events)}")

        # Save events
        for event in events:
            try:
                self.store.save_event(event)
            except Exception as e:
                print("Event storage error:", e)

        # Detection
        try:
            alerts = self.detection_manager.detect(events)
        except Exception as e:
            print("Detection error:", e)
            alerts = []

        print(f"Alerts generated: {len(alerts)}")

        # Save alerts
        for alert in alerts:
            try:
                self.store.save_alert(alert)
            except Exception as e:
                print("Alert storage error:", e)

        # Correlation
        try:
            incidents = self.correlation_engine.correlate(
                alerts,
                events
            )
        except Exception as e:
            print("Correlation error:", e)
            incidents = []

        print(f"Incidents correlated: {len(incidents)}")

        final_incidents = []

        # Risk + intelligence + response
        for incident in incidents:

            try:
                risk = self.risk_engine.calculate_score(incident)

                incident.update(risk)

                intelligence = self.intelligence.enrich(incident)

                incident.update(intelligence)

                response = self.response_engine.generate_response(
                    incident
                )

                incident["response_actions"] = response

                self.store.save_incident(incident)

                final_incidents.append(incident)

            except Exception as e:
                print("Incident processing error:", e)

        print("\n========== INCIDENTS ==========\n")

        for incident in final_incidents:

            print(
                f"[{incident.get('severity', 'unknown').upper()}] "
                f"{incident.get('incident_type')} | "
                f"{incident.get('source_ip')} | "
                f"Risk: {incident.get('risk_score')}"
            )

            print(
                "Attack types:",
                incident.get("attack_types")
            )

            print(
                "MITRE:",
                incident.get("mitre_technique_id"),
                incident.get("mitre_technique")
            )

            print(
                "Response:",
                incident.get("response_actions")
            )

            print()

        print("========== COMPLETE ==========\n")


if __name__ == "__main__":

    engine = SentinelEngine([
        "data/samples/attack_chain.log"
    ])

    engine.run()