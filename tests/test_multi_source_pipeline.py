import unittest

from src.collector.multi_source_collector import (
    MultiSourceCollector
)

from src.parser.parser_router import ParserRouter


class TestMultiSourcePipeline(unittest.TestCase):

    def test_collect_multiple_sources(self):

        collector = MultiSourceCollector([
            "data/samples/auth.log",
            "data/samples/port_scan.log"
        ])

        logs = collector.collect()

        self.assertEqual(
            len(logs),
            14
        )

    def test_parse_multiple_sources(self):

        collector = MultiSourceCollector([
            "data/samples/auth.log",
            "data/samples/port_scan.log"
        ])

        router = ParserRouter()

        logs = collector.collect()

        events = []

        for log in logs:

            event = router.parse(log)

            if event:
                events.append(event)

        self.assertEqual(
            len(events),
            14
        )

        authentication_events = [
            event
            for event in events
            if event.event_type.startswith(
                "authentication"
            )
        ]

        network_events = [
            event
            for event in events
            if event.event_type == "connection_attempt"
        ]

        self.assertEqual(
            len(authentication_events),
            6
        )

        self.assertEqual(
            len(network_events),
            8
        )


if __name__ == "__main__":
    unittest.main()