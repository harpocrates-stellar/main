### Fixed
- Analytics export now returns a distinct `analytics_store_unavailable` status (HTTP 503 from the export endpoint) when the analytics store is missing or fails while serializing, instead of reporting a successful zero-record export after a backend outage.
