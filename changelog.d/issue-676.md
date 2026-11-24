### Added
- Webhook deliveries now send `X-Harpocrates-Delivery`, `X-Harpocrates-Attempt`, and (when the payload has an event type) `X-Harpocrates-Event` headers so receivers can deduplicate and route calls (#676).
- Two-phase deletion receipts for retained evidence: approved selections and completed storage actions are recorded with an audit reference that excludes private media and plaintext keys.
