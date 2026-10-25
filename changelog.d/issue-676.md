### Added
- Webhook deliveries now send `X-Harpocrates-Delivery`, `X-Harpocrates-Attempt`, and (when the payload has an event type) `X-Harpocrates-Event` headers so receivers can deduplicate and route calls (#676).
