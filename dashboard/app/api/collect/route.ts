// dashboard/app/api/collect/route.ts
// Kept for existing API clients. Same behaviour as /api/trigger-collection:
// queue a collection job; never fabricate a snapshot for a real device.
export { POST } from '../trigger-collection/route';
