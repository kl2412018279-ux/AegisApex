// dashboard/_hooks/useMe.ts
import { useCallback, useEffect, useState } from 'react';
import { api } from '../_utils/api';
import type { Me, Role } from '../_types/dashboard.types';

const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

export function useMe() {
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Me>('/api/me').then(setMe).catch((e) => setError(e.message));
  }, []);

  const hasRole = useCallback(
    (min: Role, orgId?: string | null) => !!me?.memberships.some((m) => (!orgId || m.orgId === orgId) && RANK[m.role] >= RANK[min]),
    [me]
  );

  return { me, error, hasRole };
}
