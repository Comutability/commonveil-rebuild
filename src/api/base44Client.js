import { createClient } from '@base44/sdk';
import { appParams } from '@/lib/app-params';
import { createSelfHostClient } from './selfhostClient';

const { appId, token, functionsVersion, appBaseUrl } = appParams;

/** True on a self-hosted site (built with VITE_COMMONVEIL_BACKEND=selfhost). */
export const SELF_HOSTED = import.meta.env.VITE_COMMONVEIL_BACKEND === 'selfhost';

export const base44 = SELF_HOSTED
  ? createSelfHostClient()
  : createClient({
      appId,
      token,
      functionsVersion,
      serverUrl: '',
      appBaseUrl,
      // No usage analytics on a privacy site.
      analytics: { enabled: false },
    });
