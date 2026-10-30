import { QueryClient } from '@tanstack/react-query';

// Base44 caps how many queries an app makes each minute, shared by every visitor, so pages
// reuse what they fetched for a few minutes instead of asking again on every visit.
// Staff screens that need fresh data refetch after each change.
export const queryClientInstance = new QueryClient({
	defaultOptions: {
		queries: {
			refetchOnWindowFocus: false,
			staleTime: 5 * 60_000,
			retry: 1,
		},
	},
});
