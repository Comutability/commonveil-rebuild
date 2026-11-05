// Module resolution for the self-hosted server: the backend's realtime rooms import
// "base44:runtime/actors", which here is server/actorRuntime.mjs.
export async function resolve(specifier, context, next) {
  if (specifier === "base44:runtime/actors") {
    return { url: new URL("./actorRuntime.mjs", import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
