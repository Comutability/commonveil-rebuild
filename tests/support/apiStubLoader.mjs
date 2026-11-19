// Module resolution for tests of app code that calls the server: "@/lib/api" is the stand-in in
// apiStub.mjs. Register it with node:module's register() before importing that code.
export async function resolve(specifier, context, next) {
  if (specifier === "@/lib/api") return { url: new URL("./apiStub.mjs", import.meta.url).href, shortCircuit: true };
  return next(specifier, context);
}
