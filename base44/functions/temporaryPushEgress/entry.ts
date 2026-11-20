// TEMPORARY: isolated network-only production diagnostic; remove after testing.
export default async function (req: Request): Promise<Response> {
  if (req.method !== "POST" || req.headers.get("X-Commonveil-Diagnostic") !== "OH19DR9LjIv3lsmwPbYQto0vP8UQ2AWUgPW30__XoM8") return new Response("Not found", {status:404});
  const checks = [
    {name:"fcm-head-default", url:"https://fcm.googleapis.com/", method:"HEAD", timeout:false},
    {name:"fcm-head-timeout", url:"https://fcm.googleapis.com/", method:"HEAD", timeout:true},
    {name:"fcm-get", url:"https://fcm.googleapis.com/", method:"GET", timeout:false},
    {name:"google", url:"https://www.google.com/generate_204", method:"GET", timeout:false},
    {name:"example", url:"https://example.com/", method:"GET", timeout:false},
  ];
  const results = await Promise.all(checks.map(async (check) => {
    try {
      const init: RequestInit = {method:check.method, redirect:"error"};
      if (check.timeout) init.signal=AbortSignal.timeout(4000);
      const res=await fetch(check.url, init);
      return {name:check.name, ok:true, status:res.status};
    } catch(err) {
      const e=err && typeof err==="object" ? err as {name?:unknown,cause?:{name?:unknown,code?:unknown},message?:unknown} : {};
      const known=["TypeError","Error","TimeoutError","AbortError","NotCapable","PermissionDenied","SecurityError","NetworkError"];
      const code=typeof e.cause?.code==="string" && /^[A-Z_0-9]{1,25}$/.test(e.cause.code) ? e.cause.code : "unknown";
      const name=typeof e.name==="string" && known.includes(e.name) ? e.name : "other";
      const msg=typeof e.message==="string" ? e.message.toLowerCase() : "";
      const category=/fetch failed|fetcherror/.test(msg)?"fetch_failed":/not implemented|unsupported/.test(msg)?"unsupported":/permission|denied|notcapable/.test(msg)?"permission":/refused|connect/.test(msg)?"connection":/invalid|header/.test(msg)?"request":/timeout|timed out/.test(msg)?"timeout":"unknown";
      return {name:check.name,ok:false,errorName:name,causeCode:code,category};
    }
  }));
  return new Response(JSON.stringify({checks:results}),{status:200,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
}
