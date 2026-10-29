// Actions that must come from one of the account's approved devices, not just a
// signed-in session. The body carries the payload as an exact JSON string plus a
// proof signed by the device's own (non-exportable) key over that string.
import { ApiError, LIMITS, randomIdField, type Ctx } from "./http.ts";
import { verifyProof } from "./verify.ts";
import { requireActiveDevice } from "./store.ts";

export function payloadOf(body: any): { json: string; data: any } {
  if (typeof body.payload !== "string" || body.payload.length === 0 || body.payload.length > LIMITS.maxBodyBytes) {
    throw new ApiError(400, "BAD_PAYLOAD", "Missing payload.");
  }
  let data: any;
  try {
    data = JSON.parse(body.payload);
  } catch {
    throw new ApiError(400, "BAD_PAYLOAD", "Invalid payload.");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new ApiError(400, "BAD_PAYLOAD", "Invalid payload.");
  return { json: body.payload, data };
}

/** The request is signed by one of this account's active devices. */
export async function signedByActiveDevice(ctx: Ctx, action: string) {
  if (!ctx.body.proof || typeof ctx.body.proof !== "object") {
    throw new ApiError(401, "PROOF_REQUIRED", "This action must come from one of your devices.");
  }
  const { json, data } = payloadOf(ctx.body);
  const deviceId = randomIdField(ctx.body.proof.device_id, "device id");
  const device = await requireActiveDevice(ctx.sr, ctx.user.id, deviceId);
  await verifyProof({ userId: ctx.user.id, action, payloadJson: json, proof: ctx.body.proof, signPub: device.sign_pub, now: ctx.now });
  return { device, data };
}
