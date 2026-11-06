import React from "react";
import IdentityRegister from "@/pages/identity/IdentityRegister";

/** New accounts are a username and a password, on Base44 and self-hosted sites alike. No email. */
export default function Register() {
  return <IdentityRegister />;
}
