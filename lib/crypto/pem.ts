// PEM framing helpers. Serialisation only: no cryptography happens here.

export type PemLabel = "PUBLIC KEY" | "PRIVATE KEY" | "CERTIFICATE";

/** The DER bytes inside a PEM block (armour lines and whitespace removed). */
export function pemBody(pem: string): Buffer {
  const base64 = pem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("");
  return Buffer.from(base64, "base64");
}

export function toPem(label: PemLabel, der: Uint8Array | ArrayBuffer): string {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  const lines = Buffer.from(bytes).toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
