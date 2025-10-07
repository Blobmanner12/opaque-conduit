// Adhering to the "Rule of the Monolith": The Stage 2 loader is embedded directly.
const stage2LoaderScript = `
--[[
  Opaque-Conduit: Stage 2 Loader
  This script is downloaded and executed in memory by the Stage 1 public loader.
  Its responsibility is to perform the secure handshake and payload execution.
]]

print("[Stage 2] Opaque-Conduit client initializing...")
print("[Stage 2] Secure handshake protocol will be executed here.")

local SERVER_PUBLIC_KEY_FINGERPRINT = "PASTE_YOUR_SHA256_FINGERPRINT_HERE"

print("[Stage 2] Expected server fingerprint: " .. SERVER_PUBLIC_KEY_FINGERPRINT)
`;

export default function handler(req, res) {
  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(stage2LoaderScript);
}