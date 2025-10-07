--[[
  Opaque-Conduit: Stage 2 Loader (In-Memory)
]]

print("[Stage 2] Core client initialized in memory.")

---------------------------------------------------------------------
-- CONFIGURATION & SECURITY CONSTANTS
---------------------------------------------------------------------

local API_BASE_URL = "https://opaque-conduit-proxy.gooeyhub.workers.dev"
local HANDSHAKE_ENDPOINT = API_BASE_URL .. "/api/handshake"
local EXCHANGE_ENDPOINT = API_BASE_URL .. "/api/exchange"
local PAYLOAD_ENDPOINT = API_BASE_URL .. "/api/get-payload"

local HARDCODED_SERVER_FINGERPRINT = "aef1d727233f917a5aceb8237592ceb43dd3158a2952eb919f3621b5512ce7b6" 

local CURRENT_SCRIPT_ID = "game_a_script" 

---------------------------------------------------------------------
-- ENVIRONMENT ABSTRACTION LAYER (Dependencies on the Executor)
---------------------------------------------------------------------

local Hashing = {
    sha256 = function(str)
        assert(crypto and crypto.sha256, "FATAL: crypto.sha256 function not found in environment.")
        return crypto.sha256(str)
    end
}

local AsymmetricEncryption = {
    encrypt = function(plaintext, publicKeyB64)
        assert(crypto and crypto.rsa_encrypt, "FATAL: crypto.rsa_encrypt function not found in environment.")
        return crypto.rsa_encrypt(plaintext, publicKeyB64)
    end
}

local SymmetricEncryption = {
    decrypt = function(ciphertextB64, key)
        assert(crypto and crypto.aes_decrypt, "FATAL: crypto.aes_decrypt function not found in environment.")
        return crypto.aes_decrypt(ciphertextB64, key)
    end
}

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
    local received_key_bytes = game:GetService("HttpService"):Base64Decode(data.publicKey)
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

pcall(function()
    local server_public_key = do_handshake()
    local symmetric_key, session_token = do_exchange(server_public_key)
    local payload = get_payload(session_token, symmetric_key)
    print("[Stage 2] Handing off to final payload...")
    Execution.run(payload)
end)