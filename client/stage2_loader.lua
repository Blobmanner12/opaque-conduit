--[[
  Opaque-Conduit: Stage 2 Loader (In-Memory)
  
  This is the core client logic. It is downloaded at runtime and is responsible for:
  1. Verifying the authenticity of the server via a public key fingerprint.
  2. Negotiating a secure, one-time-use symmetric key.
  3. Fetching, decrypting, and executing the final payload.
--]]

print("[Stage 2] Core client initialized in memory.")

---------------------------------------------------------------------
-- CONFIGURATION & SECURITY CONSTANTS
---------------------------------------------------------------------

-- API Endpoints (relative to the base URL)
local API_BASE_URL = "https://opaque-conduit-proxy.gooeyhub.workers.dev"
local HANDSHAKE_ENDPOINT = API_BASE_URL .. "/api/handshake"
local EXCHANGE_ENDPOINT = API_BASE_URL .. "/api/exchange"
local PAYLOAD_ENDPOINT = API_BASE_URL .. "/api/get-payload"

-- CRITICAL: This fingerprint is the core defense against Man-in-the-Middle (MITM) attacks.
-- This is keyed to your unique server private key.
local HARDCODED_SERVER_FINGERPRINT = "aef1d727233f917a5aceb8237592ceb43dd3158a2952eb919f3621b5512ce7b6" 

-- This will be replaced by game-specific logic.
local CURRENT_SCRIPT_ID = "game_a_script" 

---------------------------------------------------------------------
-- ENVIRONMENT ABSTRACTION LAYER (Dependencies on the Executor)
---------------------------------------------------------------------
-- This section clearly defines the functions we expect the executor
-- environment to provide.

local Hashing = {
    -- Returns the hex-encoded SHA256 hash of a string.
    sha256 = function(str)
        -- In a real environment, this will be a function like 'crypto.sha256'
        assert(crypto and crypto.sha256, "FATAL: crypto.sha256 function not found in environment.")
        return crypto.sha256(str)
    end
}

local AsymmetricEncryption = {
    -- Encrypts a plaintext string using a Base64-encoded RSA public key.
    -- Returns the result as a Base64-encoded string.
    encrypt = function(plaintext, publicKeyB64)
        -- In a real environment, this will be a function like 'crypto.rsa_encrypt'
        assert(crypto and crypto.rsa_encrypt, "FATAL: crypto.rsa_encrypt function not found in environment.")
        return crypto.rsa_encrypt(plaintext, publicKeyB64)
    end
}

local SymmetricEncryption = {
    -- Decrypts a Base64-encoded ciphertext using a key.
    decrypt = function(ciphertextB64, key)
        -- In a real environment, this will be 'crypto.aes_decrypt' or similar
        assert(crypto and crypto.aes_decrypt, "FATAL: crypto.aes_decrypt function not found in environment.")
        return crypto.aes_decrypt(ciphertextB64, key)
    end
}

local Networking = {
    -- Performs a JSON-based POST request.
    post = function(url, body_table)
        assert(request, "FATAL: 'request' function not found in environment.")
        local response = request({Url = url, Method = "POST", Body = game:GetService("HttpService"):JSONEncode(body_table)})
        return game:GetService("HttpService"):JSONDecode(response.Body)
    end,
    -- Performs a GET request and decodes the JSON response.
    get = function(url)
        assert(request, "FATAL: 'request' function not found in environment.")
        local response = request({Url = url, Method = "GET"})
        return game:GetService("HttpService"):JSONDecode(response.Body)
    end
}

local Execution = {
    -- Adaptive execution engine from Stage 1.
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

-- 1. Perform the handshake to get the server's public key.
local function do_handshake()
    print("[Stage 2] Performing secure handshake...")
    local data = Networking.get(HANDSHAKE_ENDPOINT)
    assert(data and data.publicKey and data.fingerprint, "Handshake failed: Invalid server response.")

    print("[Stage 2] Server fingerprint: " .. data.fingerprint)
    print("[Stage 2] Hardcoded fingerprint: " .. HARDCODED_SERVER_FINGERPRINT)

    -- MITM CHECK: Verify the received public key's fingerprint against our hardcoded one.
    -- The public key is received in Base64, but we must hash its raw bytes.
    local received_key_bytes = game:GetService("HttpService"):Base64Decode(data.publicKey)
    local calculated_fingerprint = Hashing.sha256(received_key_bytes)
    
    assert(calculated_fingerprint == HARDCODED_SERVER_FINGERPRINT, "FATAL: SECURITY ALERT! Server fingerprint mismatch. Possible MITM attack. Terminating.")
    
    print("[Stage 2] Handshake successful. Server authenticity verified.")
    return data.publicKey
end

-- 2. Generate a symmetric key and exchange it for a session token.
local function do_exchange(server_public_key)
    print("[Stage 2] Generating and exchanging session key...")
    -- Generate a 32-byte random key for AES-256.
    local symmetric_key = ""
    for i = 1, 32 do
        symmetric_key = symmetric_key .. string.char(math.random(32, 126))
    end

    -- Encrypt our new symmetric key with the server's public key.
    local encrypted_key_b64 = AsymmetricEncryption.encrypt(symmetric_key, server_public_key)
    
    -- Send the encrypted key to the server.
    local response = Networking.post(EXCHANGE_ENDPOINT, {encryptedKey = encrypted_key_b64})
    assert(response and response.sessionToken, "Key exchange failed: Did not receive session token.")

    print("[Stage 2] Key exchange successful.")
    return symmetric_key, response.sessionToken
end

-- 3. Fetch the final payload using the session token.
local function get_payload(session_token, symmetric_key)
    print("[Stage 2] Fetching secure payload...")
    local response = Networking.post(PAYLOAD_ENDPOINT, {sessionToken = session_token, scriptId = CURRENT_SCRIPT_ID})
    assert(response and response.encryptedPayload, "Payload request failed: Invalid server response.")

    -- Decrypt the payload using the key we negotiated.
    -- The server sends it Base64 encoded.
    print("[Stage 2] Decrypting payload...")
    local decrypted_payload = SymmetricEncryption.decrypt(response.encryptedPayload, symmetric_key)
    assert(decrypted_payload, "Payload decryption failed. Key mismatch or corrupted data.")
    
    print("[Stage 2] Payload decrypted successfully (" .. #decrypted_payload .. " bytes).")
    return decrypted_payload
end

-- Main execution flow for Stage 2
pcall(function()
    local server_public_key = do_handshake()
    local symmetric_key, session_token = do_exchange(server_public_key)
    local payload = get_payload(session_token, symmetric_key)
    
    print("[Stage 2] Handing off to final payload...")
    Execution.run(payload)
end)