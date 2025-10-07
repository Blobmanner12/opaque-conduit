--[[
  Opaque-Conduit: Stage 1 Loader (Public)
  Version: 1.0.0
  
  This is the public, distributable "empty shell" loader.
  Its ONLY function is to download the real client (Stage 2) from the bootstrap server
  and execute it in memory. It contains no sensitive information.
--]]

-- Configuration: The URL to the Cloudflare proxy worker which fronts our API.
local BOOTSTRAP_URL = "https://opaque-conduit-proxy.gooeyhub.workers.dev/api/bootstrap"

-- Adaptive Networking Engine:
-- Roblox executors provide different functions for HTTP requests. This function
-- sequentially tries the most common ones until one succeeds.
local function fetch_stage2()
    local success, response
    
    -- Attempt with 'request' (Synapse X, etc.)
    if typeof and typeof(request) == "function" then
        success, response = pcall(function() return request({Url = BOOTSTRAP_URL, Method = "GET"}).Body end)
        if success and response then return response end
    end
    
    -- Attempt with 'HttpGet' / 'HttpGetAsync' (Standard)
    if typeof and typeof(HttpGet) == "function" then
        success, response = pcall(HttpGet, BOOTSTRAP_URL)
        if success and response then return response end
    end
    
    -- Fallback for older or uncommon environments
    if typeof and typeof(http_request) == "function" then
        success, response = pcall(function() return http_request({Url = BOOTSTRAP_URL, Method = "GET"}) end)
        if success and response then return response end
    end
    
    return nil, "Error: No supported HTTP function found."
end

-- Adaptive Execution Engine:
-- The 'loadstring' global is often renamed or missing. This function tries all
-- known variants to execute the downloaded Stage 2 code.
local function execute_stage2(code)
    local func, err
    
    local load_variants = {loadstring, load}
    for _, loader in ipairs(load_variants) do
        if typeof and typeof(loader) == "function" then
            success, func = pcall(loader, code)
            if success and func then
                return pcall(func)
            else
                err = func -- pcall returns error message in 'func' on failure
            end
        end
    end

    return false, "Error: No supported code execution function (loadstring/load) found. " .. (err or "")
end

-- Main Execution Flow
print("[Stage 1] Initializing Opaque-Conduit loader...")
local s2_code, err_msg = fetch_stage2()

if s2_code then
    print("[Stage 1] Stage 2 loader downloaded (" .. #s2_code .. " bytes). Executing in memory...")
    execute_stage2(s2_code)
else
    warn("[Stage 1] FAILED to download Stage 2 loader: " .. err_msg)
end