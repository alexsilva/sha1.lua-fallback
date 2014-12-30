sha1 = {
    _VERSION = "sha.lua 3.2.+",
    _URL = "https://github.com/kikito/sha.lua",
    _DESCRIPTION = [[
   SHA-1 secure hash computation, and HMAC-SHA1 signature computation in Lua (5.1)
   Based on code originally by Jeffrey Friedl (http://regex.info/blog/lua/sha1)
   And modified by Eike Decker - (http://cube3d.de/uploads/Main/sha1.txt)
  ]],
    _LICENSE = [[
    MIT LICENSE

    Copyright (c) 2013 Enrique García Cota + Eike Decker + Jeffrey Friedl

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
  ]]
}

-----------------------------------------------------------------------------------

-- loading this file (takes a while but grants a boost of factor 13)
local PRELOAD_CACHE = true

local BLOCK_SIZE = 64 -- 512 bits

-- local storing of global functions (minor speedup)
local rep = function(s, n)
    local old_s = s
    local i  = 1
    while i < n do
        s = s .. old_s
        i = i + 1
    end
    return s
end

-- A função math.mod foi renomeada para math.fmod
local modf = function(a)
    local r = mod(a, 1.0)
    return (a - r), r
end

-- merge 4 bytes to an 32 bit word
local bytes_to_w32 = function(a, b, c, d)
    return (a * 16777216) + (b * 65536) + (c * 256) + d
end

-- split a 32 bit word into four 8 bit numbers
local w32_to_bytes = function(i)
    return mod(floor(i / 16777216), 256), mod(floor(i / 65536), 256), mod(floor(i / 256), 256), mod(i, 256)
end

-- shift the bits of a 32 bit word. Don't use negative values for "bits"
local w32_rot = function(bits, a)
    local b2 = 2 ^ (32 - bits)
    local a, b = %modf(a / b2)
    return a + b * b2 * (2 ^ (bits))
end

-- caching function for functions that accept 2 arguments, both of values between
-- 0 and 255. The function to be cached is passed, all values are calculated
-- during loading and a function is returned that returns the cached values (only)
local cache2arg = function(fn)
    if not %PRELOAD_CACHE then return fn end
    local lut = {}
    local index = 0
    while index <= 65535 do
        local a, b = floor(index / 256), mod(index, 256)
        lut[index] = fn(a, b)
        index = index + 1
    end
    return function(a, b)
        return %lut[a * 256 + b]
    end
end

-- splits an 8-bit number into 8 bits, returning all 8 bits as booleans
local byte_to_bits = function(a)
    local b = function(n)
        local c = floor(%a / n)
        return mod(c, 2) == 1
    end
    return b(1), b(2), b(4), b(8), b(16), b(32), b(64), b(128)
end

-- builds an 8bit number from 8 booleans
local bits_to_byte = function(a, b, c, d, e, f, g, h)
    local n = function(b, x)
        return b and x or 0
    end
    return n(a, 1) + n(b, 2) + n(c, 4) + n(d, 8) + n(e, 16) + n(f, 32) + n(g, 64) + n(h, 128)
end

-- bitwise "and" function for 2 8bit number
local band = cache2arg(function(a, b)
    local A, B, C, D, E, F, G, H = %byte_to_bits(b)
    local a, b, c, d, e, f, g, h = %byte_to_bits(a)
    return %bits_to_byte(A and a, B and b, C and c, D and d, E and e, F and f, G and g, H and h)
end)

-- bitwise "or" function for 2 8bit numbers
local bor = cache2arg(function(a, b)
    local A, B, C, D, E, F, G, H = %byte_to_bits(b)
    local a, b, c, d, e, f, g, h = %byte_to_bits(a)
    return %bits_to_byte(A or a, B or b, C or c, D or d, E or e, F or f, G or g, H or h)
end)

-- bitwise "xor" function for 2 8bit numbers
local bxor = cache2arg(function(a, b)
    local A, B, C, D, E, F, G, H = %byte_to_bits(b)
    local a, b, c, d, e, f, g, h = %byte_to_bits(a)
    return %bits_to_byte(A ~= a, B ~= b, C ~= c, D ~= d, E ~= e, F ~= f, G ~= g, H ~= h)
end)

-- bitwise complement for one 8bit number
local bnot = function(x)
    return 255 - mod(x, 256)
end

-- creates a function to combine to 32bit numbers using an 8bit combination function
local w32_comb = function(fn)
    local w32_to_bytes_alias = %w32_to_bytes
    local bytes_to_w32_alias = %bytes_to_w32
    return function(a, b)
        local aa, ab, ac, ad = %w32_to_bytes_alias(a)
        local ba, bb, bc, bd = %w32_to_bytes_alias(b)
        return %bytes_to_w32_alias(%fn(aa, ba), %fn(ab, bb), %fn(ac, bc), %fn(ad, bd))
    end
end

-- create functions for and, xor and or, all for 2 32bit numbers
local w32_and = w32_comb(band)
local w32_xor = w32_comb(bxor)
local w32_or = w32_comb(bor)

-- xor function that may receive a variable number of arguments
local w32_xor_n = function(a, ...)
    local aa, ab, ac, ad = %w32_to_bytes(a)
    local index = 1
    while index <= getn(arg) do
        local ba, bb, bc, bd = %w32_to_bytes(arg[index])
        aa, ab, ac, ad = %bxor(aa, ba), %bxor(ab, bb), %bxor(ac, bc), %bxor(ad, bd)
        index = index + 1
    end
    return %bytes_to_w32(aa, ab, ac, ad)
end

-- combining 3 32bit numbers through binary "or" operation
local w32_or3 = function(a, b, c)
    local aa, ab, ac, ad = %w32_to_bytes(a)
    local ba, bb, bc, bd = %w32_to_bytes(b)
    local ca, cb, cc, cd = %w32_to_bytes(c)
    return %bytes_to_w32(%bor(aa, %bor(ba, ca)), %bor(ab, %bor(bb, cb)), %bor(ac, %bor(bc, cc)), %bor(ad, %bor(bd, cd)))
end

-- binary complement for 32bit numbers
local w32_not = function(a)
    return 4294967295 - mod(a, 4294967296)
end

-- adding 2 32bit numbers, cutting off the remainder on 33th bit
local w32_add = function(a, b)
    return mod((a + b), 4294967296)
end

-- adding n 32bit numbers, cutting off the remainder (again)
local w32_add_n = function(a, ...)
    local index = 1
    while index <= getn(arg) do
        a = mod((a + arg[index]), 4294967296)
        index = index + 1
    end
    return a
end

-- converting the number to a hexadecimal string
local w32_to_hexstring = function(w)
    return format("%08x", w)
end

local hex_to_binary = function(hex)
    return gsub(hex, '(..)', function(hexval)
        return strchar(tonumber(hexval, 16))
    end)
end

-- building the lookuptables ahead of time (instead of littering the source code
-- with precalculated values)
local xor_with_0x5c = {}
local xor_with_0x36 = {}
local index = 0
while index <= 255 do
    xor_with_0x5c[strchar(index)] = strchar(bxor(index, 92))
    xor_with_0x36[strchar(index)] = strchar(bxor(index, 54))
    index = index + 1
end

-----------------------------------------------------------------------------

-- calculating the SHA1 for some text
function sha1.sha1(msg)
    local H0, H1, H2, H3, H4 = 1732584193, 4023233417, 2562383102, 271733878, 3285377520
    local msg_len_in_bits = strlen(msg) * 8

    local first_append = strchar(128)  -- append a '1' bit plus seven '0' bits

    local non_zero_message_bytes = strlen(msg) + 1 + 8 -- the +1 is the appended bit 1, the +8 are for the final appended length
    local current_mod = mod(non_zero_message_bytes, 64)
    local second_append = (current_mod > 0 and %rep(strchar(0), 64 - current_mod)) or ""

    -- now to append the length as a 64-bit number.
    local B1, R1 = %modf(msg_len_in_bits / 16777216)
    local B2, R2 = %modf(16777216 * R1 / 65536)
    local B3, R3 = %modf(65536 * R2 / 256)

    local B4 = 256 * R3

    local L64 = strchar(0) .. strchar(0) .. strchar(0) .. strchar(0) -- high 32 bits
            .. strchar(B1) .. strchar(B2) .. strchar(B3) .. strchar(B4) --  low 32 bits

    msg = msg .. first_append .. second_append .. L64

    assert(mod(strlen(msg), 64) == 0)

    local chunks = strlen(msg) / 64

    local W = {}
    local start, A, B, C, D, E, f, K, TEMP
    local chunk = 0

    while chunk < chunks do
        --
        -- break chunk up into W[0] through W[15]
        --
        start, chunk = chunk * 64 + 1, chunk + 1
        local t = 0
        while t <= 15 do
            W[t] = %bytes_to_w32(
                strbyte(msg, start),
                strbyte(msg, start + 1),
                strbyte(msg, start + 2),
                strbyte(msg, start + 3))
            start = start + 4
            t = t + 1
        end

        --
        -- build W[16] through W[79]
        --
        local t = 16
        while t <= 79 do
            -- For t = 16 to 79 let Wt = S1(Wt-3 XOR Wt-8 XOR Wt-14 XOR Wt-16).
            W[t] = %w32_rot(1, %w32_xor_n(W[t - 3], W[t - 8], W[t - 14], W[t - 16]))
            t = t + 1
        end
        A, B, C, D, E = H0, H1, H2, H3, H4
        local t = 0
        while t <= 79 do
            if t <= 19 then
                -- (B AND C) OR ((NOT B) AND D)
                f = %w32_or(%w32_and(B, C), %w32_and(%w32_not(B), D))
                K = 1518500249
            elseif t <= 39 then
                -- B XOR C XOR D
                f = %w32_xor_n(B, C, D)
                K = 1859775393
            elseif t <= 59 then
                -- (B AND C) OR (B AND D) OR (C AND D
                f = %w32_or3(%w32_and(B, C), %w32_and(B, D), %w32_and(C, D))
                K = 2400959708
            else
                -- B XOR C XOR D
                f = %w32_xor_n(B, C, D)
                K = 3395469782
            end

            -- TEMP = S5(A) + ft(B,C,D) + E + Wt + Kt;
            A, B, C, D, E = %w32_add_n(%w32_rot(5, A), f, E, W[t], K), A, %w32_rot(30, B), C, D

            t = t + 1
        end
        -- Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4 + E.
        H0, H1, H2, H3, H4 = %w32_add(H0, A), %w32_add(H1, B), %w32_add(H2, C), %w32_add(H3, D), %w32_add(H4, E)
    end
    local f = %w32_to_hexstring
    return f(H0) .. f(H1) .. f(H2) .. f(H3) .. f(H4)
end


function sha1.binary(msg)
    return %hex_to_binary(sha1.sha1(msg))
end

function sha1.hmac(key, text)
    assert(type(key) == 'string', "key passed to sha1.hmac should be a string")
    assert(type(text) == 'string', "text passed to sha1.hmac should be a string")

    if strlen(key) > %BLOCK_SIZE then
        key = sha1.binary(key)
    end

    local xor_with_0x36_alias = %xor_with_0x36
    local xor_with_0x5c_alias = %xor_with_0x5c

    local replace_0x36 = function(s)
        return %xor_with_0x36_alias[s]
    end

    local replace_0x5c = function(s)
        return %xor_with_0x5c_alias[s]
    end

    local key_xord_with_0x36 = gsub(key, '(.)', replace_0x36) .. %rep(strchar(54), %BLOCK_SIZE - strlen(key))
    local key_xord_with_0x5c = gsub(key, '(.)', replace_0x5c) .. %rep(strchar(92), %BLOCK_SIZE - strlen(key))

    return sha1.sha1(key_xord_with_0x5c .. sha1.binary(key_xord_with_0x36 .. text))
end

function sha1.hmac_binary(key, text)
    return %hex_to_binary(sha1.hmac(key, text))
end

settagmethod(tag(sha1), 'function', function(_, msg) return sha1.sha1(msg) end)
