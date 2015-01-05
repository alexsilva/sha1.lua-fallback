sha1.lua
========

This pure-Lua module computes SHA-1 and HMAC-SHA1 signature computations in Lua 3.2.

Usage
=====

    local sha1 = dofile('sha1.lua')

    local hash_as_hex   = sha1(message)            -- returns a hex string
    local hash_as_data  = sha1.binary(message)     -- returns raw bytes

    local hmac_as_hex   = sha1.hmac(key, message)        -- hex string
    local hmac_as_data  = sha1.hmac_binary(key, message) -- raw bytes

Credits
=======

Converted to lua 3.2 by Alex Silva and Optimized by Alessandro Hecht

This is a cleanup of an implementation by Eike Decker - http://cube3d.de/uploads/Main/sha1.txt (lua 5.1),

Which in turn was based on an original implementation by Jeffrey Friedl - http://regex.info/blog/lua/sha1 (lua 5.1)

The original algorithm is http://www.itl.nist.gov/fipspubs/fip180-1.htm

License
=======

This version, as well as all the previous ones in which is based, are implemented under the MIT license (See license file for details).





