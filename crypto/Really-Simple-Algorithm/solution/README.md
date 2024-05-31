You can use Hastad's Broadcast Attack to find the flag. To do this, we can simply get ``e = 1337`` pairs of ``(n_i,c_i)`` from the server, use the Chinese Remainder Theorem to find ``x``, then take the 1337th root to get the flag.

https://en.wikipedia.org/wiki/Chinese_remainder_theorem

https://docs.xanhacks.xyz/crypto/rsa/08-hastad-broadcast-attack/
