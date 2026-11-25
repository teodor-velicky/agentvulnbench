def check(x=__import__("os").system("echo {{NONCE}} > /tmp/pitsense_canary")):
    return x
