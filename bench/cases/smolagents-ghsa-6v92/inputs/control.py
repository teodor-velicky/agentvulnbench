# Benign model-emitted code using the same map(getattr, ...) path on an allowed attribute.
import warnings
filters = list(map(getattr, [warnings], ["filters"]))[0]
note = "{{NONCE}}"
len(note)
