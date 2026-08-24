"""A second implementation of the client half of the protocol, for testing.

Nothing here imports `fxa_lite`. That is the point: if the server and its tests
shared a derivation, a bug in that derivation would agree with itself and pass.
"""
