# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""A second implementation of the client half of the protocol, for testing.

Nothing here imports `fxa_lite`. That is the point: if the server and its tests
shared a derivation, a bug in that derivation would agree with itself and pass.
"""
