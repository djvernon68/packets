# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Routing subsystems built on top of the packets codecs.

This is an umbrella package, deliberately empty of code. The routing engine
lives in ``packets.routing.rtengine``; anything else routing-shaped that is
not a packet codec (a standalone FIB helper, a config translator) belongs
beside it rather than inside it.

Nothing is imported here on purpose. ``packets.routing.rtengine`` pulls in
compiled RIB extensions, and importing ``packets.routing`` must stay free of
that cost for code that only wants a sibling module.
"""
