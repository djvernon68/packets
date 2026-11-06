# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The BGP-4 protocol plugin.

Nothing is imported here on purpose. The wire codec and the best-path
selection in this package are compiled modules, and an ``__init__`` that
pulled them in would make ``import packets.routing.rtengine.plugins`` pay
for an extension load that an engine configured without BGP never needs --
see the registry note in the parent package.
"""
