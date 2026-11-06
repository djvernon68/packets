# Copyright (c) 2019 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""Protocol plugins and the registry that finds them.

``registry.py`` holds the built-in registrations and the optional
entry-point scan. Each protocol lives in its own sub-package below this one
(``plugins/bgp/``), implements ``ProtocolPlugin``, and is registered on an
``Engine`` either by class (embedded use) or by entry point (standalone).

No plugin is imported here. The registry is a directory, not a loader: the
whole reason ``Engine.register_plugin`` takes a class is that an embedded
caller should pay for exactly the protocols it asked for.
"""
