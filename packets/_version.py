# Copyright (c) 2026 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

"""The one place the packets version is written (L-12).

``setup.py`` reads this file as text, with a regular expression, rather than
importing it: importing ``packets`` before the extensions are built is not
something a build can rely on. Everything that reports a version at run
time -- ``packets.__version__``, ``rtengine``'s ``/engine/status`` -- imports
it. Keep it a single assignment of a string literal, or the regex will not
find it.
"""

__version__ = '2.4.0'
