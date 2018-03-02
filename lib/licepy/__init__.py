# coding: utf-8

from xml.etree.ElementTree import tostring as _tostring
from xml.etree.ElementTree import fromstring

import sys

if sys.version_info.major > 2:
    def tostring(e):
        return str(_tostring(e), 'ascii')
else:
    tostring = _tostring

from ._info import *
from ._cart import createKeyPair, createCertRequest, createCertificate
