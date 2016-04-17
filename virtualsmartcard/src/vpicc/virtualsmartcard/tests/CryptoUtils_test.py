#
# Copyright (C) 2014 Dominik Oepen
#
# This file is part of virtualsmartcard.
#
# virtualsmartcard is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# virtualsmartcard is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# virtualsmartcard.  If not, see <http://www.gnu.org/licenses/>.
#

import unittest
from virtualsmartcard.CryptoUtils import *


class TestCryptoUtils(unittest.TestCase):

    def setUp(self):
        self.teststring = "DEADBEEFistatsyksdvhwohfwoehcowc8hw8rogfq8whv75tsg"\
                          "ohsav8wress"
        self.testpass = "SomeRandomPassphrase"
        # The following string was generated using the proteced string method
        # and is used as a regression test.
        self.protectedTestString = "$2b$12$zumYy3GAgzgxfPtc/f8EYu$GQ9aw6J" + \
                                   "u/fPIYcwv3HQoClD1HjRwDsjUHsom5xwIFy1N" + \
                                   "ta8cK8e7sX3yiaCDxPrQtPdTVei0DN8vMpriN" + \
                                   "lYpEw==$ZTRmMTUxZjkwMGY2NmZhOTFkNDdhN" + \
                                   "WYxOTA1M2RjNjE="

    def test_padding(self):
        padded = append_padding(16, self.teststring)
        unpadded = strip_padding(16, padded)
        self.assertEqual(unpadded, self.teststring)

    def test_protect_string(self):
        protectedString = protect_string(self.teststring, self.testpass)
        unprotectedString = read_protected_string(protectedString,
                                                  self.testpass)
        self.assertEqual(self.teststring, unprotectedString)

    def test_unprotect_string(self):
        unprotectedString = read_protected_string(self.protectedTestString,
                                                  self.testpass)
        self.assertEqual(unprotectedString, self.teststring)

if __name__ == "__main__":
    unittest.main()
