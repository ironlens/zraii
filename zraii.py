#
# Zraii - Web Extension Security Analyzer
#
# Version: 0.1
#
# Copyright 2016 Rion Carter
#
# License: GPLv2 only
#

import sys
from libs.chrome import ChromeParser

#
# Define the version
version = 0.1

if len(sys.argv) > 1:
    if sys.argv[1] == "chrome":
        chrome_parser = ChromeParser()
        chrome_parser.parse()
    elif sys.argv[1] == "firefox":
        print("Firefox is not supported at this time")
    else:
        print("zraii " + str(version) + "Copyright 2016 Rion Carter")
else:
    print("zraii " + str(version) + " Copyright 2016 Rion Carter")