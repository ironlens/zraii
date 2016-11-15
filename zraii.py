#
# Zraii - Web Extension Security Analyzer
#
# Version: 0.1
#
# Copyright 2016 Rion Carter
#
# License: GPLv3
#

import sys
from libs.chrome import ChromeParser

#
# Define the version
version = 0.1

def print_help():
    print("zraii " + str(version) + "Copyright 2016 Rion Carter")
    print("https://github.com/ironlens/zraii")
    print("")
    print("Zraii sifts through browser extensions to build a profile on how they operate. This information can help you as you review extensions for security issues")
    print("")
    print("Usage:")
    print("\tpython zraii.py chrome")
    print("")
    print("Troubleshooting:")
    print("If you have trouble running Zraii, ensure that you have a Virtual Environment configured that loads all the dependencies from Requirements.txt")

if len(sys.argv) > 1:
    if sys.argv[1] == "chrome":
        chrome_parser = ChromeParser()
        chrome_parser.parse()
    elif sys.argv[1] == "firefox":
        print("Firefox is not supported at this time")
    else:
        print_help()
else:
    print_help()
