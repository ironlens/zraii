#
# Zraii - Web Extension Security Analyzer
#
# Version: 0.1
#
# Copyright 2016 Rion Carter
#
# License: GPLv2 only
#

import os
import os.path
import platform
import json
from slimit.parser import Parser



#
# skeleton

# Locate the chrome extensions directory (varies based on OS)
extensions_by_platform = {'Linux':'~/.config/chromium/Default/Extensions',
              'nt':'%HOMEDRIVE%%HOMEPATH%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions',
              'mac': '~/Library/Application Support/Google/Chrome/Default/Extensions'}

#
# Have to perform tilde expansion to get to the extensions directory
current_platform = platform.system()
extensions_dir = os.path.expanduser(extensions_by_platform[current_platform])


#
# Load the permissions regex file
with open("permissions.chrome.json") as permissions_json:
    permissions = json.load(permissions_json)

#
# Load the shady code regex file
with open("shady.json") as shady_json:
    shady_code = json.load(shady_json)

#
# Define the JS-Prettifier from slimit package
jsParser = Parser()


#
# Check a specified JS file for use of permissions and use of 'shady' commands
def check_js_security(js_file_name, js):
    js_lines = js.splitlines()
    print(js_lines)

    # check for permissions use
    permissions_use = []
    for permission in permissions:
        #print("detecting: %(permission)s" % locals())
        for i, j in enumerate(js_lines):
            if permissions[permission] in j:
                print("permission found!")
                permission_instance = str(i) + "-" + js_file_name + "-" + permission
                permissions_use.append(permission_instance)

    print("\r\ndetected permissions:")
    print(permissions_use)
    print("\r\n")

#
# Parse an extension and analyze
def analyze_extension(extension_d):
    # Get a list of files in the root-directory
    extension_files = os.listdir(extension_d)

    # Load the plugin manifest
    try:
        with open(extension_d + os.sep + 'manifest.json') as manifest_f:
            manifest = json.load(manifest_f)
    except:
        print("Error: Unable to load manifest for %(extension_d)s. SKIPPING" % locals())


    # Load the permissions
    manifest_permissions = manifest['permissions']
    print(manifest_permissions)


    # Load the optional_permissions
    try:
        manifest_permissions_optional = manifest['optional_permissions']
    except:
        pass

    try:
        print(manifest_permissions_optional)
    except:
        print("No optional_permissions declared")


    # Load the content_scripts
    try:
        content_scripts = manifest['content_scripts']
    except:
        pass

    try:
        print(content_scripts)
    except:
        print("No content_scripts declared")


    # Load any content security policy information
    try:
        content_security_policy = manifest['content_security_policy']
    except:
        pass

    try:
        print(content_security_policy)
    except:
        print("No content_security_policy declared")


    #
    # Check for permissions that the extension uses
    #       This works by analyzing every .js file for the regex patterns listed in 'permissions.chrome.json'

    # Get a list of all JavaScript files used in the extension
    print("\r\n\r\n")
    js_files = []
    for dirpath, dirnames, filenames in os.walk(extension_d):
        for filename in [f for f in filenames if f.endswith(".js")]:
            js_files.append(os.path.join(dirpath, filename))

    # Examine each one for use of permissions described in the 'permissions.chrome.json' file
    for js in js_files:
        print(js)
        with open(js,'r') as js_file:
            content = js_file.read()

        try:
            jsTree = jsParser.parse(content)
            clean_js = jsTree.to_ecma()
        except:
            clean_js = content

        check_js_security(js, clean_js)


    print(js_files)
    print("\r\n\r\n")


# Iterate over each extension
for extension_dir in os.listdir(extensions_dir):
    if extension_dir == 'Temp':
        continue

    # Examine the manifest.json file
    base_path = extensions_dir + os.sep + extension_dir

    versions_dir = os.listdir(extensions_dir + os.sep + extension_dir)
    for extension_version in versions_dir:
        analyze_extension(extensions_dir + os.sep + extension_dir + os.sep + extension_version)


    # Examine the source code to see where each permission is used

    # Output a report