# Copyright 2016 Rion Carter
#
# License: GPLv3

import os
import os.path
import platform
import json
from slimit.parser import Parser

class ChromeParser(object):
    # Locate the chrome extensions directory (varies based on OS)
    platform_dir = {'Linux': '~/.config/chromium/Default/Extensions',
                    'nt': '%HOMEDRIVE%%HOMEPATH%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions',
                    'mac': '~/Library/Application Support/Google/Chrome/Default/Extensions'}

    def __init__(self):
        self.description = "Parses chrome extensions"

    def parse(self):
        # Detect Platform, locate the extension directory
        current_platform = platform.system()
        extensions_dir = os.path.expanduser(self.platform_dir[current_platform])

        #with open("permissions.chrome.json") as permissions_json:
        #    permissions = json.load(permissions_json)

        # Place to store final results
        iteration_results = {}

        # Iterate over each extension
        for extension_dir in os.listdir(extensions_dir):
            if extension_dir == 'Temp':
                continue

            # Each extension could have a number of versions, so we iterate over them all
            version_results = {}
            versions_dir = os.listdir(extensions_dir + os.sep + extension_dir)
            for extension_version in versions_dir:
                extension_to_analyze = extensions_dir + os.sep + extension_dir + os.sep + extension_version
                results = self.analyze_extension(extension_to_analyze)
                version_results[extension_version] = results

            iteration_results[extension_dir] = version_results


        # Examine the source code to see where each permission is used

        # Output a report
        #report = json.loads(iteration_results)
        print(json.dumps(iteration_results, indent=4, sort_keys=True))



    def analyze_extension(self, extension_d):
        # Load the plugin manifest
        try:
            with open(extension_d + os.sep + 'manifest.json') as manifest_f:
                manifest = json.load(manifest_f)
        except:
            print("Error: Unable to load manifest for %(extension_d)s. SKIPPING")
            return {"error":"Unable to load manifest for %(extension_d)s. SKIPPING"}

        # Find the extension name (if specified)
        name = manifest['name']

        # Load the permissions
        manifest_permissions = manifest['permissions']


        # Load the optional_permissions
        manifest_permissions_optional = []
        try:
            manifest_permissions_optional = manifest['optional_permissions']
        except:
            print("No optional_permissions declared")
            pass

        # Walk the extension directory and check each file
        analyzed_files = {'name': name, 'files': {}}
        for dirpath, subdirs, filenames in os.walk(extension_d):
            for filename in filenames:
                file_result = self.analyze_file(os.path.join(dirpath, filename), manifest_permissions, manifest_permissions_optional)
                analyzed_files['files'][filename] = file_result

        return analyzed_files


    def analyze_file(self, file, permissions, optional_permissions):
        file_result = {'http': {}, 'https': {}, 'file':{}, 'xhr':{}, 'permissions':{}}

        # Read the file
        print(file)
        try:
            with open(file, 'r') as in_file:
                content = in_file.read()
        except:
            print("Can't open file %(file)s, continuing")
            return file_result

        # Correct for minified JS if the file is javascript
        if file.endswith('.js'):
            jsParser = Parser()  # JS-Prettifier from slimit package
            try:
                jsTree = jsParser.parse(content)
                content = jsTree.to_ecma()
            except:
                print("Failed to parse JS in file %(file)s. SKIPPING")

        # Prep file for processing
        content_lines = content.splitlines()

        # Process file (line by line) and collect results
        for i, content_line in enumerate(content_lines):
            # Check for insecure urls (http:)
            if 'http:' in content_line:
                # Push the line number and the line into the result dictionary
                file_result['http'][str(i)] = content_line

            # check for secure urls (https:)
            if 'https:' in content_line:
                # Push the line number and the line into the result dictionary
                file_result['https'][str(i)] = content_line

            # check for file urls (file:)
            if 'file:' in content_line:
                # Push the line number and the line into the result dictionary
                file_result['file'][str(i)] = content_line

            # Check for XHR via JS and JQuery (As best I can right now)
            if ('XMLHttpRequest' in content_line) or ('.ajax(' in content_line) or ('.get(' in content_line) or ('.post(' in content_line):
                # Push the line number and the line into the result dictionary
                file_result['xhr'][str(i)] = content_line

            # Load the permissions regex file
            #   Use it as a lookup to get the API calls associated with the permission
            with open("libs/permissions.chrome.json") as permissions_json:
                permissions_lookup = json.load(permissions_json)

            permissions_used = []
            for permission in permissions_lookup:
                if permissions_lookup[permission] in content_line:
                    permissions_used.append(permission)

            #
            # The block above will check for all permissions that can be defined
            #
            # check for permissions use in both normal and 'optional' permissions blocks
            #permissions_use = []
            #for permission in permissions:
            #    if permission in content_line:
            #        permissions_use.append(permission)

            #for permission in optional_permissions:
            #    if permission in content_line:
            #        permissions_use.append(permission)

            # If any permissions are detected, log them in the file_result
            if len(permissions_used) > 0:
                file_result['permissions'][str(i)] = {'permissions':permissions_used, 'line_content': content_line}


        return file_result