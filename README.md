# zraii
Web-browser Extension Security Analyzer

This tool is a WIP and is designed to analyze browser extensions (chrome at the moment) to see how they utilize the permissions they have been granted.


Prep for use:
- Install virtualenv (sudo pip virtualenv)
- Activate your virtual environment (source /path/to/virtual_env/bin/activate)
- pip install -r requirements.txt

Use:

To examine all plugins on your system:
- python zraii.py

To examine a specific plugin:
- python zraii.py /path/to/extension