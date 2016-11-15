# zraii - Web extension security analyzer

Zraii is designed to speed the process of analyzing web browser extensions, plugins and add-ons. It sifts through extension files, manifests and configurations to build a profile on the extension and how it operates. This information can help you as you review extensions for security issues

Presently Zraii can work with Chrome extensions and will analyze all of the extensions that you have installed

# Prep for use:
- Install virtualenv (sudo pip virtualenv)
- Activate your virtual environment (source /path/to/virtual_env/bin/activate)
- pip install -r requirements.txt

# Use:

To examine all plugins/extensions installed in Chrome on your system:
- python zraii.py chrome

#Future:
Examine a specific plugin (chrome):
- python zraii.py chrome /path/to/extension

Examine a specific plugin (firefox):
- python zraii.py firefox /path/to/extension

Examine all plugins installed in firefox on your system:
- python zraii.py firefox