# PortWatch
This is a program developed by Black Hills Information Security for use on our networks to keep track of what ports on what machines are open.

Developed for Python 3, on Linux.

# Installation #

-Put the directory containing the program where ever you want. You'll have to populate the "Target-IPs" file with a list of the IPs you want to scan. This file uses the standard nmap input formats.
-Additionally, you'll have to configure the python script to deliver results. I used Postmark (https://postmarkapp.com/) as the email provider, so if you want to use a different one, you'll need to modify the program accordingly.
-Note that Postmark needs a python module to run. Get it here (https://github.com/Stranger6667/postmarker/) with pip. Be sure that you install it for python3, not 2.
-Finally, configure your crontab to run the BASH script once a day. I would recommend against running it close to midnight, since, depending on the nmap runtime, the files may not be recognized correctly.

