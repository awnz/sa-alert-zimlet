# Fork
This is a fork of mss/sa-alert-zimlet, modified to read the X-SPAM-LEVEL header of a Proxmox Mail Gateway mail server upstream of a Zimbra server.
I am personally using this deployed to a Zimbra 10 OSE instance.

# sa-alert-zimlet
This zimlet checks for X-Spam-Status message header and alerts the user when certain tags are found

# Automatically notify your helpdesk
You can have your users automatically submit suspicious mail to your helpdesk staff by configuring the `alertmail` property in config_template.xml.

# Help us improve!
Please help us and add more Spam Assassin tags to this Zimlet, just open a Github issue 
and copy SA message headers of Phishing mail.

