NOTE: This integration is not ready for prodoction use yet.  Contact Alex if you want to play with it.


Tenable.io Integration for DefenseStorm

This integration is intended to be installed on the DefenseStorm DVM.  You should perform the install as the "root" user and the installation should be done in the /usr/local/ directory.

This integration requires the pytenable python module.  To install it, use the command:

pip3 install pytenable

1. Pull the repository and submodules:

		git clone --recurse-submodules https://github.com/DefenseStorm/tenableScanResults.git

2. If this is the first integration on this DVM, do the following:
	
	- Edit /etc/syslog-ng/syslog-ng.conf.d and add local7 to the excluded list for filter f_syslog3 and filter f_messages.  The lines should look like the following:

			filter f_syslog3 { not facility(auth, authpriv, mail, local7) and not filter(f_debug); };
			filter f_messages { level(info,notice,warn) and not facility(auth,authpriv,cron,daemon,mail,news,local7); };
		
	- Run the following command to restart syslog-ng
	 
			service syslog-ng restart

3. Run the following command to copy the template config file and update the settings:

		cp tenableScanResults.conf.template tenableScanResults.conf

4. Edit the configuration in the tenableScanResults.conf file:

	- Obtain your Access Key and Secret Key from Tenable.io

	- Add the following to the conf file:
		
			access_key = <Access Key from Tenable.io>
			secret_key = <Secret Key from Tenable.io>

5. Add the following entry to the root crontab so the script will run once a day at midnight, or change as needed.

		0 0 * * * cd /usr/local/tenableScanResults; ./tenableioScanResults.py
