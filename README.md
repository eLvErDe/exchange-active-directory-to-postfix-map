# exchange-active-directory-to-postfix-map
Cron script to export Exchange emails addresses from Active Directory to a Postfix map (in case of an antimalware frontend)

<h2>Fighting backscatter</h2>

Why did I write this script ? Simple answer: most of Postfix frontends protecting email servers (Exchange :D) are badly configured.
There're exposed to backscattering (http://www.postfix.org/BACKSCATTER_README.html) because of their domain-based configuration instead of recipient adresses.

In a few lines, what is backscattering:
1. Spammers sends a forget email with random sender address to a random @corp.com recipient
2. Your frontend accepts the emails because the recipient matches @corp.com
3. The email gets forwarded to your Exchange server
4. Exchange receives the email but random@corp.com is not a valid recipient
5. Exchange issues a sender non-delivery notification to the orginal forged sender address
6. You get blacklisted because these kind of message get caught by honeypot like senderbase.org

Actually, the problem is easy to understand: your postfix frontend accepts emails for *@corp.com instead of accepting only valid recipient addresses.


<h2>How to handle that ?</h2>

Most of people do something like this in their frontend configuration:
<pre>
root@server:~# cat /etc/postfix/transport
# Exchange
corp.com	        smtp:192.168.0.1
</pre>

It's fine but if you want to avoid backscattering your Postfix server needs to know which @corp.com addresses are 
valid and then use this list to reject invalid users.


<h2>The script</h2>

This project is a Python script that connects to Active Directory using LDAP protocol and extract from their every email address found in Exchange related attributes.
Then we'll turn this into a Postfix map and use it a whitelist for "smtpd_recipient_restrictions" postfix configuration setting.

I inluded some comments to configure postfix as well as like a very safe cron job to update this map automatically.

Here is --help output:

<pre>
usage: get_active_directory_valid_emails.py [-h] -H HOSTNAMES [HOSTNAMES ...]
                                            -B BASE_DN -u USER -p PASSWD -d
                                            DOMAINS [DOMAINS ...] -x EXCLUDES
                                            [EXCLUDES ...] -w WRITE

Extract list of valid Exchange addresses from ActiveDirectory to Postfix map

optional arguments:
  -h, --help            show this help message and exit
  -H HOSTNAMES [HOSTNAMES ...], --hostnames HOSTNAMES [HOSTNAMES ...]
                        Active Directory host to check (using LDAP on port
                        389), can be specified multiple times, ie: --hostnames
                        192.168.0.1 192.168.0.2
  -B BASE_DN, --base-dn BASE_DN
                        LDAP root to search for Exchange attributes, ie:
                        --base 'ou=Corp,dc=corp,dc=com'
  -u USER, --user USER  LDAP user to use for binding, NTML format, ie: --user
                        'CORP\user'
  -p PASSWD, --passwd PASSWD
                        LDAP user password
  -d DOMAINS [DOMAINS ...], --domains DOMAINS [DOMAINS ...]
                        List of email domains you want to export data for, ie:
                        --domains corp.com corp.lu
  -x EXCLUDES [EXCLUDES ...], --excludes EXCLUDES [EXCLUDES ...]
                        DN you want to exclude (BE SURE TO MATCH EXACTLY
                        WHAT'S IN AD, NO ADDITIONAL SPACES....), ie:
                        --excludes
                        'ou=OldUsers,ou=Users,ou=Corp,dc=corp,dc=com'
  -w WRITE, --write WRITE
                        Output file (postfix hashmap format), ie: --write
                        /tmp/postfix_map
</pre>
