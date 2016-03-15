#!/usr/bin/python3

# Example of /etc/postfix/main.cf config to use the generated map:
#
# smtpd_recipient_restrictions =
#   permit_mynetworks,
#   permit_sasl_authenticated,
#   reject_non_fqdn_recipient,
#   reject_unknown_recipient_domain,
#   reject_unauth_destination,
#   check_recipient_access hash:/etc/postfix/exchange_recipients,
#   reject

import sys
import signal
from itertools import chain
import re
import argparse

try:
  from ldap3 import Connection
except:
  print("Please apt-get install python3-ldap3")
  sys.exit(1)

try:
  from ldap3 import NTLM
except:
  print("Your python3-ldap3 seems to be too old to USE NTLM authentication (hint: check Jessie/backports)")
  sys.exit(1)

try:
  import lepl.apps.rfc3696
except:
  print("Please apt-get install python3-lepl")
  sys.exit(1)


# Arguments
argparser = argparse.ArgumentParser(description='Extract list of valid Exchange addresses from ActiveDirectory to Postfix map')
argparser.add_argument("-H", "--hostnames", required=True, nargs='+', help="Active Directory host to check (using LDAP on port 389), can be specified multiple times, ie: --hostnames 192.168.0.1 192.168.0.2")
argparser.add_argument("-B", "--base-dn",   required=True,            help="LDAP root to search for Exchange attributes, ie: --base 'ou=Corp,dc=corp,dc=com'")
argparser.add_argument("-u", "--user",      required=True,            help="LDAP user to use for binding, NTML format, ie: --user 'CORP\\user'")
argparser.add_argument("-p", "--passwd",    required=True,            help="LDAP user password")
argparser.add_argument("-d", "--domains",   required=True, nargs='+', help="List of email domains you want to export data for, ie: --domains corp.com corp.lu")
argparser.add_argument("-x", "--excludes",  required=True, nargs='+', help="DN you want to exclude (BE SURE TO MATCH EXACTLY WHAT'S IN AD, NO ADDITIONAL SPACES....), ie: --excludes 'ou=OldUsers,ou=Users,ou=Corp,dc=corp,dc=com'")
argparser.add_argument("-w", "--write",     required=True,            help="Output file (postfix hashmap format), ie: --write /tmp/postfix_map")
args = argparser.parse_args()

servers   = args.hostnames
base_dn   = args.base_dn
bind_user = args.user
bind_pass = args.passwd
targ_dom  = args.domains
excl_dn   = args.excludes
out_file  = args.write

class timeout:
  def __init__(self, seconds=1, error_message='Timeout'):
    self.seconds = seconds
    self.error_message = error_message
  def handle_timeout(self, signum, frame):
    raise TimeoutError(self.error_message)
  def __enter__(self):
    signal.signal(signal.SIGALRM, self.handle_timeout)
    signal.alarm(self.seconds)
  def __exit__(self, type, value, traceback):
    signal.alarm(0)


class ActiveDirectory(object):

  def __init__(self, servers=[], bind_user=None, bind_pass=None, base_dn=None, targ_dom=[]):

    assert servers,   "List of servers cannot be empty"
    assert base_dn,   "Base DN (aka root) cannot be empty"
    assert bind_user, "Bind user cannot be empty (use Windows like user, ie: DOMAIN\Someuser)"
    assert bind_pass, "Bind password cannot be empty"
    assert base_dn,   "Base DN (aka root) cannot be empty"
    assert base_dn,   "Base DN (aka root) cannot be empty"

    self.bind_user = bind_user
    self.bind_pass = bind_pass
    self.base_dn   = base_dn

    self.conn = None
    for server in servers:
      try:
        with timeout(seconds=5):
          self.conn = self._srv_conn(server)
          break
      except Exception as e:
        print('Unable to connect to LDAP server %s: %r' % (server, e))

    assert self.conn, "All available servers failed to connect, this is fatal"

  def _srv_conn(self, server):
    conn = Connection(server, self.bind_user, self.bind_pass, auto_bind=True)
    return conn

  def return_exchange_smtp_entries(self):
    with timeout(seconds=30):
      self.conn.search(self.base_dn, '(proxyAddresses=*)', attributes=['distinguishedName', 'proxyAddresses'])
      return self.conn.entries


# Connect AD
try:
  AD = ActiveDirectory(servers=servers, base_dn=base_dn, bind_user=bind_user, bind_pass=bind_pass)
except Exception as e:
  print("Unable to connect to any server: %r" % e)
  sys.exit(2)

# Query (&(objectclass=person)(proxyAddresses=*))
try:
  exchange_entries = AD.return_exchange_smtp_entries()
except Exception as e:
  print('Unable to fetch any (proxyAddresses=*) entries from AD: %r' % e)
  sys.exit(3)

# Filter non-SMTP entries and keep only the domain we want
all_valid_exchange_entries = []
for entry in exchange_entries:
  try:

    # Filter excluded OU
    skipped        = False
    dn_entry       = entry.distinguishedName[0]
    for excl in excl_dn:
      if excl.lower() in dn_entry.lower():
        skipped = True

    if not skipped:
      exchange_entry = entry.proxyAddresses # Get the attribute we need
      exchange_entry = [x.lower() for x in exchange_entry] # Lowercase
      exchange_entry = [x for x in exchange_entry if x.startswith('smtp:')] # Filter non SMTP stuff

      # Filter invalid domains
      valid_exchange_entry = []
      for valid_dom in targ_dom:
        valid_exchange_entry.append([x for x in exchange_entry if x.endswith('@'+valid_dom)]) # Filter invalid domains
      all_valid_exchange_entries.append(valid_exchange_entry)

  except Exception as e:
    print('Skipping entry "%r", an error occured: %r' % (entry, e))

if not all_valid_exchange_entries:
  print("List of Exchange entries is empty, fatal error")
  sys.exit(4)

# Flatten (twice otherwise it's not really flattened)
all_valid_exchange_entries = list(chain(*all_valid_exchange_entries))
all_valid_exchange_entries = list(chain(*all_valid_exchange_entries))

# Sub 'smtp:'
all_valid_addr = []
for entry in all_valid_exchange_entries:
  all_valid_addr.append(re.sub('^smtp:', '', entry))

# Validate email addr format
email_validator = lepl.apps.rfc3696.Email()
all_valid_addr = [x for x in all_valid_addr if email_validator(x)]

if not all_valid_addr:
  print("List of email addresses is empty, fatal error")
  sys.exit(5)

all_valid_addr.sort()
try:
  with open(out_file, 'w') as f:
    for addr in all_valid_addr:
      f.write("%s\tOK\n" % addr)
except Exception as e:
  print('An error occured when trying to generate out file: %r' % e)
  sys.exit(6)
