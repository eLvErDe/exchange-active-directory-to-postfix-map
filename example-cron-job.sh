#!/bin/sh

# Addr to search (fatal if not found)
valid_addr="support@corp.com"
minimum_lines=150

# Temp file
temp=`mktemp`

# Paths
script="/root/active-directory-to-postfix-map/get_active_directory_valid_emails.py"
postmap="/etc/postfix/exchange_recipients"

# Cleanup
trap "test -f \"${temp}\" && rm -f \"${temp}\" && rm -f \"${temp}.db\"" EXIT

# Run script with my parameters
"${script}" --hostnames 192.168.0.1 192.168.0.2 --base-dn 'OU=Corp,DC=corp,DC=com' --user 'CORP\bind_user' --passwd 'password' --domains corp.com --excludes 'ou=OldUsers,ou=Users,ou=Corp,dc=corp,dc=com' --write ${temp}

# Worked ?
if [ ${?} -eq 0 ]; then
  postmap "${temp}" || (echo "Postmap check failed, fatal error" && exit 1)
  postmap -q"${valid_addr}" "${temp}" >/dev/null || (echo "${valid_addr} not found in new postmap, fatal error" && exit 2)
  [ `wc -l < "${temp}"` -ge ${minimum_lines} ] || (echo "New postfix map doesn't have enough lines, fatal error" && exit 3)
else
  echo "${script} exited badly, fatal error" && exit 4
fi

# Send diff by email
diff -u "${postmap}" "${temp}" | mail -E -s "[SMTP Frontend] ActiveDirectory 2 Postfix map changed" root

# Apply
cp -f "${temp}" "${postmap}"
postmap "${postmap}"
