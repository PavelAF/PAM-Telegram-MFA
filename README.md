# PAM Telegram MFA
PAM Telegram MFA is a PAM library for additional PUSH authentication via Telegram. The call is only possible in the PAM AUTH section.
How does it work? When calling this library, a PUSH message is sent to the Telegram chat/group, according to the configuration. Telegram user(s) can accept/reject the request. After that, the message about the login attempt and the result remains in the chat history

# In the plans
1. At the moment, the user name is linked to user accounts on the server, it is planned to fix this in the future (the restriction rests on the syntax of the config file type libconfig.h)
2. The function of prohibiting the response to an authentication request from Telegram bots (relevant for the group, will be configured in the config file)
3. Displaying the name/ID of the user who responded to the PUSH request in the message

## Build
```bash
apt install gcc libconfig-dev libjson-c-dev libcurl4-openssl-dev
gcc -fPIC -lcurl -lconfig -ljson-c -D_GNU_SOURCE=1 -fno-stack-protector -c pam_telegram.c -o pam_telegram.o \
&& mkdir -p /lib/security && sudo ld -lcurl -lconfig -ljson-c -x --shared -o /lib/security/pam_telegram.so pam_telegram.o
```

## PAM
```
# For testing:
auth        optional    pam_telegram.so [/path/to/pam_telegram.cfg]

# Production:
auth        required    pam_telegram.so [/path/to/pam_telegram.cfg]
```

## Configuration
Default configuration location: /etc/pam_telegram.cfg

## SELinux
When you are running SELinux, maybe you have to set the bool ssh_can_network to true:
```bash
setsebool -P ssh_can_network 1
```
