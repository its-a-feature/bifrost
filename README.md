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
## dump
The `-action dump` command can extract information about keytabs or credential caches based on the flags.
### tickets
To dump tickets specifically,  use `-source tickets`. By default, this will only iterate through the default credential cache. The default credential cache can be identified with the `-action list` command and looking for the cache identified with a `[*]` marker. To dump a specific credential cache, use the `-name [name here]` flag. 

Each ticket will be described and dumped into a base64 Kirbi format that can then be used for other commands or with other tools on Windows.
### keytab
To dump keytab keys, use the `-source keytab` parameter. By default, this will attempt to dump information from the default keytab (`/etc/krb5.keytab`) which is only readable by root. To specify another keytab, use the `-path /path/to/keytab` argument.

Each keytab entry will be described and the key will be dumped in base64 and hex.
## askhash
The `-action askhash` will compute the necessary hashes used to request TGTs and decrypt responses. This command requires the plaintext password with `-password [password here]`, but if the passwoord contains special characters that might cause issues, you can always supply a base64 encoded version of the password with `-bpassword [base64 password here]`. You must also supply the `-username [username]` and `-domain fqdn` parameters so that the proper salt can be generated. 

If you're wanting to get the hashes for a computer$ account, make sure to include the `$` in the username. The salt for a computer account is different than the salt for a user account.
## asktgt
The `-action asktgt` command will take a plaintext password, a hash, or a keytab entry and request a TGT from the DC.  
### with plaintext password
To use a plaintext password, you need to supply `-username [username]` and `-domain [fqdn]` in addition to `-password [password]`. If the password contains special characters that might cause issues, supply the `-bpassword [base64 of password]` instead. This will use Kerberos Login APIs to request a TGT normally and store it into a new credential cache. Bifrost will then extract the ticket from that cache and remove the cache.
### with hash
To use a hash, you need to supply `-username [username]` and `-domain [fqdn]` in addition to `-hash [hash here]` and `-enctype [aes256|aes128|rc4|des3]`.  With just these paramters, Bifrost will construct manual ASN1 Kerberos traffic and connect to `[fqdn]` on port 88 to request an AES256 TGT (specifically, listing aes256, aes128, and rc4 as valid return encryption types). This can be modified of course. Specifying the `-supportAll false` flag will adjust the traffic so that the only supported encryption response type is the same as the hash. Alternatively, you can specify `-tgtEnctype [aes256|aes128|rc4]` to request a TGT of a specific encryption type regardless of the hash type supplied.
### with keytab entry
To use a keytab, you need  to supply `-username [username]` and `-domain [fqdn]` in addition to `-enctype [aes256|aes128|rc4]` and `-keytab [path to keytab]`. Bifrost will then open the keytab and search for the entry that matches the supplied username, domain, and encryption type and pull that hash. With just these paramters, Bifrost will construct manual ASN1 Kerberos traffic and connect to `[fqdn]` on port 88 to request an AES256 TGT (specifically, listing aes256, aes128, and rc4 as valid return encryption types). This can be modified of course. Specifying the `-supportAll false` flag will adjust the traffic so that the only supported encryption response type is the same as the hash. Alternatively, you can specify `-tgtEnctype [aes256|aes128|rc4]` to request a TGT of a specific encryption type regardless of the hash type supplied.
## describe
The `-action describe` command will parse out the information of a Kirbi file. You need to supply `-ticket [base64 of Kirbi ticket]`.
## asktgs
The `-action asktgs` command will ask the KDC for a service ticket based on a supplied TGT. You need to supply `-ticket [base64 of kirbi TGT]` and `-service [spn,spn,spn]`. 

### different domains
By default, Bifrost will look to the TGT for information about the domain to connect to and the domain for the service. If either of these things differ from the TGT, you can specify them manually with `-connectDomain [domain to connect to]` and `-serviceDomain [domain of the service]`.  By default, Bifrost specifies that aes256, aes128, and rc4 encryption types for the resulting service are acceptable (so you'll most likely get back an aes256 service ticket). 
### kerberoasting
If you don't want to get an aes256 service ticket back, but instead want something more crackable, you can specify the `-kerberoast true` flag to indicate that you want the resulting service ticket to be rc4.
## s4u
The `-action s4u` command utilizes resource-based constrained delegatioon. You need to specify `-ticket [base64 of TGT]`, `-targetUser [username]` (if the user is in another domain than the one the TGT is for, specify the target user as `username@otherdomain.com`). At this point, Bifrost will only do the  S4U2Self process. To  complete the process and also do the S4U2Proxy, additionally specify `-spn [target spn]`. If you need to connect to a different domain than the one specified in the TGT, you can specify `-connectDomain [fqdn]`. This sequence will again craft manual ASN1 Kerberos traffic over port 88.
## ptt
The `-action ptt` command takes a ticket (TGT or service ticket) and imports it to a specified credential cache or creates a new credential cache. You need to specify `-ticket [base64 of ticket]` and either `-name [full credential cache name]` to add the ticket to the specified cache, or `-name new` to create a new credential cache and import the ticket  there.

## remove
The `-action remove` command removes caches or keytab entries.
### credential cache
To remove a credential cache, you need to specify `-source tickets` and `-name [cache name  here]`. This remove the entire cache. As far as I can tell with the krb5 Heimdal APIs, you cannot remove a specific credential entry - the MITKerberosShim reports that the required functions aren't implemented.
### keytab entry
To remove a principal from a keytab, you need to specify `-source keytab` and `-principal [principal name]`. By default, this will look for the principal in the default keytab, but if you want to use a specific keytab, specify it with `-name [path to keytab]`. 
