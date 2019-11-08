# bifrost

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
For asktgt action:
    -username a.test -domain DOMAIN.COM
         if using a plaintext password, specify -password 'password'
         if using a hash, specify -enctype [aes256 | aes128 | rc4] -hash [hash_here]
             optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type
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
     for keytabs: optionally specify -name to not use the default ccache
     you can't remove a specific ccache principal entry since it seems to not be implemented in heimdal
```
