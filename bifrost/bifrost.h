//
//  bifrost.h
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Kerberos/Kerberos.h>
#import "asn1.h"
#import "kirbi.h"
#import "connection.h"
#import <CommonCrypto/CommonKeyDerivation.h>

@interface bifrost : NSObject
-(NSString*)dumpCredentialsToKirbiCCache:(char*)ccache Destroy:(bool)destroy;
-(NSString*)listAllCCaches;
-(NSString*)ktutilKeyTabPath:(NSString*)keyTabPath;
-(NSString*)genPasswordHashPassword:(char*)password Length:(int)password_len Enc:(int)enc_type Username:(NSString*)username Domain:(NSString*)domain Pretty:(Boolean)prettyprint;
-(NSString*)getTGTUsername:(NSString*)usernameToUse Password:(NSString*)passwordToUse Domain:(NSString*)domainToUse;
-(krb5_creds)createKrb5CredFromKrb5Ticket:(Krb5Ticket)ticket;
-(NSString*)importCred:(NSString*)ticketKirbi ToCache:(NSString*)cacheName;
-(NSString*)removeCacheName:(NSString*)cacheName;
-(NSString*)removePrincipal:(NSString*)principal FromCacheName:(NSString*)cacheName;
-(NSString*)removePrincipal:(NSString*)principal fromKeytab:(NSString*)path;
-(NSString*)getKeyFromKeytab:(NSString*)keytab andPrincipal:(NSString*)principal withEnctype:(int)enctype;
-(int)getEncValueFromEnctype:(NSString*)enctype;
-(NSString*)askTGTConnectDomain:(NSString*)connectDomain EncType:(int)enctype Hash:(NSString*)hash Username:(NSString*)username Domain:(NSString*)domain SupportAll:(bool)supportAll TgtEnctype:(int)tgtEnctype LKDCIP:(NSString*)lkdcip;
-(NSString*)askTGTLKDCByIP:(NSString*)IP EncType:(int)enctype Password:(NSString*)password Username:(NSString*)username Domain:(NSString*)domain SupportAll:(bool)supportAll TgtEnctype:(int)tgtEnctype;
-(NSString*)askTGSConnectDomain:(NSString*)connectDomain TGT:(NSString*)tgtKirbi Service:(NSString*)service ServiceDomain:(NSString*)serviceDomain Kerberoast:(bool)kerberoasting LKDCIP:(NSString*)LKDCIP;
-(NSString*)s4u2selfTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser;
-(NSString*)s4uTicket:(NSString*)tgtKirbi ConnectDomain:(NSString*)connectDomainInput TargetUser:(NSString*)targetUser SPN:(NSString*)spn;
-(NSString*)askLKDCDomainByIP:(NSString*)IP;
-(bool)createLKDCCACHECONFDataPrincipal:(NSString*)principalName TicketData:(NSString*)ticketData CCacheName:(NSString*)cacheName;
-(bool)storeLKDCConfDataFriendlyName:(NSString*)friendlyName Hostname:(NSString*)hostname Password:(NSString*)password CCacheName:(NSString*)cacheName;
@end
void printKrbError(krb5_context context, krb5_error_code ret);

