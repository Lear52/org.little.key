package org.little.key;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class kMessageX509 {
       private static final Logger          logger  = LoggerFactory.getLogger(kMessageX509.class);
       private static boolean debug=false; 

       private static String checkPEMType(String type) {
               
           if("CERTIFICATE"            .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "CERTIFICATE";}
           if("X509 CERTIFICATE"       .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "CERTIFICATE";}
           if("PRIVATE KEY"            .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "PRIVATE KEY";}
           if("RSA PRIVATE KEY"        .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "PRIVATE KEY";}
           if("NEW CERTIFICATE REQUEST".equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "CERTIFICATE REQUEST";}
           if("CERTIFICATE REQUEST"    .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "CERTIFICATE REQUEST";}
           if("X509 CRL"               .equals(type)){ logger.trace("PEM ("+type+") Ok!"); return "X509 CRL";}
           logger.trace("PEM UNKNOW ("+type+")!");
           return null;   
               
       }
 
       private static kMessage parsePEM2MSG(kMessage msg,byte [] buf){
              InputStream       in    =null;
              InputStreamReader is    =null;
              PEMParser         parser=null;
              PemReader         reader=null;
              String            type =null;
              try {
                   in     = new ByteArrayInputStream(buf);
                   is     = new InputStreamReader(in);
                   reader = new PemReader(is);
                   PemObject pem_obj=reader.readPemObject();
                   if(pem_obj==null)return null;
                   type   =pem_obj.getType();
                   type=checkPEMType(type);
                   if(type==null)return null;
              }
              catch(Exception e){
                    if(debug) { 
                       Except ex=new Except(e);
                       logger.error("DER NO! ex:"+ex);
                    }
                    return null;
              }
              finally {
                  if(reader!=null)try {reader.close();} catch (IOException e) {}
                  if(is    !=null)try {is.close();    } catch (IOException e) {}
                  if(in    !=null)try {in.close();    } catch (IOException e) {}
              }

              in     = new ByteArrayInputStream(buf);
              is     = new InputStreamReader(in);
              parser = new PEMParser(is);

              if("CERTIFICATE".equals(type)){
                  try {
                      Object parsedObj = parser.readObject();
                      if(parsedObj==null)return null;
                      if(parsedObj instanceof X509CertificateHolder) {
                        X509CertificateHolder holder = (X509CertificateHolder) parsedObj;
                        //if(holder == null) return null;
                        BigInteger n=holder.getSerialNumber();
                        X500Name   issuer =holder.getIssuer(); 
                        X500Name   subject=holder.getSubject();
                        Date       start=holder.getNotBefore();
                        Date       end=holder.getNotAfter();   
                 
                        msg.setX509Type     (type);
                        msg.setX509TypeFile ("PEM");
                        msg.setX509BeginDate(start             );
                        msg.setX509EndDate  (end               );
                        msg.setX509Serial   (n.toString      ());
                        msg.setX509Subject  (subject.toString());
                        msg.setX509Issuer   (issuer.toString ());
                      }
                      else return null;
                  } 
                  catch(Exception e){
                        if(debug) { 
                                 Except ex=new Except(e);
                                 logger.error("DER NO! ex:"+ex);
                        }
                        return null;
                  }
                  finally {
                      if(parser!=null)try {parser.close(); } catch (Exception e){}
                      if(is    !=null)try {is.close();     } catch (Exception e){}
                      if(in    !=null)try {in.close();     } catch (Exception e){}
                  }
               }
               else
               if("X509 CRL".equals(type)){
                      try {
                      Object parsedObj = parser.readObject();
                      if(parsedObj==null)return null;
                      if (parsedObj instanceof X509CRLHolder) {
                          X509CRLHolder crl = (X509CRLHolder) parsedObj;
                          String issuer=crl.getIssuer().toString();
                          Iterator<?> crl_number=crl.getRevokedCertificates().iterator();
                              
                          String n_str="";
                          while(crl_number.hasNext()){
                                X509CRLEntryHolder p=(X509CRLEntryHolder)crl_number.next();
                                n_str+=p.getSerialNumber().toString()+";";           
                          }
                            
                          msg.setX509Type     (type);
                          msg.setX509TypeFile ("PEM");
                          msg.setX509BeginDate(new Date());
                          msg.setX509EndDate  (new Date());
                          msg.setX509Serial   (n_str);
                          msg.setX509Subject  (issuer);
                          msg.setX509Issuer   (issuer);
                      }
                      else return null;
                      
                   } 
                   catch(Exception e) {
                         if(debug) { 
                            Except ex=new Except(e);
                            logger.error("DER NO! ex:"+ex);
                         }
                         return null;
                  }
                  finally {
                      if(parser!=null)try {parser.close(); } catch (Exception e){}
                      if(is    !=null)try {is.close();     } catch (Exception e){}
                      if(in    !=null)try {in.close();     } catch (Exception e){}
                  }
               }
               else
               if("CERTIFICATE REQUEST".equals(type)){
                  try {
                       Object parsedObj = parser.readObject();
                       if(parsedObj==null)return null;
                       if(parsedObj instanceof PKCS10CertificationRequest) {
                          PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parsedObj;
                          //System.out.println("PKCS10CertificationRequest:"+csr);
                          String subject =csr.getSubject().toString();
                          Attribute []  attr=csr.getAttributes();
                          for(int i=0;i<attr.length;i++)logger.trace("attr["+i+"]"+attr[i].toString());
                               
                          msg.setX509Type     (type);
                          msg.setX509TypeFile ("PEM");
                          msg.setX509BeginDate(new Date());
                          msg.setX509EndDate  (new Date());
                          msg.setX509Serial   ("0");
                          msg.setX509Subject  (subject);
                          msg.setX509Issuer   ("");
                       }
                       else return null;
                  } 
                  catch(Exception e) {
                        if(debug) { 
                           Except ex=new Except(e);
                           logger.error("DER NO! ex:"+ex);
                        }
                   }
                   finally {
                       if(parser!=null)try {parser.close(); } catch (Exception e){}
                       if(is    !=null)try {is.close();     } catch (Exception e){}
                       if(in    !=null)try {in.close();     } catch (Exception e){}
                   }
               }
               else{
                   return null;
               }
               logger.trace(type+" DER Ok!");
               return msg;

       }
       //---------------------------------------------------------------------------------------------------------------
       //  X.509 Certificate
       private static kMessage parseX509CERDER2MSG(kMessage msg,byte [] buf){
               String          type="CERTIFICATE";
               InputStream     in  =null;
               X509Certificate cert=null;
               try{
                   try{
                       CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                       in   = new ByteArrayInputStream(buf);
                       cert = (X509Certificate) certFactory.generateCertificate(in);
                   }
                   catch (Exception e){
                          if(debug) {
                             Except ex=new Except(e);
                             logger.error("DER NO! ex:"+ex);
                          }
                          return null;
                   }
                   try{
                       BigInteger n      =cert.getSerialNumber();
                       String     n_str=n.toString      ();
                       String     issuer;
                       issuer  =  cert.getIssuerX500Principal().toString();
                       issuer  =  cert.getIssuerDN().toString().toString();
                       String     subject;
                       subject =  cert.getSubjectX500Principal().toString();
                       subject =  cert.getSubjectDN().toString();
                       Date       start  =cert.getNotBefore();
                       Date       end    =cert.getNotAfter();   
                        
                       msg.setX509Type     (type   );
                       msg.setX509TypeFile ("DER"  );
                       msg.setX509BeginDate(start  );
                       msg.setX509EndDate  (end    );
                       msg.setX509Serial   (n_str  );
                       msg.setX509Subject  (subject); 
                       msg.setX509Issuer   (issuer );
                   }
                   catch (Exception e){
                           if(debug) {                  
                             Except ex=new Except(e);
                             logger.error("DER NO! ex:"+ex);
                           }
                         return null;
                   }
                      
               }     
               finally {
                  if(in!=null)try {in.close();     } catch (Exception e){}
               }
               logger.trace(type+" DER Ok!");
               return msg;
              
       }
       
       //Certificate Revocation List (CRL)
       private static kMessage parseX509CRLDER2MSG(kMessage msg,byte [] buf){
               String type="X509 CRL";
               InputStream in=null;
               X509CRL crl=null; 
               try{
                  try{
                      CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                      in=new ByteArrayInputStream(buf);
                      crl = (X509CRL)certFactory.generateCRL(in);
                  }
                  catch (Exception e){
                         if(debug) {
                            Except ex=new Except(e);
                            logger.error("DER NO! ex:"+ex);
                         }
                         return null;
                  }
                  try{
                      Iterator<? extends X509CRLEntry> crl_number=crl.getRevokedCertificates().iterator();
                      String n_str="";
                      while(crl_number.hasNext()){
                            X509CRLEntry p=crl_number.next();
                            n_str+=p.getSerialNumber().toString()+";";           
                      }
                              
                      String     issuer;
                      issuer  = crl.getIssuerX500Principal().toString();
                      issuer  = crl.getIssuerDN().toString().toString();
                      String    subject=issuer;
                                     
                      Date       start  =crl.getThisUpdate();
                      Date       end    =crl.getNextUpdate();   
                       
                      msg.setX509Type     (type      );
                      msg.setX509TypeFile ("DER"     );
                      msg.setX509BeginDate(start     );
                      msg.setX509EndDate  (end       );
                      msg.setX509Serial   (n_str     );
                      msg.setX509Subject  (subject   ); 
                      msg.setX509Issuer   (issuer    );
                  }
                  catch(Exception e){
                        if(debug) {
                           Except ex=new Except(e);
                           logger.error("DER NO! ex:"+ex);
                        }
                        return null;
                  }
               }     
               finally {
                   if(in!=null)try {in.close();     } catch (Exception e){}
               }
               logger.trace(type+" DER Ok!");
               return msg;
       }

       //  Certificate Request Message
       private static kMessage parseX509CSRDER2MSG(kMessage msg,byte [] buf){
               String type="CERTIFICATE REQUEST";
               //if(true)
               try {
                      JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(buf);
                      String subject=csr.getSubject().toString();

                      Attribute []  attr=csr.getAttributes();for(int i=0;i<attr.length;i++)logger.trace("attr["+i+"]"+attr[i].toString());
                      
                      msg.setX509Type     (type      );
                      msg.setX509TypeFile ("DER"     );
                      msg.setX509BeginDate(new Date());
                      msg.setX509EndDate  (new Date());
                      msg.setX509Serial   ("0");
                      msg.setX509Subject  (subject   ); 
                      msg.setX509Issuer   (" "       );
               }
               catch(Exception e){
                     if(debug) {
                        Except ex=new Except(e);
                        logger.error("DER NO! ex:"+ex);
                     }
                     return null;
               }
               logger.trace(type+" DER Ok!");
               return msg;
          
       }
       private static kMessage parsePEM2MSG(kMessage msg,final InputStream in){
               byte[] buf=null;
               try{buf=_ByteBuilder.toByte(in);}
               catch (Exception e){
                     if(debug) {
                        Except ex=new Except(e);
                        logger.error("DER NO! ex:"+ex);
                     }
                     return null;
               }
               return parsePEM2MSG(msg,buf);
       }
       private static kMessage parseX509CERDER2MSG(kMessage msg,final InputStream in){
               byte[] buf=null;
               try{buf=_ByteBuilder.toByte(in);}
               catch (Exception e){
                     if(debug) {
                        Except ex=new Except(e);
                        logger.error("DER NO! ex:"+ex);
                     }
                     return null;
               }
               return parseX509CERDER2MSG(msg,buf);
       }
       private static kMessage parseX509CRLDER2MSG(kMessage msg,final InputStream in){
               byte[] buf=null;
               try{buf=_ByteBuilder.toByte(in);}
               catch (Exception e){
                     if(debug) {
                        Except ex=new Except(e);
                        logger.error("DER NO! ex:"+ex);
                     }
                     return null;
               }
               return parseX509CRLDER2MSG(msg,buf);
       }
       private static kMessage parseX509CSRDER2MSG(kMessage msg,final InputStream in){
               byte[] buf=null;
               try{buf=_ByteBuilder.toByte(in);}
               catch (Exception e){
                     if(debug) {
                        Except ex=new Except(e);
                        logger.error("DER NO! ex:"+ex);
                     }
                     return null;
               }
               return parseX509CSRDER2MSG(msg,buf);  
        }

        public static kMessage parse(kMessage msg) {
               byte[]   bin_buffer=msg.getBodyBin();
               kMessage ret=null;
               ret=parsePEM2MSG(msg,bin_buffer);
               if(ret==null)ret=parseX509CERDER2MSG(msg,bin_buffer);
               if(ret==null)ret=parseX509CRLDER2MSG(msg,bin_buffer);
               if(ret==null)ret=parseX509CSRDER2MSG(msg,bin_buffer);
              
               return ret;
       }

       public static void main(String[] args) {
              FileInputStream in;
              kMessage msg=new kMessage();

              byte[] buf=null;
              try{
                  in=new FileInputStream(args[0]);
            	  buf=_ByteBuilder.toByte(in);
              }
              catch (Exception e){
                     logger.error("ex:"+e);
                     return ;
              }
              msg.setBodyBin(buf);;
              msg=parse(msg);
              //---------------------------------------------------------------------------------------------------
              System.out.println("msg:"+msg);

       }


}
