/*
    2    * Copyright (c) 2009, Oracle and/or its affiliates. All rights reserved.
    3    * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
    4    *
    5    * This code is free software; you can redistribute it and/or modify it
    6    * under the terms of the GNU General Public License version 2 only, as
    7    * published by the Free Software Foundation.  Oracle designates this
    8    * particular file as subject to the "Classpath" exception as provided
    9    * by Oracle in the LICENSE file that accompanied this code.
   10    *
   11    * This code is distributed in the hope that it will be useful, but WITHOUT
   12    * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
   13    * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
   14    * version 2 for more details (a copy is included in the LICENSE file that
   15    * accompanied this code).
   16    *
   17    * You should have received a copy of the GNU General Public License version
   18    * 2 along with this work; if not, write to the Free Software Foundation,
   19    * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
   20    *
   21    * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
   22    * or visit www.oracle.com if you need additional information or have any
   23    * questions.
   24    
   25   package sun.security.provider.certpath;
   26   
   27   import java.net.URI;
import java.security.cert.CRLReason;
import java.security.cert.CertificateException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.ocsp.OCSPResponse;

import sun.security.util.Debug;
import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;
      
      *//**
   54    * This is a class that checks the revocation status of a certificate(s) using
   55    * OCSP. It is not a PKIXCertPathChecker and therefore can be used outside of
   56    * the CertPathValidator framework. It is useful when you want to
   57    * just check the revocation status of a certificate, and you don't want to
   58    * incur the overhead of validating all of the certificates in the
   59    * associated certificate chain.
   60    *
   61    * @author Sean Mullan
   62    *//*
   63   public final class OCSP {
   64   
   65       private static final Debug debug = Debug.getInstance("certpath");
   66   
   67       private static final int CONNECT_TIMEOUT = 15000; // 15 seconds
   68   
   69       private OCSP() {}
   70   
   71       *//**
   72        * Obtains the revocation status of a certificate using OCSP using the most
   73        * common defaults. The OCSP responder URI is retrieved from the
   74        * certificate's AIA extension. The OCSP responder certificate is assumed
   75        * to be the issuer's certificate (or issued by the issuer CA).
   76        *
   77        * @param cert the certificate to be checked
   78        * @param issuerCert the issuer certificate
   79        * @return the RevocationStatus
   80        * @throws IOException if there is an exception connecting to or
   81        *    communicating with the OCSP responder
   82        * @throws CertPathValidatorException if an exception occurs while
   83        *    encoding the OCSP Request or validating the OCSP Response
   84        *//*
   85       public static RevocationStatus check(X509Certificate cert,
   86           X509Certificate issuerCert)
   87           throws IOException, CertPathValidatorException {
   88           CertId certId = null;
   89           URI responderURI = null;
   90           try {
   91               X509CertImpl certImpl = X509CertImpl.toImpl(cert);
   92               responderURI = getResponderURI(certImpl);
   93               if (responderURI == null) {
   94                   throw new CertPathValidatorException
   95                       ("No OCSP Responder URI in certificate");
   96               }
   97               certId = new CertId(issuerCert, certImpl.getSerialNumberObject());
   98           } catch (CertificateException ce) {
   99               throw new CertPathValidatorException
  100                   ("Exception while encoding OCSPRequest", ce);
  101           } catch (IOException ioe) {
  102               throw new CertPathValidatorException
  103                   ("Exception while encoding OCSPRequest", ioe);
  104           }
  105           OCSPResponse ocspResponse = check(Collections.singletonList(certId),
  106               responderURI, issuerCert, null);
  107           return (RevocationStatus) ocspResponse.getSingleResponse(certId);
  108       }
  109   
  110       *//**
  111        * Obtains the revocation status of a certificate using OCSP.
  112        *
  113        * @param cert the certificate to be checked
  114        * @param issuerCert the issuer certificate
  115        * @param responderURI the URI of the OCSP responder
  116        * @param responderCert the OCSP responder's certificate
  117        * @param date the time the validity of the OCSP responder's certificate
  118        *    should be checked against. If null, the current time is used.
  119        * @return the RevocationStatus
  120        * @throws IOException if there is an exception connecting to or
  121        *    communicating with the OCSP responder
  122        * @throws CertPathValidatorException if an exception occurs while
  123        *    encoding the OCSP Request or validating the OCSP Response
  124        *//*
  125       public static RevocationStatus check(X509Certificate cert,
  126           X509Certificate issuerCert, URI responderURI, X509Certificate
  127           responderCert, Date date)
  128           throws IOException, CertPathValidatorException {
  129           CertId certId = null;
  130           try {
  131               X509CertImpl certImpl = X509CertImpl.toImpl(cert);
  132               certId = new CertId(issuerCert, certImpl.getSerialNumberObject());
  133           } catch (CertificateException ce) {
  134               throw new CertPathValidatorException
  135                   ("Exception while encoding OCSPRequest", ce);
  136           } catch (IOException ioe) {
  137               throw new CertPathValidatorException
  138                   ("Exception while encoding OCSPRequest", ioe);
  139           }
  140           OCSPResponse ocspResponse = check(Collections.singletonList(certId),
  141               responderURI, responderCert, date);
  142           return (RevocationStatus) ocspResponse.getSingleResponse(certId);
  143       }
  144   
  145       *//**
  146        * Checks the revocation status of a list of certificates using OCSP.
  147        *
  148        * @param certs the CertIds to be checked
  149        * @param responderURI the URI of the OCSP responder
  150        * @param responderCert the OCSP responder's certificate
  151        * @param date the time the validity of the OCSP responder's certificate
  152        *    should be checked against. If null, the current time is used.
  153        * @return the OCSPResponse
  154        * @throws IOException if there is an exception connecting to or
  155        *    communicating with the OCSP responder
  156        * @throws CertPathValidatorException if an exception occurs while
  157        *    encoding the OCSP Request or validating the OCSP Response
  158        *//*
  159       static OCSPResponse check(List<CertId> certIds, URI responderURI,
  160           X509Certificate responderCert, Date date)
  161           throws IOException, CertPathValidatorException {
  162   
  163           byte[] bytes = null;
  164           try {
  165               OCSPRequest request = new OCSPRequest(certIds);
  166               bytes = request.encodeBytes();
  167           } catch (IOException ioe) {
  168               throw new CertPathValidatorException
  169                   ("Exception while encoding OCSPRequest", ioe);
  170           }
  171   
  172           InputStream in = null;
  173           OutputStream out = null;
  174           byte[] response = null;
  175           try {
  176               URL url = responderURI.toURL();
  177               if (debug != null) {
  178                   debug.println("connecting to OCSP service at: " + url);
  179               }
  180               HttpURLConnection con = (HttpURLConnection)url.openConnection();
  181               con.setConnectTimeout(CONNECT_TIMEOUT);
  182               con.setReadTimeout(CONNECT_TIMEOUT);
  183               con.setDoOutput(true);
  184               con.setDoInput(true);
  185               con.setRequestMethod("POST");
  186               con.setRequestProperty
  187                   ("Content-type", "application/ocsp-request");
  188               con.setRequestProperty
  189                   ("Content-length", String.valueOf(bytes.length));
  190               out = con.getOutputStream();
  191               out.write(bytes);
  192               out.flush();
  193               // Check the response
  194               if (debug != null &&
  195                   con.getResponseCode() != HttpURLConnection.HTTP_OK) {
  196                   debug.println("Received HTTP error: " + con.getResponseCode()
  197                       + " - " + con.getResponseMessage());
  198               }
  199               in = con.getInputStream();
  200               int contentLength = con.getContentLength();
  201               if (contentLength == -1) {
  202                   contentLength = Integer.MAX_VALUE;
  203               }
  204               response = new byte[contentLength > 2048 ? 2048 : contentLength];
  205               int total = 0;
  206               while (total < contentLength) {
  207                   int count = in.read(response, total, response.length - total);
  208                   if (count < 0)
  209                       break;
  210   
  211                   total += count;
  212                   if (total >= response.length && total < contentLength) {
  213                       response = Arrays.copyOf(response, total * 2);
  214                   }
  215               }
  216               response = Arrays.copyOf(response, total);
  217           } finally {
  218               if (in != null) {
  219                   try {
  220                       in.close();
  221                   } catch (IOException ioe) {
  222                       throw ioe;
  223                   }
  224               }
  225               if (out != null) {
  226                   try {
  227                       out.close();
  228                   } catch (IOException ioe) {
  229                       throw ioe;
  230                   }
  231               }
  232           }
  233   
  234           OCSPResponse ocspResponse = null;
  235           try {
  236               ocspResponse = new OCSPResponse(response, date, responderCert);
  237           } catch (IOException ioe) {
  238               // response decoding exception
  239               throw new CertPathValidatorException(ioe);
  240           }
  241           if (ocspResponse.getResponseStatus() != ResponseStatus.SUCCESSFUL) {
  242               throw new CertPathValidatorException
  243                   ("OCSP response error: " + ocspResponse.getResponseStatus());
  244           }
  245   
  246           // Check that the response includes a response for all of the
  247           // certs that were supplied in the request
  248           for (CertId certId : certIds) {
  249               SingleResponse sr = ocspResponse.getSingleResponse(certId);
  250               if (sr == null) {
  251                   if (debug != null) {
  252                       debug.println("No response found for CertId: " + certId);
  253                   }
  254                   throw new CertPathValidatorException(
  255                       "OCSP response does not include a response for a " +
  256                       "certificate supplied in the OCSP request");
  257               }
  258               if (debug != null) {
  259                   debug.println("Status of certificate (with serial number " +
  260                       certId.getSerialNumber() + ") is: " + sr.getCertStatus());
  261               }
  262           }
  263           return ocspResponse;
  264       }
  265   
  266       *//**
  267        * Returns the URI of the OCSP Responder as specified in the
  268        * certificate's Authority Information Access extension, or null if
  269        * not specified.
  270        *
  271        * @param cert the certificate
  272        * @return the URI of the OCSP Responder, or null if not specified
  273        *//*
  274       public static URI getResponderURI(X509Certificate cert) {
  275           try {
  276               return getResponderURI(X509CertImpl.toImpl(cert));
  277           } catch (CertificateException ce) {
  278               // treat this case as if the cert had no extension
  279               return null;
  280           }
  281       }
  282   
  283       static URI getResponderURI(X509CertImpl certImpl) {
  284   
  285           // Examine the certificate's AuthorityInfoAccess extension
  286           AuthorityInfoAccessExtension aia =
  287               certImpl.getAuthorityInfoAccessExtension();
  288           if (aia == null) {
  289               return null;
  290           }
  291   
  292           List<AccessDescription> descriptions = aia.getAccessDescriptions();
  293           for (AccessDescription description : descriptions) {
  294               if (description.getAccessMethod().equals(
  295                   AccessDescription.Ad_OCSP_Id)) {
  296   
  297                   GeneralName generalName = description.getAccessLocation();
  298                   if (generalName.getType() == GeneralNameInterface.NAME_URI) {
  299                       URIName uri = (URIName) generalName.getName();
  300                       return uri.getURI();
  301                   }
  302               }
  303           }
  304           return null;
  305       }
  306   
  307       *//**
  308        * The Revocation Status of a certificate.
  309        *//*
  310       public static interface RevocationStatus {
  311           public enum CertStatus { GOOD, REVOKED, UNKNOWN };
  312   
  313           *//**
  314            * Returns the revocation status.
  315            *//*
  316           CertStatus getCertStatus();
  317           *//**
  318            * Returns the time when the certificate was revoked, or null
  319            * if it has not been revoked.
  320            *//*
  321           Date getRevocationTime();
  322           *//**
  323            * Returns the reason the certificate was revoked, or null if it
  324            * has not been revoked.
  325            *//*
  326           CRLReason getRevocationReason();
  327   
  328           *//**
  329            * Returns a Map of additional extensions.
  330            *//*
  331           Map<String, Extension> getSingleExtensions();
  332       }
  333   }*/