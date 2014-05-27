/*
* Copyright 2004,2013 The Apache Software Foundation.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.cxf.sts;

import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.FileSystemXmlApplicationContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;


public class WSO2STSTest {

    public static void main(String[] args) throws ParserConfigurationException {
        System.out.println("base folder - " + new File("").getAbsolutePath());

System.setProperty("javax.net.ssl.trustStore",
        "/home/kasun/wso2/products/420-packs/wso2is-4.6.0/repository/resources/security/client-truststore.jks");
System.setProperty("javax.net.ssl.trustStorePassword", "wso2carbon");

ApplicationContext ctx = new FileSystemXmlApplicationContext(
        "classpath:wssec-sts-bean.xml");
        doSTS(ctx);
    }

    private static void doSTS(ApplicationContext ctx) throws ParserConfigurationException {
        STSClient sts = (STSClient) ctx.
                getBean("{http://ws.apache.org/axis2}wso2carbon-stsHttpsSoap12Endpoint.sts-client");

        //parse the ut policy xml, and get a DOM element
        File f = new File("src/main/resources/sts.policy.xml");
        Element stsPolicy = loadPolicy(f.getAbsolutePath());
        sts.setPolicy(stsPolicy);

        sts.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
        sts.setKeyType("http://schemas.xmlsoap.org/ws/2005/02/trust/Bearer");
        sts.setSoap11(false);

//        //sts.setWsdlLocation("https://localhost:9443/services/wso2carbon-sts?wsdl");
//        sts.setLocation("https://localhost:9443/services/wso2carbon-sts.wso2carbon-stsHttpsSoap12Endpoint");
//        sts.setServiceName("{http://ws.apache.org/axis2}wso2carbon-sts");
//        sts.setEndpointName("{http://ws.apache.org/axis2}wso2carbon-stsHttpsSoap12Endpoint");

//        Map<String, Object> props = new HashMap<String, Object>();
//        props.put(SecurityConstants.USERNAME, "admin");
//        props.put(SecurityConstants.PASSWORD, "admin");
//        props.put(SecurityConstants.CALLBACK_HANDLER, "com.cxf.sts.ClientCallbackHandler");
//        props.put(SecurityConstants.ENCRYPT_PROPERTIES,
//                "bearer-client.properties");
//        props.put(SecurityConstants.ENCRYPT_USERNAME, "wso2carbon");
//        sts.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");
//        sts.setKeyType("http://schemas.xmlsoap.org/ws/2005/02/trust/Bearer");
//        sts.setProperties(props);

        try {
            SecurityToken samlToken =
                    sts.requestSecurityToken("http://localhost:9453/services/echo",
                    "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT",
                    "/Issue", null);

            //convert the token dom element to string
            String token = ((DOMImplementationLS) samlToken.getToken().getOwnerDocument().getImplementation()).
                    createLSSerializer().writeToString(samlToken.getToken().getOwnerDocument());
            System.out.println(token);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println(sts.getEndpointQName());

    }

    private static Element loadPolicy(String xmlPath) {
        try{
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document d = db.parse(new File(xmlPath));
            return d.getDocumentElement();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}