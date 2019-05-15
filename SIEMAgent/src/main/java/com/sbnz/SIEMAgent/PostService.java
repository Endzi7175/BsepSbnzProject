package com.sbnz.SIEMAgent;

import com.sbnz.SIEMAgent.Log.LogEntry;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.util.List;

@Service
public class PostService {


    private String allPassword = "root123";
    private String serverBaseUrl="https://siemcentar:8043";

    @Bean
    public RestTemplate restTemplate() throws Exception {

        SSLContext sslContext = SSLContextBuilder
                .create()
                .loadKeyMaterial(ResourceUtils.getFile("classpath:keystore.jks"), allPassword.toCharArray(), allPassword.toCharArray())
                .loadTrustMaterial(ResourceUtils.getFile("classpath:truststore.jks"), allPassword.toCharArray())
                .build();

        HttpClient client = HttpClients.custom()
                .setSSLContext(sslContext)
                .build();
        HttpComponentsClientHttpRequestFactory factory =
                new HttpComponentsClientHttpRequestFactory(client);

        return new RestTemplate(factory);

    }


    public void sendEnteriesToSIEM(List<LogEntry> enteries){
//        try {
//            restTemplate().postForEntity(serverBaseUrl, enteries , String.class);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
        for(LogEntry entry : enteries){
            System.out.println(entry);
        }
    }



}
