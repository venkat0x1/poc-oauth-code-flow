package com.xplor.microsoftlogincodeflow;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.text.ParseException;
import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {


    public static String authorizeUrl="https://login.microsoftonline.com/9cbb4e71-dd48-43a1-991f-379fe7fe47fb/oauth2/v2.0/authorize";
    public static String tokenEndpoint = "https://login.microsoftonline.com/9cbb4e71-dd48-43a1-991f-379fe7fe47fb/oauth2/v2.0/token";
    public static String tenantId="9cbb4e71-dd48-43a1-991f-379fe7fe47fb";
    public static String clientId="113d981b-832d-42b2-8c7b-2fd01a1df7a8";
    public static String clientSecret = "r0W8Q~CV~FhB4VYj6BnsDwrN5x6m6yqKuO-2ndf.";

    public static String redirectUri = "http://localhost:4200/auth/microsoft";

    @Autowired
    private ObjectMapper objectMapper;

    @GetMapping("/test-app")
    public String testApp(){
        return "Working..!";
    }


    @GetMapping("/login")
    public RedirectView redirectToMicrosoft(){

        RedirectView redirectView = new RedirectView();
        String url = String.format("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=openid+profile",authorizeUrl,clientId,redirectUri);
        redirectView.setUrl(url);
        return redirectView;

    }

    @GetMapping("/microsoft")
    public User getUserFromAzureByAuthorizationCode(@RequestParam(name = "code") String code) throws JsonProcessingException, ParseException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            MultiValueMap<String,String> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("client_id",clientId);
            requestBody.add("client_secret",clientSecret);
            requestBody.add("code",code);
            requestBody.add("redirect_uri",redirectUri);
            requestBody.add("grant_type","authorization_code");

            String firstName = null;
            String lastName = null;
            String email = null;
            List<String> groups = null;


            ResponseEntity<String> responseEntity = restTemplate.postForEntity(tokenEndpoint,requestBody,String.class);

            if (responseEntity.getStatusCode() == HttpStatus.OK){

                AzureADTokenResponse azureADTokenResponse = objectMapper.readValue(responseEntity.getBody(), AzureADTokenResponse.class);

                String idToken = azureADTokenResponse.getId_token();


                JWTClaimsSet jwtClaimsSet = SignedJWT.parse(idToken).getJWTClaimsSet();

                firstName = jwtClaimsSet.getStringClaim("given_name");
                lastName = jwtClaimsSet.getStringClaim("family_name");
                email = jwtClaimsSet.getStringClaim("upn");
                groups = jwtClaimsSet.getStringListClaim("groups");
            }

            User user = new User();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setUsername(email);
            user.setGroups(groups);

            return user;
        } catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("Field to login..!");
        }
    }

}
