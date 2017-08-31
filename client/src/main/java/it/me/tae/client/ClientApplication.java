package it.me.tae.client;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@EnableOAuth2Sso
@RestController
@SpringBootApplication
public class ClientApplication extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.antMatcher("/**")
                .authorizeRequests()
                    .antMatchers("/index.html", "/home.html", "/").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .csrf()
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    @Bean
    public OAuth2RestTemplate restTemplate(OAuth2ClientContext oauth2ClientContext, OAuth2ProtectedResourceDetails resourceDetails) {
        return new OAuth2RestTemplate(resourceDetails, oauth2ClientContext);
    }




    @Autowired
    private OAuth2RestTemplate restTemplate;

    @Value("${oauth2.resource.url}")
    private String resourceUrl;


    @RequestMapping("/admin")
    public Map<String, String> user() {
        return restTemplate.exchange(
                resourceUrl + "/me",
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<Map<String, String>>() {
                }).getBody();
    }

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }



    public static void main(String[] args) {
        new SpringApplicationBuilder(ClientApplication.class).run(args);
    }
}