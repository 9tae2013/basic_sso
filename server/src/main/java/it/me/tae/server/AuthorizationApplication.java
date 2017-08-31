package it.me.tae.server;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;


@SpringBootApplication
public class AuthorizationApplication {

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("dave").password("secret").authorities("ROLE_USER")
                .and()
                .withUser("tae").password("secret").authorities("ROLE_USER", "ROLE_ADMIN");
    }

    @Configuration
    @EnableAuthorizationServer
    public static class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("my-client")
                    .secret("my-client-pass")
                    .scopes("openid")
                    .autoApprove(true)
                    .authorizedGrantTypes("implicit", "refresh_token", "password", "authorization_code", "client_credentials");
        }


        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer()).authenticationManager(authenticationManager);
        }

        @Bean
        public TokenStore tokenStore() {
            return new JwtTokenStore(jwtTokenEnhancer());
        }

        @Bean
        @ConfigurationProperties("jwt")
        protected JwtAccessTokenConverter jwtTokenEnhancer() {
            return new JwtAccessTokenConverter();
        }
    }


    @Configuration
    public static class LoginConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    .formLogin()
                        .and()
                    .httpBasic()
                        .and()
                    .csrf()
                        .disable()
                    .authorizeRequests()
                        .anyRequest().authenticated();
            // @formatter:on
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationApplication.class, args);
    }
}