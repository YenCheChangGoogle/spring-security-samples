package org.javaboy.oauth2.res.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class AccessTokenConfig {
  @Bean
  TokenStore tokenStore() {
    return new JwtTokenStore(jwtAccessTokenConverter());
  }

  @Bean
  JwtAccessTokenConverter jwtAccessTokenConverter() {
    JwtAccessTokenConverter converter=new JwtAccessTokenConverter();
    converter.setSigningKey("javaboy"); //設定的簽章鍵
    return converter;
  }
}
