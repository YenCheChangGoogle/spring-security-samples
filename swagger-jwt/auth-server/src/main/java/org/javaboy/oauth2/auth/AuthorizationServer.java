package org.javaboy.oauth2.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.lang.ref.SoftReference;
import java.util.Arrays;

@EnableAuthorizationServer //開啟授權伺服器的自動化配置
@Configuration
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
  @Autowired
  TokenStore tokenStore;
  @Autowired
  ClientDetailsService clientDetailsService;
  @Autowired
  AuthenticationManager authenticationManager;
  @Autowired
  PasswordEncoder passwordEncoder;
  @Autowired
  JwtAccessTokenConverter jwtAccessTokenConverter;

  //主要用來配置Token的一些基本信息
  @Bean
  AuthorizationServerTokenServices tokenServices() {
    DefaultTokenServices services=new DefaultTokenServices();
    services.setClientDetailsService(clientDetailsService);
    services.setSupportRefreshToken(true);
    services.setTokenStore(tokenStore);
    services.setAccessTokenValiditySeconds(60*60*24*2);
    services.setRefreshTokenValiditySeconds(60*60*24*7);
    TokenEnhancerChain tokenEnhancerChain=new TokenEnhancerChain();
    tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter));
    services.setTokenEnhancer(tokenEnhancerChain);
    return services;
  }

  //用來配置令牌端點的安全約束, 也就是這個端點誰能訪問, 誰不能訪問
  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.allowFormAuthenticationForClients();
  }

  //用來配置客戶端的詳細信息
  //授權伺服器要做兩方面的檢驗, 一方面是校驗客戶端, 另一方面則是校驗用戶
  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.inMemory()
    .withClient("javaboy") //就是client_id的值
    .secret(passwordEncoder.encode("123")) //就是client_secret的值
    .resourceIds("res1")
    .authorizedGrantTypes("password", "refresh_token")
    .scopes("all") //勾選all acope
    .redirectUris("http://localhost:8082/index.html", "http://localhost:8081/swagger-ui.html");
  }

  //用來配置令牌的訪問端點和令牌服務
  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.authenticationManager(authenticationManager).tokenServices(tokenServices());
  }
}
