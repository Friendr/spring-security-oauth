package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("marissa").password("koala").roles("USER").and().withUser("paul")
                .password("emu").roles("USER");
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers("/webjars/**", "/images/**", "/oauth/uncache_approvals", "/oauth/cache_approvals");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeRequests(authz -> authz
                        .requestMatchers("/login.jsp").permitAll()
                        .anyRequest().hasRole("USER")
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedPage("/login.jsp?authorization_error=true")
                )
                // TODO: put CSRF protection back into this endpoint
                .csrf(csrf -> csrf
                        .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
                        .disable()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login.jsp")
                )
                .formLogin(formLogin -> formLogin
                        .loginProcessingUrl("/login")
                        .failureUrl("/login.jsp?authentication_error=true")
                        .loginPage("/login.jsp")
                )
                .build();
    }
}
