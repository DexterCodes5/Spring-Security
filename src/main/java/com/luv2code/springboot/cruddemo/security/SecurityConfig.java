package com.luv2code.springboot.cruddemo.security;

import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.provisioning.*;
import org.springframework.security.web.*;

import javax.sql.*;

@Configuration
public class SecurityConfig {

    // A Bean is an object managed by Spring. It's contained in the Spring Container,
    // which can also be an object factory, if we need more than one instance of an object
    // add support for JDBC and no more hardcoding
    @Bean
    public UserDetailsManager userDetailsManger(DataSource datasource) {
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(datasource);

        // define query to retrieve a user by username
        userDetailsManager.setUsersByUsernameQuery("SELECT user_id, pw, active FROM members WHERE user_id=?");

        // define query to retrieve a authorities/roles by username
        userDetailsManager.setAuthoritiesByUsernameQuery("SELECT user_id, role FROM roles WHERE user_id=?");

        return userDetailsManager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((configurer) -> configurer
                .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                .requestMatchers(HttpMethod.POST, "/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.PUT, "/api/employees").hasRole("MANAGER")
                .requestMatchers(HttpMethod.DELETE, "/api/employees/**").hasRole("ADMIN")
        );

        // use HTTP Basic authentication
        http.httpBasic();

        // disable Cross Site Request Forgery (CSRF)
        // in general, not required for stateless REST APIs that use POST, PUT, DELETE and\or PATCH
        http.csrf().disable();

        return http.build();
    }

    // This method initializes a Bean, when we run the app
//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager() {
//        System.out.println("Initializing Bean");
//        UserDetails john = User.builder()
//                .username("john")
//                .password("{noop}test123")
//                .roles("EMPLOYEE")
//                .build();
//
//        UserDetails mary = User.builder()
//                .username("mary")
//                .password("{noop}test123")
//                .roles("EMPLOYEE", "MANAGER")
//                .build();

//        var l = mary.getAuthorities();
//        for (var elem: l) {
//            System.out.println(elem.getAuthority());
//        }

//        UserDetails susan = User.builder()
//                .username("susan")
//                .password("{noop}test123")
//                .roles("EMPLOYEE", "MANAGER", "ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(john, mary, susan);
//    }
}

