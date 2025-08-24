# Migration using Annotations Spring Boot 2.x → 3.x
====================================================
# Enable Web Security
======================
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // Security beans go here
}

# Replace 
==========
-> @EnableGlobalMethodSecurity → @EnableMethodSecurity
-> Before (Boot 2.x / Security 5):

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfig {
}

# Use Method-Level Annotations
===============================
Pre/Post annotations (default on):
==================================
@PreAuthorize("hasRole('ADMIN')")
@PostAuthorize("returnObject.owner == authentication.name")
JSR-250 annotations (if jsr250Enabled = true):
@RolesAlowed("ADMIN")
Spring’s @Secured (if securedEnabled = true):
@Secured("ROLE_USER")


# Security Configuration with Annotations + Beans
===================================================
Role-based access using annotations + form login
=================================================
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder encoder) {
        UserDetails user = User.withUsername("user")
            .password(encoder.encode("password"))
            .roles("USER")
            .build();

        UserDetails admin = User.withUsername("admin")
            .password(encoder.encode("admin"))
            .roles("ADMIN")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}

And then you secure endpoints like this:

@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userOnly() {
        return "User content";
    }

    @GetMapping("/admin")
    @RolesAllowed("ADMIN")
    public String adminOnly() {
        return "Admin content";
    }
}

# Migration Checklist (Annotations)
====================================
 Replace @EnableGlobalMethodSecurity → @EnableMethodSecurity
 Check securedEnabled and jsr250Enabled flags if you use @Secured or @RolesAllowed
 Update any deprecated antMatchers → requestMatchers in SecurityFilterChain bean
 Continue to use @PreAuthorize, @RolesAllowed, @Secured as before
=================================================================================
 
 # Classes & Annotations to Use in Spring Security 6 (Boot 3)
 =============================================================
# Configuration & Enable Annotations
@EnableWebSecurity → enables web security
@EnableMethodSecurity → replaces @EnableGlobalMethodSecurity

# Beans 
========
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { ... }

PasswordEncoder
================
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

UserDetailsService
===================
Defines where users come from (in-memory, JDBC, custom).

@Bean
UserDetailsService userDetailsService(PasswordEncoder encoder) {
    return new InMemoryUserDetailsManager(...);
}

AuthenticationManager
======================
@Bean
AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
}

# Supporting Classes
=====================
HttpSecurity → fluent API for configuring HTTP security
Customizer → provides Customizer.withDefaults() convenience
User, UserDetails, InMemoryUserDetailsManager → building/test users
AuthenticationConfiguration → used to retrieve AuthenticationManager

# Method Security Annotations
==============================
@PreAuthorize / @PostAuthorize (SpEL expressions)
@Secured("ROLE_X") (if securedEnabled = true)
@RolesAllowed("ROLE_X") (if jsr250Enabled = true)

# Package Changes to Remember
==============================
-> All these are now in org.springframework.security.* packages
org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
org.springframework.security.web.SecurityFilterChain
org.springframework.security.crypto.password.PasswordEncoder
org.springframework.security.core.userdetails.UserDetailsService

# Summary of classes you must use in Boot 3:
===============================================
Concern	Class/Annotation used in Boot 3
Enable web security	@EnableWebSecurity
Enable method security	@EnableMethodSecurity
HTTP security rules	SecurityFilterChain bean
Password encoding	PasswordEncoder (e.g., BCryptPasswordEncoder)
User management	UserDetailsService, User, InMemoryUserDetailsManager
Authentication manager	AuthenticationManager via AuthenticationConfiguration
Method-level protection	@PreAuthorize, @Secured, @RolesAllowed




