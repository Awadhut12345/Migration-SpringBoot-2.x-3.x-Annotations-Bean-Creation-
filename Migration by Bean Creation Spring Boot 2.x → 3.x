# Migration by Bean Creation Spring Boot 2.x → 3.x
===================================================

# Spring Security Migration by Bean Creation
 ===========================================
# SecurityFilterChain Bean

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}

# PasswordEncoder Bean
=======================
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

# UserDetailsService Bean
==========================
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

# AuthenticationManager Bean 
=============================
@Bean
AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
}

# Method Security Bean
=======================
@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class MethodSecurityConfig {
}


# Minimal Complete Example (All Beans)
=======================================
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults());
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

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
=======================================================================
