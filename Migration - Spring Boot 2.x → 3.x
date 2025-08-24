Migration - Spring Boot 2.x → 3.x
====================================
# Create a migration branch in GitHub
-> Spring Boot 2.7.x and fix deprecations first. 
-> Boot 3.x requires Java 17+ 

Maven (pom.xml)

<parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>3.5.5</version>
  <relativePath/> 
</parent>

<properties>
  <java.version>17</java.version>
</properties>


# Switch from javax.* → jakarta.*  Boot 3 / Framework 6 adopt Jakarta EE 9+ packages.
======================================================================================
-> Run a code rewrite before you touch anything by hand:
-> Jakarta (javax→jakarta) -> These refactor imports, annotations and common APIs.
-> javax.validation.* → jakarta.validation.*
-> javax.persistence.* → jakarta.persistence.*
-> javax.servlet.* → jakarta.servlet.*
-> javax.transaction.Transactional → jakarta.transaction.Transactional

// before
import javax.validation.Valid;
import javax.persistence.Entity;
import javax.transaction.Transactional;

// after
import jakarta.validation.Valid;
import jakarta.persistence.Entity;
import jakarta.transaction.Transactional;


# Security (Spring Security 6)
================================
-> Replace WebSecurityConfigurerAdapter with a SecurityFilterChain bean.
-> antMatchers(...) → requestMatchers(...).
-> Prefer @EnableMethodSecurity over @EnableGlobalMethodSecurity.

@Bean
SecurityFilterChain security(HttpSecurity http) throws Exception {
  http
    .authorizeHttpRequests(reg -> reg
      .requestMatchers("/public/**").permitAll()
      .anyRequest().authenticated())
    .httpBasic(Customizer.withDefaults());
  return http.build();
}

# Data & JPA (Hibernate 6)
===========================
Verify custom Dialect class names (some changed) and remove legacy ones when auto-detection suffices.
Revisit HQL/Criteria queries if you relied on deprecated behavior.
Review Hibernate’s migration notes if you hit query issues. 
Stack Overflow

# HTTP clients & Web
======================
-> If you were explicitly using Apache HttpClient 4 with RestTemplate, move to HttpClient 5 (groupId changed). 
-> Trailing slash matching is off by default. /foo no longer matches /foo/; add explicit mappings or opt back in globally while you transition.

# Actuator, metrics & tracing
==============================
-> Actuator httptrace → httpexchanges (name and payload changed). Update any dashboards or scrapers.
-> Only health is exposed over JMX by default now; configure exposure as needed. 
-> Observability: Boot 3 uses Micrometer Observation/Tracing (replacement for Spring Cloud Sleuth). If you previously used Sleuth, adopt Micrometer Tracing starters. 
-> Baeldung on Kotlin

# Logging
==========
-> Boot 3 aligns log timestamps with ISO-8601 by default (e.g., 2025-08-23T12:34:56.789+05:30). 
-> You can restore the old pattern with logging.pattern.dateformat. 
-> SLF4J 2.0 is the baseline—update any custom bridges/bindings if pinned.
-> Library auto-config discovery uses AutoConfiguration.imports (not spring.factories)—only relevant if you maintain starters.

# Replace incompatible libraries - Swagger
===========================================
-> Swagger/Springfox → springdoc-openapi 2.x (built for Spring Boot 3/Jakarta). 
docs.openrewrite.org
-> Verify JDBC drivers and any EE-related libs are Jakarta compatible.

<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-properties-migrator</artifactId>
  <scope>runtime</scope>
</dependency>
           
# Rebuild, test, and verify
=============================
-> Clean build on Java 17+: mvn -U -DskipTests=false clean verify.
-> Run the app with --debug, hit all critical endpoints, and check logs for property warnings and actuator availability.
-> Security: remove WebSecurityConfigurerAdapter, add a SecurityFilterChain bean (see Step 4). 
-> Jakarta: change javax.* imports to jakarta.*. 
-> Actuator: replace httptrace with httpexchanges. 
-> HttpClient: if using Apache client 4, move to client 5. 
-> OpenAPI: swap Springfox for springdoc-openapi 2.x. docs.openrewrite.org
-> Logging: expect ISO-8601 timestamps by default.

# Suggested migration workflow (what to run)
============================================
Upgrade build to Boot 3.x and Java 17+. 
Run OpenRewrite recipes (Jakarta + Boot 3).
Fix compiler errors (mostly import/package moves).
Replace Security config, then run tests. 
Fix config keys using the properties migrator, then remove it. 
Smoke test your APIs & actuator, verify metrics/tracing.
===========================================================

# Swagger → springdoc migration (Spring Boot 3)
===============================================
<dependency>
  <groupId>io.springfox</groupId>
  <artifactId>springfox-boot-starter</artifactId>
  <version>3.x</version>
</dependency>

# Check the default Swagger UI path
====================================
-> Springfox UI → /swagger-ui.html
-> Springdoc UI → /swagger-ui.html (or /swagger-ui/index.html)
-> OpenAPI JSON → /v3/api-docs

http://localhost:8080/swagger-ui/index.html
http://localhost:8080/v3/api-docs

# Replace Docket with OpenAPI bean
===================================
Before (Springfox):

@Bean
public Docket api() {
    return new Docket(DocumentationType.SWAGGER_2)
            .select()
            .apis(RequestHandlerSelectors.basePackage("com.example"))
            .paths(PathSelectors.any())
            .build()
            .apiInfo(new ApiInfo(
                "My API",
                "Description",
                "1.0",
                "Terms of service",
                new Contact("Me", "url", "me@email.com"),
                "License",
                "License URL",
                Collections.emptyList()
            ));
}

After (Springdoc):

@Bean
public OpenAPI customOpenAPI() {
    return new OpenAPI()
        .info(new Info()
            .title("My API")
            .version("1.0")
            .description("Description")
            .contact(new Contact()
                .name("Me")
                .url("url")
                .email("me@email.com"))
            .license(new License()
                .name("License")
                .url("License URL")));
}

# Update annotations
=====================
-> Swagger annotations from io.swagger.v3.oas.annotations.* (not Springfox’s).
@ApiOperation → @Operation
@ApiParam → @Parameter
@ApiModel → @Schema

@Operation(summary = "Get user by ID")
@GetMapping("/users/{id}")
public User getUser(@Parameter(description = "User ID") @PathVariable Long id) {
    return service.getUser(id);
}

# Test & verify
================
Rebuild and run on Spring Boot 3.
Visit /swagger-ui.html or /swagger-ui/index.html.
Validate JSON at /v3/api-docs.
=======================================================================================================

Spring Security Migration (Boot 2 → Boot 3)
=============================================
# Remove WebSecurityConfigurerAdapter
Before (Boot 2.x):

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
          .authorizeRequests()
            .antMatchers("/public/**").permitAll()
            .anyRequest().authenticated()
          .and()
          .formLogin();
    }
}

After (Boot 3.x):

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
          .formLogin(Customizer.withDefaults());
        return http.build();
    }
}

# Replace 
==========
-> antMatchers → requestMatchers
-> authorizeRequests() → authorizeHttpRequests()
-> antMatchers(...) → requestMatchers(...)

# Password encoding
====================
@Bean
PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}

# Method security
==================
-> @EnableGlobalMethodSecurity → @EnableMethodSecurity
-> prePostEnabled = true (default is true now).
-> securedEnabled = true if you use @Secured.
-> jsr250Enabled = true if you use @RolesAllowed.

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class MethodSecurityConfig {
}

# UserDetailsService bean
===========================
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("user").password("{noop}password").roles("USER");
}

After: 

@Bean
UserDetailsService userDetailsService(PasswordEncoder encoder) {
    UserDetails user = User.withUsername("user")
        .password(encoder.encode("password"))
        .roles("USER")
        .build();
    return new InMemoryUserDetailsManager(user);
}

# AuthenticationManager changes
================================
@Bean
AuthenticationManager authenticationManager(
        AuthenticationConfiguration configuration) throws Exception {
    return configuration.getAuthenticationManager();
}

# OAuth2 / JWT
===============
Token validation config now uses DSL style.
@Bean
SecurityFilterChain apiSecurity(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(auth -> auth
          .requestMatchers("/api/public/**").permitAll()
          .anyRequest().authenticated()
      )
      .oauth2ResourceServer(oauth2 -> oauth2.jwt());
    return http.build();
}

# Dispatcher types
===================
-> spring.security.filter.dispatcher-types=request,async,error


# Migration Checklist
====================
-> Remove WebSecurityConfigurerAdapter
-> Replace antMatchers → requestMatchers
-> Expose SecurityFilterChain bean(s)
-> Add PasswordEncoder bean
-> Update method security → @EnableMethodSecurity
-> Refactor UserDetailsService setup
=======================================================================================


