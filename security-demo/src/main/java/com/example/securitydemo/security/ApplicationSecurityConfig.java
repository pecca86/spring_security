package com.example.securitydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity // Tells spring our security configs can be found here
@EnableGlobalMethodSecurity(prePostEnabled = true) // Lets us specify the authorities at method level inside the controller
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 1. Authorize requests
         * 2. Any request must be authenticated
         * 3. Use basic auth (i.e, pop-up alert windows and no logout functionality, every request needs to be authenticated)
         *
         * antMatchers + permitAll is a whitelist of resources that do not require authentication
         */
        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())// Configuring how the tokens are generated and saved, should be used when implementing HTML form!
//                .and()
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name()) // Only allow STUDENT roles to visit this endpoint
                // ORDER OF ANTMATCHERS MATTER!
//                .antMatchers(HttpMethod.DELETE, "/admin/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission()) // Anyone with given permission is able to access this endpoint
//                .antMatchers(HttpMethod.POST, "/admin/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission()) // Anyone with given permission is able to access this endpoint
//                .antMatchers(HttpMethod.PUT, "/admin/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission()) // Anyone with given permission is able to access this endpoint
//                .antMatchers("/admin/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
//                .httpBasic();
                .formLogin()
                    .loginPage("/login") // Custom login page
                    .permitAll()
                    .defaultSuccessUrl("/courses", true) // redirects to this page after logging in if set true
                    .passwordParameter("password") // Tells spring sec which html (name value) element to look for when password is provided
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // Default session expiration time to two weeks, requires checkbox with id and name of "remember-me"
                    .key("a_secure_key_used_creating_the_md5_hash_for_the_cookie_value")
                    .rememberMeParameter("remember-me")
                .and()
                .logout().logoutUrl("/logout")// LOGOUT LOGIC
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // This should be disabled if using csrf, the logout should be handled by a POST method in this case
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        /**
         * Specify how users are retrieved from the database
         */
        UserDetails anna = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("pass")) // Encode using bcrypt, spring sec requires encoding
//                .roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
                .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build();

        UserDetails admin = User.builder()
                .username("adde")
                .password(passwordEncoder.encode("admin"))
//                .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build();

        UserDetails trainee_admin = User.builder()
                .username("transu")
                .password(passwordEncoder.encode("admin"))
//                .roles(ApplicationUserRole.ADMIN_TRAINEE.name())
                .authorities(ApplicationUserRole.ADMIN_TRAINEE.getGrantedAuthorities())
                .build();

        // UserDetailsService is an interface which InMemoryUserDetailsManager implements
        return new InMemoryUserDetailsManager(
                anna,
                admin,
                trainee_admin
        );
    }

}
