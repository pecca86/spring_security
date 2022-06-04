package com.example.securitydemo.security;

import com.example.securitydemo.services.ApplicationUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity // Tells spring our security configs can be found here
@EnableGlobalMethodSecurity(prePostEnabled = true) // Lets us specify the authorities at method level inside the controller
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
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

    // These two methods need to be implemented in order for us to use our own UserDetailService
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);

        return provider;
    }

}
