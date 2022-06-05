package com.example.securitydemo.services;

import com.example.securitydemo.auth.ApplicationUser;
import com.example.securitydemo.dao.ApplicationUserDAO;
import com.example.securitydemo.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDAO {

    private final PasswordEncoder passwordEncoder;


    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String userName) {
        return getApplicationUsers()
                .stream()
                .filter(appUser -> userName.equals(appUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUserList = Lists.newArrayList(
            new ApplicationUser(
                    ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                    passwordEncoder.encode("password"),
                    "pekka",
                    true,
                    true,
                    true,
                    true
            ),
                new ApplicationUser(
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("admin"),
                        "adde",
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser(
                        ApplicationUserRole.ADMIN_TRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("adminpass"),
                        "kekka",
                        true,
                        true,
                        true,
                        true
                )
        );

        return applicationUserList;
    }
}
