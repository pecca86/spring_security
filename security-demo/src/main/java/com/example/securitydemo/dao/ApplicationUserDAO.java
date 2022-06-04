package com.example.securitydemo.dao;

import com.example.securitydemo.auth.ApplicationUser;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import java.util.Optional;

public interface ApplicationUserDAO {

    public Optional<ApplicationUser> selectApplicationUserByUsername(String userName);
}
