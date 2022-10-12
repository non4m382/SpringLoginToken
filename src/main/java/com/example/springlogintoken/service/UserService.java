package com.example.springlogintoken.service;

import com.example.springlogintoken.model.User;

public interface UserService {
    boolean existByUserName(String username);

    boolean existByEmail(String email);

    User saveUser(User user);
}
