package com.example.springlogintoken.service;

import com.example.springlogintoken.model.ERole;
import com.example.springlogintoken.model.Role;

import java.util.Optional;

public interface RoleService {
    Optional<Role> findByName(ERole eRole);
}
