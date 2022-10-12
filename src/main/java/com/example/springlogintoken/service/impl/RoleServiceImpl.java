package com.example.springlogintoken.service.impl;

import com.example.springlogintoken.model.ERole;
import com.example.springlogintoken.model.Role;
import com.example.springlogintoken.repository.RoleRepository;
import com.example.springlogintoken.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

    @Override
    public Optional<Role> findByName(ERole eRole) {
        return roleRepository.findByName(eRole);
    }
}
