package com.exam.service.impl;

import com.exam.model.Role;
import com.exam.repo.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

//  created by smh

@Service
public class RoleService {

    @Autowired
    private RoleRepository roleRepository;
    public Role saveCrediantial(Role role){
        return roleRepository.save(role);
    }
}
