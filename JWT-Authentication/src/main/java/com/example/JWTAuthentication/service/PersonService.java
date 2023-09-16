package com.example.JWTAuthentication.service;

import com.example.JWTAuthentication.model.PersonDetails;
import com.example.JWTAuthentication.model.Persons;
import com.example.JWTAuthentication.repository.PersonRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class PersonService implements UserDetailsService {
    @Autowired
    private PersonRepository personRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Persons> person=personRepository.findByUsername(username);
        return person.map(PersonDetails::new).orElseThrow(()->new UsernameNotFoundException("Invalid username"));
    }
}
