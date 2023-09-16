package com.example.JWTAuthentication.repository;

import com.example.JWTAuthentication.model.Persons;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PersonRepository extends JpaRepository<Persons,Integer> {
    Optional<Persons> findByUsername(String username);
}
