package com.example.securityjwt.repository;

import com.example.securityjwt.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    Boolean existsByUsername(String username);

    //username을 통해서 회원 정보 조회
    UserEntity findByUsername(String username);
}
