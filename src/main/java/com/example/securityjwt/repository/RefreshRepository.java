package com.example.securityjwt.repository;

import com.example.securityjwt.entity.RefreshEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface RefreshRepository extends JpaRepository<RefreshEntity, Long> {

    Boolean existsByRefreshToken(String refreshToken);

    @Transactional
    void deleteByRefreshToken(String refreshToken);

    @Query("select r from RefreshEntity  r where r.refreshToken = :refreshToken")
    RefreshEntity findByRefresh(@Param("refreshToken") String refreshToken);
}
