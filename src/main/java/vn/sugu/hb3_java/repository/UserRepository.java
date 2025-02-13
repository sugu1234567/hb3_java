package vn.sugu.hb3_java.repository;

import vn.sugu.hb3_java.entity.User;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByName(String name);

    Optional<User> findByName(String name);

    Optional<User> findByEmail(String email);
}
