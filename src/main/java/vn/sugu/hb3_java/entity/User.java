package vn.sugu.hb3_java.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import vn.sugu.hb3_java.enums.UserRole;

import java.util.Date;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    UserRole role;

    String accountCode;
    String name;
    String password;
    String email;
    Date dateOfBirth;
    Date dateOfBirthLunar;
    String avatarUrl;
    String department;
    String level;
    String gender;
    String phone;
    String maritalStatus;
    Date workingStartDate;
    Integer workingStartYear;
    String fiveElements;

    @Column(columnDefinition = "MEDIUMTEXT")
    String accessToken;

    @Column(columnDefinition = "MEDIUMTEXT")
    String refreshToken;

    @Column(columnDefinition = "MEDIUMTEXT")
    String resetPasswordToken;

    @OneToMany(mappedBy = "mentor")
    List<UserMentor> mentors;

    @OneToMany(mappedBy = "member")
    List<UserMentor> member;
}
