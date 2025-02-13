package vn.sugu.hb3_java.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import vn.sugu.hb3_java.enums.UserProjectRole;

@Entity
@Table(name = "user_projects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)

public class UserProject {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    User user;

    @ManyToOne
    @JoinColumn(name = "project_id", nullable = false)
    Project project;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    UserProjectRole role;

    String note;
}
