package vn.sugu.hb3_java.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Date;
import java.util.List;

@Entity
@Table(name = "projects")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)

public class Project {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    String name;
    Integer rank;
    Date startDate;
    Date endDate;
    String customerName;
    String descriptions;

    @OneToMany(mappedBy = "project")
    List<UserProject> userProjects;
}