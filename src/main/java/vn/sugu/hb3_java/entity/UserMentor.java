package vn.sugu.hb3_java.entity;

import jakarta.persistence.*;
import lombok.*;
import java.util.Date;

@Entity
@Table(name = "user_mentors")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserMentor {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "mentor_id", nullable = false)
    private User mentor;

    @ManyToOne
    @JoinColumn(name = "member_id", nullable = false)
    private User member;

    private Date assignDate;
}
