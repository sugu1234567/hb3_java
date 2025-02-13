package vn.sugu.hb3_java.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Data
@FieldDefaults(level = AccessLevel.PRIVATE)
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class AuthenticationRequest {
    @NotBlank(message = "LOGIN_VALID")
    String username;
    @NotBlank(message = "LOGIN_VALID")
    String password;
}
