package ao.samid.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.Getter;

import java.io.Serializable;

@Data
public class UserRegisterRequest implements Serializable {
    @NotBlank
    private  String username;
    @NotBlank
    @Email
    private  String email;
    @NotBlank
    private  String password;
    @NotBlank
    private  String confirmPassword;
}
