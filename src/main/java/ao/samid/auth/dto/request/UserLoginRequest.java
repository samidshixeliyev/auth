package ao.samid.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class UserLoginRequest implements Serializable {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
