package ao.samid.auth.dto.request;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class UserUpdateRequest implements Serializable {
    private Long id;
    private String username;
    private String email;
    private String oldPassword;
    private String password;
    private Long roleId;
}
