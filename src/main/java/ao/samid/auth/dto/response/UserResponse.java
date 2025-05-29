package ao.samid.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.util.List;
import java.util.Set;

@Data
@Builder
public class UserResponse implements Serializable {
    private Long id;
    private String username;
    private String email;
    private Set<RoleResponse> roles;
}
