package ao.samid.auth.dto.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ChangePasswordRequest {
    private Long userId;
    private String oldPassword;
    private String newPassword;
}
