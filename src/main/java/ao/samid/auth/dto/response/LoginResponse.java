package ao.samid.auth.dto.response;

import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class LoginResponse implements Serializable {
    private String accessToken;
    private String refreshToken;
}
