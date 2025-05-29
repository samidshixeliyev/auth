package ao.samid.auth.handler;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class CustomException extends RuntimeException {
    private String message;
    private int code;
    public CustomException(String message) {
        super(message);
    }
}
