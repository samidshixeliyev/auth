package ao.samid.auth.handler;

import lombok.Getter;

@Getter
public class UserNotFoundException extends RuntimeException {
    private final String message;
    private Integer code;
    public UserNotFoundException(String message) {
        super(message);
        this.message = message;
    }
    public UserNotFoundException(String message, Integer code) {
        super(message);
        this.message = message;
        this.code = code;
    }
    public static UserNotFoundException of(){
        return new UserNotFoundException("User not found", 404);
    }
}
