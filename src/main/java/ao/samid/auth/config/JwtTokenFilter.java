package ao.samid.auth.config;

import ao.samid.auth.handler.CustomException;
import ao.samid.auth.handler.ErrorResponse;
import ao.samid.auth.repository.UserRepository;
import ao.samid.auth.service.CustomUserDetailedService;
import ao.samid.auth.service.JwtTokenService;
import ao.samid.auth.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter {
    private final JwtTokenService jwtTokenService;
    private final CustomUserDetailedService userService;
//    @SneakyThrows
    private String generateErrorMessage(String message, int code,String url) {;
        ErrorResponse errorResponse = ErrorResponse.builder()
                .message("Invalid token")
                .code(401)
                .url(url)
                .build();
        ObjectMapper objectMapper = new ObjectMapper();
       String jsonResponse = null;
        try {

             jsonResponse = objectMapper.writeValueAsString(errorResponse);

        } catch (IOException e) {;
            throw new CustomException("Error generating error message", 500);
        }
        return jsonResponse;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");
        String path = request.getRequestURI();
        if(path.equals("/api/v1/auth/login") || path.equals("/api/v1/auth/register")
                || path.equals("/api/v1/auth/refresh")
                || path.equals("/api/v1/auth/access")
                || path.equals("/api/v1/auth/logout")) {

            filterChain.doFilter(request, response);
        } else {
            if (authorization != null && authorization.startsWith("Bearer ")) {
                try {
                    String token = authorization.substring(7);
                    if (jwtTokenService.isValidAccessToken(token)) {
                        String usernameFromToken = jwtTokenService.getUsernameFromAccessToken(token);
                        UserDetails user = userService.loadUserByUsername(usernameFromToken);
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        filterChain.doFilter(request, response);
                    } else {
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        String mesaj = generateErrorMessage("Invalid token", 401, request.getRequestURL().toString() + "?" + request.getQueryString());
                        response.getWriter().write(mesaj);
                    }
                }catch (Exception e) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    String mesaj = generateErrorMessage(e.getMessage(), 401, request.getRequestURL().toString() + "?" + request.getQueryString());
                    response.getWriter().write(mesaj);
                }
            }
            else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                String mesaj=generateErrorMessage("Authorization header is missing or invalid", 401, request.getRequestURL().toString() + "?" + request.getQueryString());
                response.getWriter().write(mesaj);
            }
        }

    }
}