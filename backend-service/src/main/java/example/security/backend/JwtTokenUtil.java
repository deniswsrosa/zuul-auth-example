package example.security.backend;

import java.io.Serializable;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

@Component
public class JwtTokenUtil implements Serializable {

    private static final long serialVersionUID = -3301605591108950415L;

    public String getLoggedUser() {
        return getClaims().getSubject();
    }

    public String getClientId() {
        return (String) getClaims().get("clientId");
    }

    private Claims getClaims(){
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .getRequestAttributes()).getRequest();

        String token = request.getHeader("Authorization");

        if(token == null || token.trim().isEmpty()) {
            return null;
        }

        if (token != null && token.startsWith("Bearer" + " ")) {
            token = token.replace("Bearer" + " ", "");
        }

        return Jwts.parser()
                .setSigningKey("otherpeopledontknowit".getBytes())
                .parseClaimsJws(token)
                .getBody();
    }
}
