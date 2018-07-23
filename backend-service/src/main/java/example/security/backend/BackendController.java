package example.security.backend;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

/**
 * A simple controller.
 *
 */
@RestController
public class BackendController {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @GetMapping("/admin")
    public String admin() {
        return "Hello Admin!";
    }

    @GetMapping("/user")
    public String user() {
        return "Hello there! your username is "+jwtTokenUtil.getLoggedUser()+" from tenant "+jwtTokenUtil.getClientId() ;
    }

    @GetMapping("/guest")
    public String guest() {
        return "Hello Guest!";
    }
}

