package com.example.springlogintoken.controller;

import com.example.springlogintoken.exception.TokenRefreshException;
import com.example.springlogintoken.model.ERole;
import com.example.springlogintoken.model.RefreshToken;
import com.example.springlogintoken.model.Role;
import com.example.springlogintoken.model.User;
import com.example.springlogintoken.payload.request.LoginRequest;
import com.example.springlogintoken.payload.request.SignupRequest;
import com.example.springlogintoken.payload.request.TokenRefreshRequest;
import com.example.springlogintoken.payload.response.JwtResponse;
import com.example.springlogintoken.payload.response.MessageResponse;
import com.example.springlogintoken.payload.response.TokenRefreshResponse;
import com.example.springlogintoken.security.jwt.JwtUtils;
import com.example.springlogintoken.security.service.UserDetailsImpl;
import com.example.springlogintoken.service.impl.RefreshTokenServiceImpl;
import com.example.springlogintoken.service.impl.RoleServiceImpl;
import com.example.springlogintoken.service.impl.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;

    private final UserServiceImpl userService;

    private final RoleServiceImpl roleService;
    private final PasswordEncoder encoder;

    private final JwtUtils jwtUtils;

    private final RefreshTokenServiceImpl refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<Object> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                        loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtTokenWithAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return ResponseEntity.ok(new JwtResponse(
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles,
                jwt,
                refreshToken.getToken()));
    }


    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(requestRefreshToken,
                        "Refresh token is not in database!"));
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userService.existByUserName(signupRequest.getUsername())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Username is taken!"));
        }

        if (userService.existByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = new User();
        user.setUsername(signupRequest.getUsername());
        user.setEmail(signupRequest.getEmail());
        user.setPassword(encoder.encode(signupRequest.getPassword()));

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        String error = "Error: Role is not found.";

        if (strRoles == null) {
            Role userRole = roleService.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException(error));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleService.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException(error));

                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleService.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException(error));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleService.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException(error));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userService.saveUser(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}
