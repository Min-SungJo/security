package com.ride.security.service;

import com.ride.security.dto.ChangePasswordRequest;
import com.ride.security.entity.Member;
import com.ride.security.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    public void changePassword(ChangePasswordRequest request, Principal connectedMember) {
        var member = ((Member) ((UsernamePasswordAuthenticationToken) connectedMember).getPrincipal());

        //check if the current password os correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), member.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }

        member.setPassword(passwordEncoder.encode(request.getNewPassword()));
        memberRepository.save(member);
    }
}
