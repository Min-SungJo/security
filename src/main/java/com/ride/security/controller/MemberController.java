package com.ride.security.controller;

import com.ride.security.dto.ChangePasswordRequest;
import com.ride.security.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/v1/members")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @PatchMapping
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request, Principal connectedMember) {
        memberService.changePassword(request, connectedMember);
        return ResponseEntity.ok().build();
    }
}
