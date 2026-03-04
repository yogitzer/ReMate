package com.example.backend.controller;

import com.example.backend.dto.WorkspaceResponseDto;
import com.example.backend.global.common.ApiResponse;
import com.example.backend.service.WorkspaceService;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/workspaces")
@RequiredArgsConstructor
public class WorkspaceController {

  private final WorkspaceService workspaceService;

  @GetMapping("/entry-check")
  public ResponseEntity<ApiResponse<Map<String, Object>>> checkEntry(Principal principal) {
    List<WorkspaceResponseDto> workspaces = workspaceService.getMyWorkspaces(principal.getName());
    return ResponseEntity.ok(ApiResponse.ok(Map.of("workspaceCount", workspaces.size())));
  }

  @PostMapping
  public ResponseEntity<ApiResponse<Long>> createWorkspace(
      @RequestParam String name, Principal principal) {
    return ResponseEntity.ok(
        ApiResponse.ok(workspaceService.createWorkspace(name, principal.getName())));
  }

  @PostMapping("/{workspaceId}/invite")
  public ResponseEntity<ApiResponse<Void>> invite(
      @PathVariable Long workspaceId, @RequestParam String email, Principal principal) {
    workspaceService.inviteByEmail(workspaceId, email, principal.getName());
    return ResponseEntity.ok(ApiResponse.ok());
  }

  @GetMapping("/invitations")
  public ResponseEntity<ApiResponse<List<WorkspaceResponseDto>>> getInvitations(
      Principal principal) {
    return ResponseEntity.ok(
        ApiResponse.ok(workspaceService.getPendingInvitations(principal.getName())));
  }

  @PostMapping("/invitations/{membershipId}/accept")
  public ResponseEntity<ApiResponse<Void>> accept(@PathVariable Long membershipId) {
    workspaceService.acceptInvitation(membershipId);
    return ResponseEntity.ok(ApiResponse.ok());
  }

  @GetMapping("/my")
  public ResponseEntity<ApiResponse<List<WorkspaceResponseDto>>> getMyWorkspaces(
      Principal principal) {
    return ResponseEntity.ok(ApiResponse.ok(workspaceService.getMyWorkspaces(principal.getName())));
  }
}
