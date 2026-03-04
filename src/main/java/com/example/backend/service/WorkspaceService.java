package com.example.backend.service;

import com.example.backend.audit.AuditAction;
import com.example.backend.audit.AuditLogService;
import com.example.backend.domain.User;
import com.example.backend.dto.WorkspaceResponseDto;
import com.example.backend.entity.MembershipStatus;
import com.example.backend.entity.Workspace;
import com.example.backend.entity.WorkspaceMember;
import com.example.backend.entity.WorkspaceRole;
import com.example.backend.repository.UserRepository;
import com.example.backend.repository.WorkspaceMemberRepository;
import com.example.backend.repository.WorkspaceRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class WorkspaceService {

  private final WorkspaceRepository workspaceRepository;
  private final WorkspaceMemberRepository workspaceMemberRepository;
  private final UserRepository userRepository;
  private final AuditLogService auditLogService;

  @Transactional
  public Long createWorkspace(String name, String principal) {
    User user = findUserByPrincipal(principal);
    Workspace workspace = workspaceRepository.save(Workspace.builder().name(name).build());

    workspaceMemberRepository.save(
        WorkspaceMember.builder()
            .workspaceId(workspace.getId())
            .userId(user.getId())
            .role(WorkspaceRole.ADMIN)
            .status(MembershipStatus.ACCEPTED)
            .build());

    auditLogService.record(
        AuditAction.WORKSPACE_CREATE,
        "USER",
        user.getId().toString(),
        workspace.getId(),
        null,
        Map.of("workspaceName", name));

    return workspace.getId();
  }

  @Transactional(readOnly = true)
  public List<WorkspaceResponseDto> getPendingInvitations(String principal) {
    User user = findUserByPrincipal(principal);
    List<WorkspaceMember> members =
        workspaceMemberRepository.findAllByUserIdAndStatus(user.getId(), MembershipStatus.PENDING);

    return members.stream()
        .map(
            m -> {
              Workspace ws =
                  workspaceRepository
                      .findById(m.getWorkspaceId())
                      .orElseThrow(() -> new RuntimeException("WORKSPACE_NOT_FOUND"));
              return WorkspaceResponseDto.builder()
                  .workspaceId(ws.getId())
                  .workspaceName(ws.getName())
                  .role(m.getRole())
                  .membershipId(m.getId())
                  .build();
            })
        .collect(Collectors.toList());
  }

  @Transactional
  public void inviteByEmail(Long workspaceId, String email, String adminPrincipal) {
    validateAdmin(workspaceId, adminPrincipal);
    User invitee =
        userRepository
            .findByEmail(email)
            .orElseThrow(() -> new RuntimeException("INVITEE_NOT_FOUND"));

    workspaceMemberRepository
        .findByWorkspaceIdAndUserId(workspaceId, invitee.getId())
        .ifPresent(
            m -> {
              throw new RuntimeException("ALREADY_INVITED_OR_MEMBER");
            });

    workspaceMemberRepository.save(
        WorkspaceMember.builder()
            .workspaceId(workspaceId)
            .userId(invitee.getId())
            .role(WorkspaceRole.MEMBER)
            .status(MembershipStatus.PENDING)
            .build());

    auditLogService.record(
        AuditAction.MEMBER_JOIN_REQUEST,
        "USER",
        adminPrincipal,
        workspaceId,
        null,
        Map.of("invitedEmail", email));
  }

  @Transactional
  public void acceptInvitation(Long membershipId) {
    WorkspaceMember member =
        workspaceMemberRepository
            .findById(membershipId)
            .orElseThrow(() -> new RuntimeException("INVITATION_NOT_FOUND"));
    member.updateStatus(MembershipStatus.ACCEPTED);
  }

  @Transactional(readOnly = true)
  public List<WorkspaceResponseDto> getMyWorkspaces(String principal) {
    User user = findUserByPrincipal(principal);
    List<WorkspaceMember> members =
        workspaceMemberRepository.findAllByUserIdAndStatus(user.getId(), MembershipStatus.ACCEPTED);

    return members.stream()
        .map(
            m -> {
              Workspace ws =
                  workspaceRepository
                      .findById(m.getWorkspaceId())
                      .orElseThrow(() -> new RuntimeException("WORKSPACE_NOT_FOUND"));
              return WorkspaceResponseDto.builder()
                  .workspaceId(ws.getId())
                  .workspaceName(ws.getName())
                  .role(m.getRole())
                  .membershipId(m.getId())
                  .build();
            })
        .collect(Collectors.toList());
  }

  private void validateAdmin(Long workspaceId, String principal) {
    User user = findUserByPrincipal(principal);
    WorkspaceMember requester =
        workspaceMemberRepository
            .findByWorkspaceIdAndUserId(workspaceId, user.getId())
            .orElseThrow(() -> new RuntimeException("NOT_A_MEMBER"));
    if (requester.getRole() != WorkspaceRole.ADMIN) {
      throw new RuntimeException("ADMIN_ONLY");
    }
  }

  private User findUserByPrincipal(String principal) {
    return userRepository
        .findByEmail(principal)
        .orElseGet(
            () ->
                userRepository.findAll().stream()
                    .filter(u -> principal.equals(u.getProviderId()))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("USER_NOT_FOUND")));
  }
}
