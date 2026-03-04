package com.example.backend.dto;

import com.example.backend.entity.WorkspaceRole;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class WorkspaceResponseDto {
  private Long workspaceId;
  private String workspaceName;
  private WorkspaceRole role;
  private Long membershipId;
}
