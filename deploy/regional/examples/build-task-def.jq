# jq script to build investigation-specific task definition
# Usage: BASE_TASK_JSON | jq -f build-task-def.jq --arg ...

.containerDefinitions[0].environment += [
  {name: "CLUSTER_ID", value: $cluster_id},
  {name: "INVESTIGATION_ID", value: $investigation},
  {name: "OC_VERSION", value: $oc_version},
  {name: "S3_AUDIT_BUCKET", value: $bucket},
  {name: "TASK_TIMEOUT", value: $task_timeout}
] |

{
  family: $family,
  taskRoleArn: $task_role,
  executionRoleArn: $exec_role,
  networkMode: .networkMode,
  requiresCompatibilities: .requiresCompatibilities,
  cpu: .cpu,
  memory: .memory,
  containerDefinitions: [.containerDefinitions[0]],
  volumes: [{
    name: "sre-home",
    efsVolumeConfiguration: {
      fileSystemId: $efs_id,
      transitEncryption: "ENABLED",
      authorizationConfig: {
        accessPointId: $access_point,
        iam: "ENABLED"
      }
    }
  }]
}
