"""Test EFS filesystem and access point management"""

import pytest
from datetime import datetime


@pytest.mark.integration
def test_create_efs_filesystem(efs_client):
    """Test EFS filesystem creation with encryption"""
    creation_token = f'test-fs-{int(datetime.now().timestamp())}'

    response = efs_client.create_file_system(
        CreationToken=creation_token,
        PerformanceMode='generalPurpose',
        Encrypted=True,
        Tags=[
            {'Key': 'Name', 'Value': 'test-filesystem'},
            {'Key': 'Environment', 'Value': 'test'}
        ]
    )

    filesystem_id = response['FileSystemId']
    assert response['Encrypted'] is True
    assert response['PerformanceMode'] == 'generalPurpose'

    # Wait for filesystem to become available
    waiter = efs_client.get_waiter('file_system_available')
    waiter.wait(FileSystemId=filesystem_id)

    # Verify filesystem exists
    filesystems = efs_client.describe_file_systems(FileSystemId=filesystem_id)
    assert filesystems['FileSystems'][0]['FileSystemId'] == filesystem_id

    # Cleanup
    efs_client.delete_file_system(FileSystemId=filesystem_id)


@pytest.mark.integration
def test_create_access_point_with_posix_user(test_efs, efs_client):
    """Test EFS access point creation with POSIX user configuration"""
    cluster_id = 'rosa-dev'
    investigation_id = f'inv-{int(datetime.now().timestamp())}'
    owner_sub = 'test-user-123'

    response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={
            'Uid': 1000,
            'Gid': 1000
        },
        RootDirectory={
            'Path': f'/{cluster_id}/{investigation_id}',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        },
        Tags=[
            {'Key': 'Name', 'Value': f'{cluster_id}-{investigation_id}'},
            {'Key': 'ClusterID', 'Value': cluster_id},
            {'Key': 'InvestigationID', 'Value': investigation_id},
            {'Key': 'OwnerSub', 'Value': owner_sub}
        ]
    )

    access_point_id = response['AccessPointId']
    assert response['PosixUser']['Uid'] == 1000
    assert response['PosixUser']['Gid'] == 1000
    assert response['RootDirectory']['Path'] == f'/{cluster_id}/{investigation_id}'

    # Verify access point
    access_points = efs_client.describe_access_points(AccessPointId=access_point_id)
    ap = access_points['AccessPoints'][0]

    assert ap['AccessPointId'] == access_point_id
    assert ap['FileSystemId'] == test_efs

    # Verify tags
    tag_dict = {t['Key']: t['Value'] for t in ap['Tags']}
    assert tag_dict['ClusterID'] == cluster_id
    assert tag_dict['InvestigationID'] == investigation_id
    assert tag_dict['OwnerSub'] == owner_sub

    # Cleanup
    efs_client.delete_access_point(AccessPointId=access_point_id)


@pytest.mark.integration
def test_access_point_lifecycle(test_efs, efs_client):
    """Test access point creation and deletion"""
    # Create access point
    response = efs_client.create_access_point(
        FileSystemId=test_efs,
        PosixUser={'Uid': 1000, 'Gid': 1000},
        RootDirectory={
            'Path': '/test-lifecycle',
            'CreationInfo': {
                'OwnerUid': 1000,
                'OwnerGid': 1000,
                'Permissions': '0755'
            }
        }
    )

    access_point_id = response['AccessPointId']

    # List access points for filesystem
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids = [ap['AccessPointId'] for ap in access_points['AccessPoints']]
    assert access_point_id in ap_ids

    # Delete access point
    efs_client.delete_access_point(AccessPointId=access_point_id)

    # Verify deletion
    access_points_after = efs_client.describe_access_points(FileSystemId=test_efs)
    ap_ids_after = [ap['AccessPointId'] for ap in access_points_after['AccessPoints']]
    assert access_point_id not in ap_ids_after


@pytest.mark.integration
def test_multiple_access_points_per_filesystem(test_efs, efs_client):
    """Test creating multiple access points on same filesystem"""
    access_point_ids = []

    # Create 3 access points
    for i in range(3):
        response = efs_client.create_access_point(
            FileSystemId=test_efs,
            PosixUser={'Uid': 1000, 'Gid': 1000},
            RootDirectory={
                'Path': f'/investigation-{i}',
                'CreationInfo': {
                    'OwnerUid': 1000,
                    'OwnerGid': 1000,
                    'Permissions': '0755'
                }
            },
            Tags=[{'Key': 'Index', 'Value': str(i)}]
        )
        access_point_ids.append(response['AccessPointId'])

    # Verify all access points exist
    access_points = efs_client.describe_access_points(FileSystemId=test_efs)
    assert len(access_points['AccessPoints']) == 3

    # Cleanup all access points
    for ap_id in access_point_ids:
        efs_client.delete_access_point(AccessPointId=ap_id)

    # Verify all deleted
    access_points_after = efs_client.describe_access_points(FileSystemId=test_efs)
    assert len(access_points_after['AccessPoints']) == 0
