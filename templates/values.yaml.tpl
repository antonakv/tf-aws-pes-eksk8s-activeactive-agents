---
replicaCount: 1

imagePullSecrets:
- name: docker-registry

image:
  repository: quay.io
  name: hashicorp/terraform-enterprise
  tag: ${tfe_quaiio_tag}
  pullSecret: docker-registry
  pullPolicy: Always

resources:
  requests:
    memory: "2500Mi"
    cpu: "750m"
  limits:
    memory: "7500Mi"
    cpu: "4000m"

ssl:
  secretName: terraform-enterprise-certificates

tls:
  certData: ${tls_crt_data}
  keyData: ${tls_key_data}

env:
  TFE_HOSTNAME: ${hostname}
  TFE_OPERATIONAL_MODE: "active-active"
  TFE_ENCRYPTION_PASSWORD: ${enc_password}
  TFE_IACT_TOKEN: ${user_token}
  TFE_DISK_CACHE_VOLUME_NAME: $${COMPOSE_PROJECT_NAME}_terraform-enterprise-cache
#  TFE_TLS_CERT_FILE: /etc/ssl/private/terraform-enterprise/certificate.pem
#  TFE_TLS_KEY_FILE: /etc/ssl/private/terraform-enterprise/key.pem
#  TFE_TLS_CA_BUNDLE_FILE: /etc/ssl/private/terraform-enterprise/chain.pem
  TFE_TLS_VERSION: ${tfe_tls_version}
  TFE_TLS_ENFORCE: true
  TFE_DATABASE_USER: ${pg_user}
  TFE_DATABASE_PASSWORD: ${pg_password}
  TFE_DATABASE_HOST: ${pg_netloc}
  TFE_DATABASE_NAME: ${pg_dbname}
  TFE_DATABASE_PARAMETERS: sslmode=require
  TFE_OBJECT_STORAGE_TYPE: s3
  TFE_OBJECT_STORAGE_S3_USE_INSTANCE_PROFILE: true
  TFE_OBJECT_STORAGE_S3_REGION: ${region}
  TFE_OBJECT_STORAGE_S3_BUCKET: ${s3_bucket}
  TFE_OBJECT_STORAGE_S3_SERVER_SIDE_ENCRYPTION: AES256
  TFE_LICENSE: ${license_data}
  TFE_METRICS_ENABLE: false
  TFE_REDIS_PASSWORD: ${redis_pass}
  TFE_REDIS_HOST: ${redis_host}:6380
  TFE_REDIS_USE_AUTH: true
  TFE_REDIS_USE_TLS: true
