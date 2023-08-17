---
replicaCount: 3

imagePullSecrets:
- name: docker-registry

image:
  repository: ${docker_repository}
  name: terraform-enterprise
  tag: ${docker_image_tag}
  pullSecret: docker-registry
  pullPolicy: Always

resources:
  requests:
    memory: "2500Mi"
    cpu: "750m"
  # limits:
  #   memory: "7500Mi"
  #   cpu: "4000m"

ssl:
  secretName: terraform-enterprise-certificates

tls:
  certificateSecret: terraform-enterprise-certificates
  certData: ${tls_crt_data}
  keyData: ${tls_key_data}
  certMountPath: /etc/ssl/private/terraform-enterprise/cert.pem
  keyMountPath: /etc/ssl/private/terraform-enterprise/key.pem

tfe:
  privateHttpPort: 8080
  privateHttpsPort: 8443 

pod:
  annotations: {}

nodeSelector: {}

tolerations: []

affinity: {}

# In the docker image TFE user id is 1000 and name is terraform-enterprise
# TFE user group is 0
# Manual: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
securityContext:
  runAsNonRoot: false
  runAsUser: 1000
  runAsGroup: 0
  fsGroup: 0

initContainers: null

ingress:
  enabled: false
  className: nginx
  annotations: 
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    # kubernetes.io/ingress.class: nginx
    # kubernetes.io/tls-acme: "true"
  hosts:
    - host: ${hostname}
      paths:
        - path: /
          pathType: Prefix
          serviceName: "terraform-enterprise"
          portNumber: 443
  tls: 
     - secretName: terraform-enterprise-certificates
       hosts:
       - ${hostname} 

service:
  annotations: {}
    # cloud.google.com/neg: '{"ingress": true}'
  type: LoadBalancer
  port: 443
  nodePort: 32443 # if service.type is NodePort value will be set

rbac:
  create: true

serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "${tfe_s3_role_arn}"
  name: ""
  # The name of the service account to use.
  # If not set and create is true, a name is generated using the fullname template

env:
  variables:
    TFE_HOSTNAME: ${hostname}
    TFE_OPERATIONAL_MODE: active-active
    TFE_DISK_CACHE_VOLUME_NAME: $${COMPOSE_PROJECT_NAME}_terraform-enterprise-cache
    TFE_TLS_VERSION: ${tfe_tls_version}
    TFE_TLS_ENFORCE: true
    TFE_DATABASE_USER: ${pg_user}
    TFE_DATABASE_HOST: ${pg_netloc}
    TFE_DATABASE_NAME: ${pg_dbname}
    TFE_DATABASE_PARAMETERS: sslmode=require
    TFE_OBJECT_STORAGE_TYPE: s3
    TFE_OBJECT_STORAGE_S3_USE_INSTANCE_PROFILE: true
    TFE_OBJECT_STORAGE_S3_REGION: ${region}
    TFE_OBJECT_STORAGE_S3_BUCKET: ${s3_bucket}
    TFE_OBJECT_STORAGE_S3_SERVER_SIDE_ENCRYPTION: AES256
    TFE_METRICS_ENABLE: false
    TFE_REDIS_HOST: ${redis_host}:6380
    TFE_REDIS_USE_AUTH: true
    TFE_REDIS_USE_TLS: true
    TZ: Europe/Amsterdam
  secrets:
    TFE_LICENSE: ${license_data}
    TFE_ENCRYPTION_PASSWORD: ${enc_password}
    TFE_IACT_TOKEN: ${user_token}
    TFE_DATABASE_PASSWORD: ${pg_password}
    TFE_REDIS_PASSWORD: ${redis_pass}

# Variables configuration reference https://developer.hashicorp.com/terraform/enterprise/flexible-deployments-beta/install/configuration
