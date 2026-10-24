// =============================================================================
// Jenkinsfile — n8n-custom-service (multi-microservice: git-sync-service & sharing-service).
// Flow: checkout -> lint + test + govulncheck (parallel) -> build & push to Harbor
//       -> on main: bump image.tag in helm-values platform-manifest.
//
// Same conventions as platform/portal-platform:
//  - environment-specific values come from Jenkins Global properties / JCasC;
//  - N8N_* / N8NGIT_* fallback to PORTAL_*;
//  - credentials are referenced by ID only.
// =============================================================================

def cfg = { String name, String fallback -> env."N8NGIT_${name}" ?: env."N8N_${name}" ?: env."PORTAL_${name}" ?: fallback }

def REGISTRY_URL            = cfg('REGISTRY_URL', 'TODO_REGISTRY_URL')                       // e.g. harbor.lab.local
def REGISTRY_CREDENTIALS_ID = cfg('REGISTRY_CREDENTIALS_ID', 'TODO_REGISTRY_CREDENTIALS_ID') // username/password (Harbor robot jenkins)
def IMAGE_PREFIX            = env.N8N_IMAGE_PREFIX ?: env.N8NGIT_IMAGE_PREFIX ?: 'n8n-custom-service'
def SERVICES                = ['git-sync-service', 'sharing-service', 'auth-service']
def AGENT_LABEL             = cfg('AGENT_LABEL', 'portal-build')
def BUILD_MODE              = cfg('BUILD_MODE', 'kaniko')                                   // 'kaniko' | 'docker'
def KANIKO_EXTRA_ARGS       = cfg('KANIKO_EXTRA_ARGS', '')

// Manifest bump
def MANIFEST_REPO_URL       = env.N8N_MANIFEST_REPO_URL ?: env.N8NGIT_MANIFEST_REPO_URL ?: 'git@github.com:Glhby13/helm-values-lab.git'
if (MANIFEST_REPO_URL == 'none') { MANIFEST_REPO_URL = '' }
def MANIFEST_BRANCH         = env.N8N_MANIFEST_BRANCH   ?: env.N8NGIT_MANIFEST_BRANCH   ?: 'main'
def MANIFEST_PATH           = env.N8N_MANIFEST_PATH     ?: env.N8NGIT_MANIFEST_PATH     ?: 'lab-manifest/n8n-custom-service'
def MANIFEST_ENV            = env.N8N_MANIFEST_ENV      ?: env.N8NGIT_MANIFEST_ENV      ?: 'dev'
def MANIFEST_CREDENTIALS_ID = env.N8NGIT_MANIFEST_CREDENTIALS_ID ?: env.PORTAL_MANIFEST_CREDENTIALS_ID ?: 'github-helm-values-lab'

def GO_IMAGE       = cfg('GO_IMAGE', 'golang:1.27.2-alpine')
def GOLANGCI_IMAGE = cfg('GOLANGCI_IMAGE', 'golangci/golangci-lint:v2.14.0-alpine')
def KANIKO_IMAGE   = cfg('KANIKO_IMAGE', 'gcr.io/kaniko-project/executor:v1.23.2-debug')
def GOVULNCHECK_VERSION = cfg('GOVULNCHECK_VERSION', 'v1.9.0')

def POD_YAML = """
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: golang
      image: ${GO_IMAGE}
      command: ['sleep', 'infinity']
    - name: golangci
      image: ${GOLANGCI_IMAGE}
      command: ['sleep', 'infinity']
    - name: kaniko
      image: ${KANIKO_IMAGE}
      command: ['sleep', 'infinity']
"""

def shortSha = ''

def runIn(String mode, String image, String podContainer, String cmd) {
  if (mode == 'kaniko') {
    container(podContainer) { sh cmd }
  } else {
    docker.image(image).inside('-e HOME=/tmp -e GOCACHE=/tmp/go-cache -e GOMODCACHE=/tmp/go-mod') { sh cmd }
  }
}

pipeline {
  agent {
    label "${AGENT_LABEL}"
  }

  options {
    timestamps()
    disableConcurrentBuilds(abortPrevious: true)
    buildDiscarder(logRotator(numToKeepStr: '30'))
    timeout(time: 30, unit: 'MINUTES')
  }

  parameters {
    booleanParam(name: 'PUSH_IMAGES', defaultValue: true, description: 'Push images to Harbor (false = build only).')
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        script {
          ['REGISTRY_URL': REGISTRY_URL, 'REGISTRY_CREDENTIALS_ID': REGISTRY_CREDENTIALS_ID].each { k, v ->
            if (v.startsWith('TODO')) { error("Jenkins env N8NGIT_${k} (or PORTAL_${k}) is not set.") }
          }
          if (!(BUILD_MODE in ['docker', 'kaniko'])) { error("BUILD_MODE must be 'docker' or 'kaniko'.") }
          shortSha = sh(returnStdout: true, script: 'git rev-parse --short=8 HEAD').trim()
          currentBuild.displayName = "#${env.BUILD_NUMBER} ${shortSha}"
        }
      }
    }

    stage('Lint & Test') {
      parallel {
        stage('Go lint') {
          steps { script { runIn(BUILD_MODE, GOLANGCI_IMAGE, 'golangci', 'golangci-lint run ./cmd/... ./internal/...') } }
        }
        stage('Go test') {
          steps { script { runIn(BUILD_MODE, GO_IMAGE, 'golang', 'go vet ./... && go test -count=1 -coverprofile=coverage.out ./...') } }
        }
        stage('Go vuln (SCA)') {
          steps {
            script {
              runIn(BUILD_MODE, GO_IMAGE, 'golang',
                "go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} && \$(go env GOPATH)/bin/govulncheck ./...")
            }
          }
        }
      }
    }

    stage('Build & Push') {
      steps {
        script {
          def tags = [shortSha]
          if (env.BRANCH_NAME == 'main') { tags << 'latest' }

          for (svc in SERVICES) {
            def repo = "${REGISTRY_URL}/${IMAGE_PREFIX}/${svc}"
            def buildArgs = "--build-arg GO_IMAGE=${GO_IMAGE} --build-arg SERVICE_NAME=${svc}"
            echo "Building image for ${svc} -> ${repo}:${shortSha}"
            if (BUILD_MODE == 'kaniko') {
              container('kaniko') {
                withCredentials([usernamePassword(credentialsId: REGISTRY_CREDENTIALS_ID, usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
                  sh """
                    mkdir -p /kaniko/.docker
                    AUTH=\$(printf '%s:%s' "\$REG_USER" "\$REG_PASS" | base64 | tr -d '\\n')
                    printf '{"auths":{"%s":{"auth":"%s"}}}' '${REGISTRY_URL}' "\$AUTH" > /kaniko/.docker/config.json
                    for attempt in 1 2 3; do
                      if /kaniko/executor --context=\$WORKSPACE --dockerfile=\$WORKSPACE/Dockerfile ${buildArgs} \
                        ${tags.collect { "--destination=${repo}:${it}" }.join(' ')} \
                        ${params.PUSH_IMAGES ? '' : '--no-push'} --cache=true --snapshot-mode=redo --use-new-run \
                        --skip-unused-stages --cleanup --push-retry=5 --image-fs-extract-retry=3 ${KANIKO_EXTRA_ARGS}; then
                        break
                      fi
                      if [ "\$attempt" = "3" ]; then
                        echo "Kaniko build failed after 3 attempts"
                        exit 1
                      fi
                      echo "Kaniko failed (attempt \$attempt/3), retrying in 5s..."
                      sleep 5
                    done
                  """
                }
              }
            } else {
              sh "DOCKER_BUILDKIT=1 docker build ${buildArgs} ${tags.collect { "-t ${repo}:${it}" }.join(' ')} ."
              if (params.PUSH_IMAGES) {
                docker.withRegistry("https://${REGISTRY_URL}", REGISTRY_CREDENTIALS_ID) {
                  tags.each { t -> sh "docker push ${repo}:${t}" }
                }
              }
            }
            echo "Image ${svc}: ${tags.collect { "${repo}:${it}" }.join(', ')}"
          }
        }
      }
    }

    stage('Update manifest') {
      when { allOf { branch 'main'; expression { params.PUSH_IMAGES && MANIFEST_REPO_URL } } }
      steps {
        script {
          def manifestHttps = MANIFEST_REPO_URL.startsWith('https://')
          def manifestCreds = manifestHttps
            ? [usernamePassword(credentialsId: MANIFEST_CREDENTIALS_ID, usernameVariable: 'MANIFEST_USER', passwordVariable: 'MANIFEST_TOKEN')]
            : [sshUserPrivateKey(credentialsId: MANIFEST_CREDENTIALS_ID, keyFileVariable: 'MANIFEST_KEY')]
          def manifestGitAuth = manifestHttps
            ? '''export GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$WORKSPACE/.manifest_askpass"
            printf '%s\\n' '#!/bin/sh' 'case "$1" in Username*) printf "%s" "$MANIFEST_USER";; *) printf "%s" "$MANIFEST_TOKEN";; esac' > "$GIT_ASKPASS"
            chmod 700 "$GIT_ASKPASS"'''
            : 'export GIT_SSH_COMMAND="ssh -i $MANIFEST_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$WORKSPACE/.manifest_known_hosts"'
          withCredentials(manifestCreds) {
            sh """
              set -eu
              ${manifestGitAuth}
              for attempt in 1 2 3; do
                rm -rf "\$WORKSPACE/.manifest"
                git clone -q --depth 1 --branch '${MANIFEST_BRANCH}' '${MANIFEST_REPO_URL}' "\$WORKSPACE/.manifest"
                cd "\$WORKSPACE/.manifest"
                git config user.name 'Jenkins'
                git config user.email 'jenkins@ci.local'
                
                for svc in ${SERVICES.join(' ')}; do
                  f='${MANIFEST_PATH}'/\$svc/values-env-'${MANIFEST_ENV}'.yaml
                  if [ -f "\$f" ]; then
                    sed -i -E 's/^(  tag:)[[:space:]]*.*/\\1 "${shortSha}"/' "\$f"
                    grep -q '^  tag: "${shortSha}"\$' "\$f" || { echo "failed to set tag in \$f"; exit 1; }
                  else
                    echo "\$f does not exist, skipping"
                  fi
                done

                git add -A
                if git diff --cached --quiet; then echo 'Manifest already up to date.'; exit 0; fi
                git commit -q -m "n8n-custom-service: image tag ${shortSha}" -m "Jenkins ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                git push -q origin HEAD:'${MANIFEST_BRANCH}' && { echo "Manifest updated -> ${shortSha}"; exit 0; }
                cd "\$WORKSPACE"; sleep 5
              done
              echo 'Manifest push failed 3x'; exit 1
            """
          }
        }
      }
    }
  }

  post {
    always {
      script {
        if (BUILD_MODE == 'docker') { sh 'docker image prune -f --filter "until=24h" || true' }
      }
    }
  }
}
