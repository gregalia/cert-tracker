# syntax=docker/dockerfile:1
FROM alpine:3.22.0 AS cdk-run

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
WORKDIR /build

COPY package*.json ./

# 'npm warn Unknown builtin config globalignorefile|python' before deleting npmrc
# hadolint ignore=DL3018,SC2086
RUN <<HEREDOC
  apk upgrade 
  apk add --no-cache \
    ca-certificates \
    jq~1.8 

  NODE_MAJOR_VERSION=$(
    jq --raw-output '.packages[""].engines.node | sub("\\^|~";"")' package-lock.json
  ) 
  NPM_MAJOR_VERSION=$(
    jq --raw-output '.packages[""].engines.npm | sub("\\^|~";"")' package-lock.json
  )

  apk add --no-cache \
    nodejs~${NODE_MAJOR_VERSION} \
    npm~${NPM_MAJOR_VERSION} 

  rm /usr/lib/node_modules/npm/npmrc 
  npm ci
HEREDOC

COPY lib/ lib/
COPY cdk.json tsconfig.json app.ts ./

# add bind mount or env vars for AWS auth at runtime
ENTRYPOINT ["npx", "cdk"]

###

FROM cdk-run AS cdk-debug

# hadolint ignore=DL3018
RUN apk add --no-cache \
  aws-cli \
  aws-cli-zsh-completion \
  zsh

ENTRYPOINT ["zsh"]
