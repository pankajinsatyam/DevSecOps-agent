# Deliberately UNSAFE image for testing the Trivy agent. Do not use in real work.
#
# What Trivy should find:
#   - OS vulnerabilities: Node 14 on Alpine 3.15 is end-of-life
#   - npm package vulnerabilities: old lodash, express, minimist, jsonwebtoken
#   - Misconfigurations in this Dockerfile (see the comments marked "BAD")
#
# Build from this folder:
#   docker build -t devsecops-sample/node-express-old sample_images/node-express-old

# BAD: old, end-of-life base image
FROM node:14-alpine3.15

WORKDIR /usr/src/app

COPY package.json package-lock.json ./

# BAD: "npm install" instead of "npm ci", so the lock file is not enforced
RUN npm install

COPY server.js .

# BAD: SSH port opened for no reason
EXPOSE 22 3000

# BAD: runs as root (no USER line), no HEALTHCHECK
CMD ["node", "server.js"]
