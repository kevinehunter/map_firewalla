# Multi-stage build for optimal image size
FROM node:18-alpine AS builder

# Install build dependencies for native modules
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy built application from builder
COPY --from=builder /app/dist ./dist

# Copy documentation
COPY --from=builder /app/docs ./docs
COPY README.md LICENSE ./

# Change ownership to nodejs user
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Set environment variables
ENV NODE_ENV=production
ENV MCP_TRANSPORT=http
ENV MCP_HTTP_PORT=3000
ENV MCP_HTTP_PATH=/mcp

# Expose HTTP port for MCP server
EXPOSE 3000

# Note: Health check removed due to Alpine Linux IPv6/IPv4 networking complexity
# Server is monitored via docker ps and responds correctly on HTTP port 3000

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Run the MCP server
CMD ["node", "dist/server.js"]

# Labels for metadata
LABEL org.opencontainers.image.title="Firewalla MCP Server"
LABEL org.opencontainers.image.description="MCP server for Firewalla MSP API integration"
LABEL org.opencontainers.image.version="1.2.1"
LABEL org.opencontainers.image.authors="Alex Mittell <mittell@me.com>"
LABEL org.opencontainers.image.source="https://github.com/amittell/firewalla-mcp-server"
LABEL org.opencontainers.image.licenses="MIT"
