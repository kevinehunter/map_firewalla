# Docker Deployment Guide

This guide explains how to deploy the Firewalla MCP Server using Docker.

## Prerequisites

- Docker 20.10 or later
- Docker Compose v2.x
- Firewalla MSP account with API access

### Docker Permissions

If you get permission errors, you have two options:

**Option 1: Add your user to the docker group (recommended)**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Option 2: Use sudo with Docker commands**
```bash
sudo docker build ...
sudo docker compose up ...
```

## Quick Start

### 1. Create Environment Configuration

Copy the example environment file and configure your credentials:

```bash
cp .env.example .env
```

Edit `.env` and set your Firewalla credentials:

```env
FIREWALLA_MSP_TOKEN=your_msp_access_token_here
FIREWALLA_MSP_ID=yourdomain.firewalla.net
```

### 2. Build and Start with Docker Compose

Note: Modern Docker uses `docker compose` (v2) instead of `docker-compose` (v1).

```bash
# Build and start the container
docker compose up -d

# View logs
docker compose logs -f

# Stop the container
docker compose down
```

If using sudo:
```bash
sudo docker compose up -d
sudo docker compose logs -f
sudo docker compose down
```

### 3. Access the MCP Server

The MCP server will be available at:
- **HTTP Endpoint**: `http://localhost:3000/mcp`
- **Health Check**: `http://localhost:3000/health`

## Manual Docker Commands

If you prefer to use Docker directly without docker-compose:

### Build the Image

```bash
docker build -t firewalla-mcp-server:latest .
```

### Run the Container

```bash
docker run -d \
  --name firewalla-mcp-server \
  --restart unless-stopped \
  -p 3000:3000 \
  --env-file .env \
  -e MCP_TRANSPORT=http \
  -e MCP_HTTP_PORT=3000 \
  firewalla-mcp-server:latest
```

### View Logs

```bash
docker logs -f firewalla-mcp-server
```

### Stop and Remove

```bash
docker stop firewalla-mcp-server
docker rm firewalla-mcp-server
```

## Configuration

### Environment Variables

The Docker container uses HTTP transport by default. Key environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `http` | Transport mode (http for Docker) |
| `MCP_HTTP_PORT` | `3000` | HTTP server port |
| `MCP_HTTP_PATH` | `/mcp` | HTTP endpoint path |
| `FIREWALLA_MSP_TOKEN` | (required) | Your MSP API token |
| `FIREWALLA_MSP_ID` | (required) | Your MSP domain |

### Port Mapping

The default configuration exposes port 3000. To use a different port:

```bash
# docker-compose.yml
ports:
  - "8080:3000"  # External:Internal
```

Or with docker run:

```bash
docker run -p 8080:3000 ...
```

## Health Monitoring

The container includes a health check that runs every 30 seconds:

```bash
# Check container health status
docker ps

# View health check logs
docker inspect --format='{{.State.Health}}' firewalla-mcp-server
```

## Resource Management

Default resource limits (can be adjusted in docker-compose.yml):
- **CPU Limit**: 1 core
- **Memory Limit**: 512MB
- **CPU Reservation**: 0.25 cores
- **Memory Reservation**: 128MB

## Troubleshooting

### Container Won't Start

1. Check logs: `docker compose logs` (or `sudo docker compose logs`)
2. Verify .env file exists and contains valid credentials
3. Ensure port 3000 is not already in use: `sudo lsof -i :3000`

### Health Check Failing

1. Check if the server is responding: `curl http://localhost:3000/health`
2. View detailed logs: `docker compose logs -f` (or `sudo docker compose logs -f`)
3. Verify environment variables are set correctly

### Permission Issues

The container runs as a non-root user (nodejs:1001) for security. If you encounter permission issues, check file ownership.

## Security Best Practices

1. **Never commit .env file** - It contains sensitive credentials
2. **Use secrets management** - For production, consider Docker secrets or external secret managers
3. **Keep image updated** - Regularly rebuild to get security updates
4. **Network isolation** - Use Docker networks to restrict access
5. **Resource limits** - Configure appropriate CPU/memory limits

## Updating

To update to a new version:

```bash
# Pull latest code
git pull

# Rebuild and restart
docker compose up -d --build

# Or with Docker directly
docker build -t firewalla-mcp-server:latest .
docker stop firewalla-mcp-server
docker rm firewalla-mcp-server
docker run ...  # Use your previous docker run command
```

If using sudo, prefix commands with `sudo`.

## Integration with MCP Clients

### Claude Desktop / VS Code

Configure your MCP client to connect to the HTTP endpoint:

```json
{
  "mcpServers": {
    "firewalla": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

### Remote Access

For remote access, consider:
1. **Reverse proxy** (nginx, Caddy) with HTTPS
2. **VPN** for secure remote access
3. **Firewall rules** to restrict access

Example nginx configuration:

```nginx
server {
    listen 443 ssl;
    server_name mcp.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /mcp {
        proxy_pass http://localhost:3000/mcp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Production Deployment

For production environments:

1. **Use proper secrets management**
2. **Configure monitoring and alerting**
3. **Set up log aggregation**
4. **Use container orchestration** (Kubernetes, Docker Swarm)
5. **Implement backup and disaster recovery**
6. **Configure proper resource limits**
7. **Set up HTTPS with valid certificates**

## Support

For issues and questions:
- GitHub Issues: https://github.com/amittell/firewalla-mcp-server/issues
- Documentation: See README.md and CLAUDE.md
