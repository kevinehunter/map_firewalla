# Claude Code Setup Guide

This guide explains how to use the Firewalla MCP Server with Claude Code.

## Quick Start

The MCP server is already configured for Claude Code! The `.mcp.json` file in this project connects Claude Code to your local Firewalla MCP server.

## Configuration

The `.mcp.json` file in the project root contains:

```json
{
  "mcpServers": {
    "firewalla": {
      "type": "http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

This configuration:
- **Name**: `firewalla` - The MCP server name
- **Type**: `http` - HTTP transport mode
- **URL**: `http://localhost:3000/mcp` - Your Docker container endpoint

## Prerequisites

1. **Docker container must be running**:
   ```bash
   docker ps | grep firewalla-mcp-server
   ```

   If not running, start it:
   ```bash
   docker compose up -d
   ```

2. **Verify the endpoint responds**:
   ```bash
   curl http://localhost:3000/mcp
   # Should return: "Invalid or missing session ID"
   ```

## Using the MCP Server in Claude Code

### 1. Check MCP Server Status

In Claude Code, you can check the MCP connection:

```
/mcp
```

This will show all configured MCP servers and their connection status.

### 2. Available Tools (28 Total)

Once connected, Claude Code can use all 28 Firewalla tools:

#### Security Tools (2)
- `get_active_alarms` - Get current security alerts
- `get_specific_alarm` - Get details of a specific alarm

#### Network Tools (1)
- `get_flow_data` - Get network flow data

#### Device Tools (1)
- `get_device_status` - Get device connection status

#### Rules Tools (8)
- `get_network_rules` - List all firewall rules
- `pause_rule` - Temporarily pause a rule
- `resume_rule` - Resume a paused rule
- `get_target_lists` - List all target lists
- `get_specific_target_list` - Get specific target list details
- `create_target_list` - Create a new target list
- `update_target_list` - Update an existing target list
- `delete_target_list` - Delete a target list

#### Search Tools (3)
- `search_flows` - Search network flows with filters
- `search_alarms` - Search security alarms
- `search_rules` - Search firewall rules

#### Analytics Tools (8)
- `get_boxes` - List all Firewalla boxes
- `get_simple_statistics` - Get basic network statistics
- `get_statistics_by_region` - Get geo-based statistics
- `get_statistics_by_box` - Get box-specific statistics
- `get_flow_insights` - Get category-based flow insights
- `get_flow_trends` - Get flow trend analysis
- `get_alarm_trends` - Get alarm trend analysis
- `get_rule_trends` - Get rule usage trends

#### Convenience Wrappers (5)
- `get_bandwidth_usage` - Get top bandwidth consumers
- `get_offline_devices` - List offline devices
- `search_devices` - Search devices with filters
- `search_target_lists` - Search target lists
- `get_network_rules_summary` - Get summarized rules view

### 3. Example Queries

Ask Claude Code natural language questions, and it will use the MCP tools:

```
"What security alerts do I have?"
"Show me top bandwidth users today"
"Which devices are offline?"
"Has anyone accessed social media sites today?"
"Show me all blocked traffic from China"
"List all firewall rules targeting gaming sites"
```

Claude Code will automatically select and use the appropriate MCP tools to answer your questions.

### 4. Direct Tool Usage

You can also reference tools directly in your prompts:

```
"Use get_active_alarms to show me current security issues"
"Call search_flows to find all video streaming traffic"
"Use get_flow_insights to analyze social media usage"
```

## Troubleshooting

### MCP Server Not Connected

1. **Check Docker container is running**:
   ```bash
   docker ps | grep firewalla-mcp-server
   ```

2. **Check container logs**:
   ```bash
   docker logs firewalla-mcp-server
   ```

3. **Restart the container**:
   ```bash
   docker compose restart
   ```

### Tools Not Available

1. **Verify MCP configuration**:
   ```bash
   cat .mcp.json
   ```

2. **Restart Claude Code** to reload the MCP configuration

3. **Check feature flags** in `.env`:
   ```bash
   grep "MCP_WAVE0_ENABLED" .env
   # Should be: MCP_WAVE0_ENABLED=true
   ```

### Connection Refused

1. **Verify the port is accessible**:
   ```bash
   curl http://localhost:3000/mcp
   ```

2. **Check firewall settings**:
   ```bash
   sudo lsof -i :3000
   ```

3. **Check Docker network**:
   ```bash
   docker inspect firewalla-mcp-server | grep IPAddress
   ```

## Managing the MCP Server

### Start/Stop Commands

```bash
# Start the MCP server
docker compose up -d

# Stop the MCP server
docker compose down

# Restart the MCP server
docker compose restart

# View logs
docker compose logs -f

# Rebuild after changes
docker compose up -d --build
```

### Configuration Changes

If you modify the `.env` file with new Firewalla credentials:

```bash
# Restart to apply changes
docker compose restart
```

If you modify the Docker configuration:

```bash
# Rebuild and restart
docker compose up -d --build
```

## Advanced Configuration

### Custom Port

If you need to run on a different port, edit `docker-compose.yml`:

```yaml
ports:
  - "8080:3000"  # Change 8080 to your desired port
```

Then update `.mcp.json`:

```json
{
  "mcpServers": {
    "firewalla": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### Environment Variables in Configuration

You can use environment variables in `.mcp.json`:

```json
{
  "mcpServers": {
    "firewalla": {
      "type": "http",
      "url": "${FIREWALLA_MCP_URL:-http://localhost:3000/mcp}"
    }
  }
}
```

Then set the environment variable:

```bash
export FIREWALLA_MCP_URL=http://localhost:3000/mcp
```

### Authentication Headers

If you add authentication to the MCP server, update `.mcp.json`:

```json
{
  "mcpServers": {
    "firewalla": {
      "type": "http",
      "url": "http://localhost:3000/mcp",
      "headers": {
        "Authorization": "Bearer your-token-here"
      }
    }
  }
}
```

## Security Considerations

1. **Local Network Only**: The MCP server is configured for `localhost` access only
2. **Environment Variables**: Your Firewalla credentials are stored in `.env` (not committed to git)
3. **Docker Isolation**: The server runs in an isolated Docker container
4. **No External Exposure**: Port 3000 is only exposed to localhost by default

For remote access, see `DOCKER.md` for setting up HTTPS with a reverse proxy.

## Support

- **Firewalla MCP Server Issues**: See [GitHub Issues](https://github.com/amittell/firewalla-mcp-server/issues)
- **Claude Code Help**: Run `/help` in Claude Code
- **Docker Issues**: Check `DOCKER.md` for troubleshooting

## Additional Resources

- **Full Documentation**: See `README.md`
- **Docker Deployment**: See `DOCKER.md`
- **API Reference**: See `docs/firewalla-api-reference.md`
- **Development Guide**: See `CLAUDE.md`
