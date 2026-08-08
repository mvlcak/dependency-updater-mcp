# Dependency Updater MCP

MCP Server that uses Embabel to orchestrate agent to update Maven or Gradle
dependencies in git repository on Github

## Stack

- Embabel
- Java 25
- Spring Boot
- Spring AI

## Requirements

- Java 25
- Maven
- OpenAI key or Azure OpenAI deployment

## Installation

create *env.properties* file from *env.properties.example* and fill:

Azure OpenAI (required):

- `OPENAI_API_KEY`
- `OPENAI_BASE_URL`
- `OPENAI_COMPLETIONS_PATH`
- `AZURE_DEPLOYMENT_NAME`

GitHub:
- `GITHUB_TOKEN` - required
- `GITHUB_ENDPOINT` - fill out if GitHub Enterprise is used

- `PUSH_ENABLED` - true/false - enables push to GitHub
- `SERVER_PORT` - set port - if blank defaults to 8080

Example *env.properties*:

```properties
OPENAI_API_KEY=<your-api-key>
OPENAI_BASE_URL=https://<your-resource>.openai.azure.com
OPENAI_COMPLETIONS_PATH=/openai/deployments/<your-deployment-name>/chat/completions?api-version=<api-version>
AZURE_DEPLOYMENT_NAME=<your-deployment-name>

GITHUB_TOKEN=<your-github-token>
GITHUB_ENDPOINT=https://github.example.com/api/v3
PUSH_ENABLED=true
SERVER_PORT=8080
```

Or create env variables in your OS <br>
Mac/Linux:

```bash
export OPENAI_API_KEY="<your-api-key>"
export OPENAI_BASE_URL="https://<your-resource>.openai.azure.com"
export OPENAI_COMPLETIONS_PATH="/openai/deployments/<your-deployment-name>/chat/completions?api-version=<api-version>"
export AZURE_DEPLOYMENT_NAME="<your-deployment-name>"

export GITHUB_TOKEN="<your-github-token>"
export GITHUB_ENDPOINT="https://github.example.com/api/v3"
export PUSH_ENABLED=true
export SERVER_PORT=8080
```

Windows

```powershell
$env:OPENAI_API_KEY="<your-api-key>"
$env:OPENAI_BASE_URL="https://<your-resource>.openai.azure.com"
$env:OPENAI_COMPLETIONS_PATH="/openai/deployments/<your-deployment-name>/chat/completions?api-version=<api-version>"
$env:AZURE_DEPLOYMENT_NAME="<your-deployment-name>"

$env:GITHUB_TOKEN="<your-github-token>"
$env:GITHUB_ENDPOINT="https://github.example.com/api/v3"
$env:PUSH_ENABLED="true"
$env:SERVER_PORT="8080"
```

`GITHUB_ENDPOINT`, `PUSH_ENABLED` and `SERVER_PORT` can be omitted — they default to
public GitHub, `false` and `8080` respectively.

## Build

### Requirements

- Maven
- JDK 25

#### Running on JVM

For running this app on JVM run command:

``mvn package``

Then you can run the application with command:

``java -jar target/dependnecy-updater-mcp-0.0.1.jar``

## Register MCP 

### Claude Code
```claude mcp add --transport http dependency-upgrader http://localhost:8080/mcp```
