import os

def fix():
    with open("docker-compose.yml", "r") as f:
        content = f.read()

    # 1. Update shadow-api
    old_api = """      - DATABASE_URL=postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379"""
    
    new_api = """      - SHADOW_DATABASE__HOST=postgres
      - SHADOW_DATABASE__PORT=5432
      - SHADOW_DATABASE__USER=${POSTGRES_USER}
      - SHADOW_DATABASE__PASSWORD=${POSTGRES_PASSWORD}
      - SHADOW_DATABASE__DATABASE=${POSTGRES_DB}
      - SHADOW_REDIS__HOST=redis
      - SHADOW_REDIS__PORT=6379
      - SHADOW_REDIS__PASSWORD=${REDIS_PASSWORD}
      - SHADOW_REDIS__DB=0"""
    
    if old_api in content:
        content = content.replace(old_api, new_api)
        print("Updated shadow-api")
    else:
        print("Could not find shadow-api pattern")

    # 2. Update shadow-ui (remove restrictive flags)
    # Using a slightly larger context to ensure match
    old_ui = """  shadow-ui:
    build: ./shadow-ui
    container_name: shadow-ui
    ports:
      - "127.0.0.1:3000:80"
    depends_on:
      - shadow-api
    networks:
      - shadow-network
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL"""
    
    new_ui = """  shadow-ui:
    build: ./shadow-ui
    container_name: shadow-ui
    ports:
      - "127.0.0.1:3000:80"
    depends_on:
      - shadow-api
    networks:
      - shadow-network"""
    
    if old_ui in content:
        content = content.replace(old_ui, new_ui)
        print("Updated shadow-ui")
    else:
        print("Could not find shadow-ui pattern")

    with open("docker-compose.yml", "w") as f:
        f.write(content)

if __name__ == "__main__":
    fix()
