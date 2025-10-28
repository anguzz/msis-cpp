# Web-Based Weather App (NWS) + Docker

This is a single-page HTML/CSS/JS app that calls the National Weather Service (api.weather.gov) to show:
- Current temperature in °C and °F
- 7-day forecast (day names, highs in °C/°F, and conditions)


<img width="1429" height="935" alt="image" src="https://github.com/user-attachments/assets/069f732f-fb6c-43e2-9ea4-bd0a2eeb6481" />

## Docker setup (mintOS)
- Taken from Ubuntu setup docs at https://docs.docker.com/engine/install/ubuntu/

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

```bash
# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```

To install the latest version, run:
```bash
 sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
 ```


The Docker service starts automatically after installation. To verify that Docker is running, use:

`sudo systemctl status docker`

Some systems may have this behavior disabled and will require a manual start:

`sudo systemctl start docker`


Ensure user can use docker
- `sudo usermod -aG docker $USER`
- `newgrp docker`
- Log out of current session and log back in


## Run locally with Docker

```bash
# From this folder:
docker build -t docker-nws-weather .

# Map container port 80 to localhost:8080
docker run --rm -p 8080:80 docker-nws-weather
```

Open http://localhost:8080 in your browser.

## How it works

1. `GET https://api.weather.gov/points/{lat},{lon}` → provides:
   - Forecast URL
   - Relative location (city/state)
   - Observation stations list

2. `GET {firstStation}/observations/latest` → current temp (°C). If missing, the app falls back to the first daytime forecast period.

3. `GET {forecastUrl}` → daily periods (in °F). The app converts to °C for display.

No API keys required. The NWS API supports CORS for browser clients.
