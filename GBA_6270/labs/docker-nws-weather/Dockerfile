# Simple static web server for the NWS Weather app
FROM nginx:alpine

# Copy app into default nginx web root
COPY . /usr/share/nginx/html

# Expose default nginx port
EXPOSE 80

# No custom CMD needed; nginx base image provides it
