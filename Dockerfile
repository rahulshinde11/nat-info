FROM nginx:alpine

# Copy binaries from dist folder to web root
COPY dist/ /usr/share/nginx/html/

# Copy install script template
COPY install.sh.template /usr/share/nginx/html/install.sh.template

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Make entrypoint executable
RUN chmod +x /docker-entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/docker-entrypoint.sh"]

# Default command to start Nginx
CMD ["nginx", "-g", "daemon off;"]

