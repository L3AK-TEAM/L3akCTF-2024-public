FROM nginx:alpine

COPY default.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/
COPY pkg /usr/share/nginx/html/pkg

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
