FROM php:7.4-apache
RUN useradd -m ctfuser

RUN chown -R root:root /home/ctfuser
RUN chmod 755 /home/ctfuser
RUN chmod 555 /tmp



WORKDIR /var/www/html

COPY --chown=root:root index.php .
COPY --chown=root:root flag.txt .

USER root
RUN chmod -R 555 /var/www/html && \
    chmod 444 /var/www/html/flag.txt

RUN mv /var/www/html/flag.txt /var/www/html/flag-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1).txt

USER ctfuser

EXPOSE 80


CMD ["apache2-foreground"]
