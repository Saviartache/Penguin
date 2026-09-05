# Сервер SSH для проверки. Своя сборка, а не готовый образ: у готовых
# `AllowTcpForwarding` то включён, то выключен от версии к версии, и отказ в
# канале выглядел бы ошибкой нашего протокола.
FROM alpine:3.20

RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && adduser -D penguin \
    && echo 'penguin:secret' | chpasswd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
